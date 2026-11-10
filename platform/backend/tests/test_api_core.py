"""M6 acceptance tests: migrations, persistence, API endpoints, auth/RBAC and audit."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import func, select, text, update

from app.config import Role, Settings, parse_token_specs
from app.db import make_engine, make_session_factory
from app.models import (
    Anomaly,
    AuditLogRecord,
    Deployment,
    IncidentRecord,
    NetworkMetric,
    OperationalEventRecord,
)
from app.security.tokens import authenticate, hash_token
from call_analyzer import analyze_call_log

from .api_support import ApiHarness, alembic_config, make_harness, migrate

LEAK_CELLS = ["CELL-101", "CELL-102", "CELL-103", "CELL-104"]


@pytest.fixture(scope="module")
def api(tmp_path_factory: pytest.TempPathFactory) -> ApiHarness:
    harness = make_harness(tmp_path_factory.mktemp("api"))
    response = harness.post("/api/pipeline/run", json={"scenario": "seeded", "seed": 7})
    assert response.status_code == 201, response.text  # type: ignore[attr-defined]
    return harness


def _session(api: ApiHarness):  # type: ignore[no-untyped-def]
    return make_session_factory(make_engine(api.settings.database_url))()


# ---- Migrations --------------------------------------------------------------------------


def test_sqlite_migration_upgrade_downgrade_and_no_drift(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "head")
    command.check(cfg)  # raises if the models and the migration disagree
    command.downgrade(cfg, "base")
    engine = make_engine(url)
    with engine.connect() as conn:
        tables = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
    assert tables <= {"alembic_version"}
    command.upgrade(cfg, "head")


@pytest.mark.skipif(not os.environ.get("AEGIS_TEST_POSTGRES_URL"),
                    reason="set AEGIS_TEST_POSTGRES_URL to run against PostgreSQL")
def test_postgres_migration_and_pipeline(tmp_path: Path) -> None:
    url = os.environ["AEGIS_TEST_POSTGRES_URL"]
    cfg = alembic_config(url)
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    command.check(cfg)
    harness = make_harness(tmp_path, database_url=url)
    response = harness.post("/api/pipeline/run", json={"scenario": "seeded", "seed": 7})
    assert response.status_code == 201, response.text  # type: ignore[attr-defined]
    detail = harness.get(f"/api/incidents/{response.json()['incident_ids'][0]}").json()  # type: ignore[attr-defined]
    assert detail["affected_cells"] == LEAK_CELLS
    assert harness.get("/api/audit/verify", role="admin").json()["valid"] is True  # type: ignore[attr-defined]


# ---- Settings and tokens -----------------------------------------------------------------


def test_token_specs_and_secret_hygiene() -> None:
    token = "s3cret-token-value"
    spec = f"ops:operator:{hash_token(token)}"
    settings = Settings(api_tokens=parse_token_specs(spec), anthropic_api_key="sk-ant-xyz")
    assert authenticate(token, settings.api_tokens) is not None
    assert authenticate(token, settings.api_tokens).role is Role.OPERATOR  # type: ignore[union-attr]
    assert authenticate("wrong", settings.api_tokens) is None
    text_repr = repr(settings)
    assert "sk-ant-xyz" not in text_repr and hash_token(token) not in text_repr
    for bad in ("ops:operator:nothex", "ops:superuser:" + "a" * 64, "a:viewer:" + "b" * 64 + ",a:admin:" + "c" * 64):
        with pytest.raises(ValueError):
            parse_token_specs(bad)


def test_settings_from_env() -> None:
    env = {"DATABASE_URL": "sqlite:///x.db", "LLM_PROVIDER": "Anthropic", "AGENT_ALLOW_HIGH_RISK": "true",
           "AEGIS_API_TOKENS": f"a:admin:{'d' * 64}"}
    settings = Settings.from_env(env)
    assert settings.llm_provider == "anthropic" and settings.agent_allow_high_risk is True
    assert settings.api_tokens[0].role is Role.ADMIN
    assert Settings.from_env({}).agent_allow_high_risk is False


# ---- Authentication and authorisation ---------------------------------------------------------


def test_health_is_public_and_leaks_nothing(api: ApiHarness) -> None:
    response = api.client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["database"] == "ok" and body["call_analyzer"] == "ok"
    assert set(body) == {"status", "version", "database", "call_analyzer", "llm_provider"}
    assert "sqlite" not in response.text and "Bearer" not in response.text


@pytest.mark.parametrize(("method", "path", "minimum"), [
    ("get", "/api/incidents", "viewer"),
    ("get", "/api/network/anomalies", "viewer"),
    ("get", "/api/calls/statistics", "viewer"),
    ("get", "/api/deployments", "viewer"),
    ("get", "/api/security/findings", "viewer"),
    ("get", "/api/pipeline/runs", "viewer"),
    ("get", "/api/audit", "operator"),
    ("get", "/api/audit/verify", "admin"),
])
def test_role_matrix(api: ApiHarness, method: str, path: str, minimum: str) -> None:
    assert getattr(api.client, method)(path).status_code == 401
    bad = getattr(api.client, method)(path, headers={"Authorization": "Bearer not-a-real-token"})
    assert bad.status_code == 401
    ranks = ["viewer", "operator", "approver", "admin"]
    for role in ranks:
        response = getattr(api.client, method)(path, headers=api.headers(role))
        expected = 200 if ranks.index(role) >= ranks.index(minimum) else 403
        assert response.status_code == expected, (role, path, response.text)


def test_mutation_requires_operator(api: ApiHarness) -> None:
    body = {"scenario": "healthy", "seed": 1, "minutes": 60}
    assert api.client.post("/api/pipeline/run", json=body).status_code == 401
    assert api.post("/api/pipeline/run", role="viewer", json=body).status_code == 403  # type: ignore[attr-defined]


def test_denied_requests_are_audited(api: ApiHarness) -> None:
    api.client.get("/api/incidents", headers={"Authorization": "Bearer nope", "X-Request-ID": "deny-test-1"})
    api.post("/api/pipeline/run", role="viewer", json={"scenario": "healthy"})
    with _session(api) as session:
        denied = session.scalars(select(AuditLogRecord).where(AuditLogRecord.request_id == "deny-test-1")).one()
        assert denied.action == "auth.denied" and denied.outcome == "denied"
        forbidden = session.scalars(select(AuditLogRecord).where(AuditLogRecord.action == "auth.forbidden")
                                    .order_by(AuditLogRecord.id.desc())).first()
        assert forbidden is not None and forbidden.actor == "test-viewer"
        assert forbidden.resource_id == "POST /api/pipeline/run"


# ---- Persistence via the pipeline ------------------------------------------------------------


def test_pipeline_persists_all_layers(api: ApiHarness) -> None:
    with _session(api) as session:
        run_id = 1
        assert session.scalar(select(func.count()).select_from(NetworkMetric)
                              .where(NetworkMetric.run_id == run_id)) == 360 * 12 * 17
        assert session.scalar(select(func.count()).select_from(Anomaly).where(Anomaly.run_id == run_id)) == 36
        assert session.scalar(select(func.count()).select_from(Deployment)) == 2
        assert session.scalar(select(func.count()).select_from(OperationalEventRecord)) > 50
        incident = session.get(IncidentRecord, "INC-2026-001")
        assert incident is not None and incident.status == "open"
        assert incident.top_cause_type == "deployment_regression"
        audit = session.scalars(select(AuditLogRecord).where(AuditLogRecord.action == "pipeline.run")).first()
        assert audit is not None and audit.actor == "test-operator" and audit.resource_id == "1"


def test_second_run_continues_incident_numbering(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    ids = []
    for _ in range(2):
        response = harness.post("/api/pipeline/run", json={"scenario": "seeded", "seed": 7})
        assert response.status_code == 201  # type: ignore[attr-defined]
        ids += response.json()["incident_ids"]  # type: ignore[attr-defined]
    assert ids == ["INC-2026-001", "INC-2026-002"]
    second = harness.get("/api/incidents/INC-2026-002").json()  # type: ignore[attr-defined]
    assert second["run_id"] == 2 and all(a.startswith("R2-") for a in second["anomaly_ids"])


# ---- Endpoints ---------------------------------------------------------------------------------


def test_call_statistics_match_c_library(api: ApiHarness) -> None:
    stats = api.get("/api/calls/statistics").json()  # type: ignore[attr-defined]
    direct = analyze_call_log(api.settings.data_dir / "runs" / "run-0001" / "call_logs.csv")
    for key in ("total_calls", "successful_calls", "dropped_calls", "drop_rate", "success_rate"):
        assert stats[key] == pytest.approx(direct[key]), key
    assert [c["cell_id"] for c in stats["cells"]] == [c["cell_id"] for c in direct["cells"]]
    anomalies = api.get("/api/calls/anomalies").json()  # type: ignore[attr-defined]
    assert {a["subject"] for a in anomalies if a["category"] == "cell"} == set(LEAK_CELLS)


def test_network_metrics_filters(api: ApiHarness) -> None:
    body = api.get("/api/network/metrics", params={"metric": "cpu_utilization"}).json()  # type: ignore[attr-defined]
    assert len(body["series"]) == 12 and len(body["series"][0]["values"]) == 360
    start = body["series"][0]["epochs"][100]
    one = api.get("/api/network/metrics", params={"metric": "latency_ms", "cell_id": "CELL-102",  # type: ignore[attr-defined]
                                                   "start": start, "end": start + 600}).json()
    assert len(one["series"]) == 1 and len(one["series"][0]["values"]) == 11
    assert api.get("/api/network/metrics", params={"metric": "drop table"}).status_code == 422  # type: ignore[attr-defined]
    assert api.get("/api/network/metrics", params={"metric": "cpu_utilization", "cell_id": "../x"}).status_code == 422  # type: ignore[attr-defined]


def test_network_anomalies(api: ApiHarness) -> None:
    rows = api.get("/api/network/anomalies", params={"cell_id": "CELL-101"}).json()  # type: ignore[attr-defined]
    assert {r["metric"] for r in rows} >= {"memory_utilization", "cpu_utilization", "packet_loss_pct"}
    assert all(r["timestamp"].endswith("Z") for r in rows)
    critical = api.get("/api/network/anomalies", params={"severity": "critical"}).json()  # type: ignore[attr-defined]
    assert critical and all(r["severity"] == "critical" for r in critical)


def test_incident_endpoints(api: ApiHarness) -> None:
    listing = api.get("/api/incidents").json()  # type: ignore[attr-defined]
    assert [i["incident_id"] for i in listing] == ["INC-2026-001"]
    assert listing[0]["affected_cells"] == LEAK_CELLS and listing[0]["severity"] == "CRITICAL"
    detail = api.get("/api/incidents/INC-2026-001").json()  # type: ignore[attr-defined]
    for key in ("incident_id", "severity", "start_time", "affected_cells", "symptoms", "events",
                "suspected_causes", "confidence"):
        assert key in detail
    assert detail["affected_nodes"] == ["pgw-1"]
    assert detail["suspected_causes"][0]["cause_type"] == "deployment_regression"
    assert all(e.startswith("R1-EVT-") for e in detail["suspected_causes"][0]["evidence"])
    epochs = [e["epoch"] for e in detail["events"]]
    assert epochs == sorted(epochs) and detail["events"][0]["type"] == "deployment"
    assert api.get("/api/incidents/INC-2026-999").status_code == 404  # type: ignore[attr-defined]
    assert api.get("/api/incidents/not-an-id").status_code == 422  # type: ignore[attr-defined]
    assert api.get("/api/incidents", params={"severity": "critical"}).status_code == 422  # type: ignore[attr-defined]


def test_deployments_endpoint(api: ApiHarness) -> None:
    rows = api.get("/api/deployments").json()  # type: ignore[attr-defined]
    assert [r["node_id"] for r in rows] == ["pgw-1", "pgw-3"]
    assert rows[0]["to_version"] == "2.4.1" and rows[0]["deployed_at"] == "2026-03-01T14:05:00Z"


def test_request_validation(api: ApiHarness) -> None:
    assert api.post("/api/pipeline/run", json={"scenario": "seeded", "unexpected": 1}).status_code == 422  # type: ignore[attr-defined]
    assert api.post("/api/pipeline/run", json={"scenario": "nope"}).status_code == 422  # type: ignore[attr-defined]
    assert api.post("/api/pipeline/run", json={"scenario": "healthy", "rollback_minute": 30}).status_code == 422  # type: ignore[attr-defined]
    assert api.post("/api/pipeline/run", json={"seed": -1}).status_code == 422  # type: ignore[attr-defined]


def test_request_id_round_trip(api: ApiHarness) -> None:
    response = api.client.get("/api/health", headers={"X-Request-ID": "abc-123"})
    assert response.headers["X-Request-ID"] == "abc-123"
    generated = api.client.get("/api/health", headers={"X-Request-ID": "bad id!\n"})
    assert generated.headers["X-Request-ID"] != "bad id!\n" and len(generated.headers["X-Request-ID"]) == 32


def test_openapi_documents_endpoints(api: ApiHarness) -> None:
    paths = api.client.get("/openapi.json").json()["paths"]
    for path in ("/api/health", "/api/incidents", "/api/incidents/{incident_id}", "/api/calls/statistics",
                 "/api/calls/anomalies", "/api/network/metrics", "/api/network/anomalies", "/api/audit"):
        assert path in paths
    assert api.client.get("/docs").status_code == 200


# ---- Audit chain -------------------------------------------------------------------------------


def test_audit_listing_and_chain_verification(api: ApiHarness) -> None:
    page = api.get("/api/audit", role="operator").json()  # type: ignore[attr-defined]
    assert page["total"] >= 1 and {"hash", "prev_hash", "actor", "action"} <= set(page["items"][0])
    assert api.get("/api/audit/verify", role="admin").json()["valid"] is True  # type: ignore[attr-defined]


def test_audit_tampering_is_detected(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    harness.post("/api/pipeline/run", json={"scenario": "healthy", "minutes": 60})
    harness.client.get("/api/incidents")  # denied -> audited
    assert harness.get("/api/audit/verify", role="admin").json()["valid"] is True  # type: ignore[attr-defined]
    engine = make_engine(harness.settings.database_url)
    with engine.begin() as conn:
        conn.execute(update(AuditLogRecord).where(AuditLogRecord.id == 1).values(actor="mallory"))
    verdict = harness.get("/api/audit/verify", role="admin").json()  # type: ignore[attr-defined]
    assert verdict["valid"] is False and verdict["first_invalid_id"] == 1


def test_migrate_helper_is_idempotent(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'x.db'}"
    migrate(url)
    migrate(url)


def test_network_overview(api: ApiHarness) -> None:
    body = api.get("/api/network/overview").json()  # type: ignore[attr-defined]
    assert body["active_incidents"] >= 1 and body["anomaly_count"] == 36
    penalties = sum(b["penalty"] for b in body["health_breakdown"])
    assert body["health_score"] == max(0, 100 - penalties)
    assert any("CRITICAL incident INC-2026-001" in b["reason"] for b in body["health_breakdown"])
    degraded = {c["cell_id"] for c in body["cells"] if c["status"] == "degraded"}
    assert degraded == set(LEAK_CELLS) and len(body["cells"]) == 12
    kpis = {k["metric"]: k for k in body["kpis"]}
    assert kpis["latency_ms"]["current"] > 3 * kpis["latency_ms"]["baseline"]
    assert kpis["throughput_mbps"]["bad_direction"] == "down"
    assert body["affected_cells_by_incident"]["INC-2026-001"] == LEAK_CELLS


def test_network_overview_healthy_run(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    harness.post("/api/pipeline/run", json={"scenario": "healthy", "minutes": 120})
    body = harness.get("/api/network/overview").json()  # type: ignore[attr-defined]
    assert body["health_score"] == 100 and body["health_breakdown"] == [] and body["active_incidents"] == 0
    assert all(c["status"] == "ok" for c in body["cells"])
