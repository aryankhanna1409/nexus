"""M10 acceptance tests: hardening (limits, headers, auth bypass, injection, secrets) and observability."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from app.security.ratelimit import MemoryRateLimiter, RedisRateLimiter

from .api_support import ApiHarness, make_harness


@pytest.fixture(scope="module")
def api(tmp_path_factory: pytest.TempPathFactory) -> ApiHarness:
    harness = make_harness(tmp_path_factory.mktemp("sec"), anthropic_api_key="sk-ant-SECRET-not-real",
                           openai_api_key="sk-openai-SECRET-not-real")
    assert harness.post("/api/pipeline/run", json={"scenario": "seeded"}).status_code == 201  # type: ignore[attr-defined]
    return harness


# ---- Headers, request ids, errors ----------------------------------------------------------------


def test_security_headers(api: ApiHarness) -> None:
    response = api.get("/api/incidents")
    headers = response.headers  # type: ignore[attr-defined]
    assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer" and headers["cache-control"] == "no-store"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert len(headers["x-request-id"]) == 32


def test_unhandled_errors_return_generic_json(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)

    def boom() -> None:
        raise RuntimeError("internal detail: /etc/secret-path")

    harness.client.app.add_api_route("/api/test-boom", boom)  # type: ignore[attr-defined]
    response = harness.client.get("/api/test-boom", headers={"X-Request-ID": "err-1"})
    assert response.status_code == 500
    assert response.json() == {"detail": "internal server error", "request_id": "err-1"}
    assert "secret-path" not in response.text and "Traceback" not in response.text


# ---- Request limits ---------------------------------------------------------------------------------


def test_declared_body_too_large(tmp_path: Path) -> None:
    harness = make_harness(tmp_path, max_request_bytes=1000)
    response = harness.client.post("/api/pipeline/run", content=b"x" * 5000,
                                   headers={**harness.headers("operator"), "content-type": "application/json"})
    assert response.status_code == 413


def test_streamed_body_too_large(tmp_path: Path) -> None:
    harness = make_harness(tmp_path, max_request_bytes=1000)

    def chunks():  # type: ignore[no-untyped-def]
        for _ in range(10):
            yield b"y" * 500

    response = harness.client.post("/api/pipeline/run", content=chunks(),
                                   headers={**harness.headers("operator"), "content-type": "application/json"})
    assert response.status_code == 413


def test_rate_limit(tmp_path: Path) -> None:
    harness = make_harness(tmp_path, rate_limit_per_minute=5)
    statuses = [harness.get("/api/incidents").status_code for _ in range(7)]  # type: ignore[attr-defined]
    assert statuses[:5] == [200] * 5 and statuses[5:] == [429, 429]
    limited = harness.get("/api/incidents")
    assert int(limited.headers["retry-after"]) >= 1  # type: ignore[attr-defined]
    assert harness.get("/api/incidents", role="admin").status_code == 200  # type: ignore[attr-defined]  # own bucket
    assert all(harness.client.get("/api/health").status_code == 200 for _ in range(10))  # exempt
    metrics = harness.client.get("/metrics").text
    assert "aegis_rate_limited_total 3.0" in metrics


def test_memory_rate_limiter_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = MemoryRateLimiter()
    now = [1_000_020.0]
    monkeypatch.setattr("app.security.ratelimit.time.time", lambda: now[0])
    assert [limiter.hit("k", 2)[0] for _ in range(3)] == [True, True, False]
    now[0] += 60
    assert limiter.hit("k", 2)[0] is True


class _FakePipeline:
    def __init__(self, store: dict[str, int], fail: bool) -> None:
        self.store, self.fail = store, fail
        self.ops: list[tuple[str, str]] = []

    def incr(self, key: str) -> None:
        self.ops.append(("incr", key))

    def expire(self, key: str, seconds: int) -> None:
        self.ops.append(("expire", key))

    def execute(self) -> list[int]:
        if self.fail:
            raise ConnectionError("redis down")
        key = self.ops[0][1]
        self.store[key] = self.store.get(key, 0) + 1
        return [self.store[key], True]


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.fail = False

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self.store, self.fail)


def test_redis_rate_limiter_and_fallback() -> None:
    fake = _FakeRedis()
    limiter = RedisRateLimiter(fake)
    assert [limiter.hit("k", 2)[0] for _ in range(3)] == [True, True, False]
    assert any(k.startswith("aegis:rl:k:") for k in fake.store)
    fake.fail = True
    assert limiter.hit("other", 1)[0] is True and limiter.degraded
    assert limiter.hit("other", 1)[0] is False  # fallback still enforces the limit


@pytest.mark.skipif(not os.environ.get("AEGIS_TEST_REDIS_URL"), reason="set AEGIS_TEST_REDIS_URL for a live Redis test")
def test_live_redis_rate_limiter() -> None:
    limiter = RedisRateLimiter.from_url(os.environ["AEGIS_TEST_REDIS_URL"])
    key = f"live-{os.getpid()}"
    assert [limiter.hit(key, 3)[0] for _ in range(4)] == [True, True, True, False]
    assert not limiter.degraded


# ---- Authorisation bypass and injection attempts --------------------------------------------------


@pytest.mark.parametrize(("method", "path", "headers"), [
    ("get", "/api/incidents?token={viewer}", {}),
    ("get", "/api/incidents", {"Authorization": "Basic {viewer}"}),
    ("get", "/api/incidents", {"Authorization": "{viewer}"}),
    ("get", "/api/incidents", {"Cookie": "token={viewer}"}),
    ("get", "/api/incidents", {"X-API-Key": "{viewer}"}),
])
def test_tokens_only_accepted_as_bearer_header(api: ApiHarness, method: str, path: str,
                                               headers: dict[str, str]) -> None:
    fill = {"viewer": api.tokens["viewer"]}
    response = getattr(api.client, method)(path.format(**fill), headers={k: v.format(**fill) for k, v in headers.items()})
    assert response.status_code == 401


def test_method_override_and_path_tricks(api: ApiHarness) -> None:
    override = api.client.post("/api/incidents", headers={**api.headers("viewer"), "X-HTTP-Method-Override": "GET"})
    assert override.status_code == 405
    for path in ("/api/incidents/..%2Faudit", "/api/incidents/%2e%2e/audit", "/api/audit%00"):
        response = api.client.get(path, headers=api.headers("viewer"))
        assert response.status_code in (404, 422), path


@pytest.mark.parametrize("value", ["' OR 1=1 --", "CELL-101; DROP TABLE incidents", "<script>", "../../etc"])
def test_injection_strings_are_rejected(api: ApiHarness, value: str) -> None:
    response = api.get("/api/network/anomalies", params={"cell_id": value})
    assert response.status_code == 422  # type: ignore[attr-defined]
    assert api.get("/api/incidents").json()[0]["incident_id"] == "INC-2026-001"  # type: ignore[attr-defined]


# ---- Secrets ------------------------------------------------------------------------------------------


def test_secrets_never_exposed(api: ApiHarness, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="aegis")
    bodies = [api.client.get("/api/health").text, api.client.get("/openapi.json").text,
              api.get("/api/agent/status").text, api.client.get("/metrics").text,  # type: ignore[attr-defined]
              api.client.get("/api/incidents", headers={"Authorization": "Bearer wrong-token"}).text]
    logged = "\n".join(r.getMessage() + json.dumps(vars(r), default=str) for r in caplog.records)
    for secret in ("sk-ant-SECRET-not-real", "sk-openai-SECRET-not-real", api.tokens["viewer"], "wrong-token"):
        assert all(secret not in body for body in bodies), secret
        assert secret not in logged, secret
    assert "sk-ant" not in repr(api.settings)


# ---- Logging and metrics ---------------------------------------------------------------------------


def test_structured_access_log(api: ApiHarness, caplog: pytest.LogCaptureFixture) -> None:
    from app.observability.logging import JsonFormatter

    caplog.set_level(logging.INFO, logger="aegis")
    api.client.get("/api/incidents/INC-2026-001", headers={**api.headers("viewer"), "X-Request-ID": "log-test-1"})
    record = next(r for r in caplog.records if getattr(r, "route", None) == "/api/incidents/{incident_id}")
    line = json.loads(JsonFormatter().format(record))
    assert line["request_id"] == "log-test-1" and line["status"] == 200 and line["actor"] == "test-viewer"
    assert line["method"] == "GET" and line["duration_ms"] >= 0 and line["level"] == "INFO"


def test_rca_and_agent_logs_carry_incident_and_run_ids(api: ApiHarness, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="aegis")
    api.post("/api/incidents/INC-2026-001/investigate")
    from app.observability.logging import JsonFormatter

    lines = [json.loads(JsonFormatter().format(r)) for r in caplog.records]
    assert any(line.get("incident_id") == "INC-2026-001" and line["message"] == "rca completed" for line in lines)
    run = api.post("/api/agent/investigate", json={"scenario": "failed_ci"}).json()  # type: ignore[attr-defined]
    lines = [json.loads(JsonFormatter().format(r)) for r in caplog.records]
    assert any(line.get("agent_run_id") == run["run_id"] for line in lines)


def test_prometheus_metrics(api: ApiHarness) -> None:
    api.get("/api/incidents/INC-2026-001")
    text = api.client.get("/metrics").text
    assert 'aegis_http_requests_total{method="GET",route="/api/incidents/{incident_id}",status="200"}' in text
    assert "aegis_http_request_duration_seconds_bucket" in text
    assert "INC-2026-001" not in text  # route templates, not raw paths (bounded cardinality)
    assert "aegis_agent_actions_total" in text and "aegis_rca_runs_total" in text
