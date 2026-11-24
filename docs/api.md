# REST API

Interactive OpenAPI documentation is served by the backend at `/docs` (JSON at `/openapi.json`).

## Authentication

Send `Authorization: Bearer <token>`. Tokens are configured as `name:role:sha256(token)` entries in
`AEGIS_API_TOKENS` (`make env` or `scripts/hash_token.py`). Roles are ordered: viewer < operator < approver < admin.
Missing or invalid tokens get `401`; insufficient roles get `403`. Both are written to the audit log.

## Typical session

```bash
TOKEN=$(grep ^operator= .aegis-tokens | cut -d= -f2-)
H="Authorization: Bearer $TOKEN"
curl -s -H "$H" -X POST localhost:8000/api/pipeline/run -H 'Content-Type: application/json' -d '{"scenario":"seeded"}'
curl -s -H "$H" localhost:8000/api/incidents
curl -s -H "$H" -X POST localhost:8000/api/incidents/INC-2026-001/investigate
curl -s -H "$H" -X POST localhost:8000/api/reports/generate -H 'Content-Type: application/json' -d '{"incident_id":"INC-2026-001"}'
curl -s -H "$H" "localhost:8000/api/reports/RPT-INC-2026-001-01?format=markdown"
```

## Endpoints

| Method and path | Role | Notes |
|---|---|---|
| `GET /api/health` | public | status, database, C library, LLM provider; no secrets |
| `POST /api/pipeline/run` | operator | `{scenario: seeded\|healthy, seed, minutes, rollback_minute}`; simulate → CDRs → C analysis → detection → correlation |
| `GET /api/pipeline/runs` | viewer | runs with their incident ids |
| `GET /api/calls/statistics`, `/api/calls/anomalies` | viewer | libcallanalyzer results (`?run_id`, default latest run) |
| `GET /api/network/overview` | viewer | health score with breakdown, KPI current vs baseline, cell status |
| `GET /api/network/metrics?metric=&cell_id=&start=&end=` | viewer | one series per cell |
| `GET /api/network/anomalies?cell_id=&metric=&severity=` | viewer | spec §6 anomaly objects |
| `GET /api/incidents?status=&severity=`, `/api/incidents/{id}` | viewer | detail includes timeline, symptoms, hypotheses, excluded candidates, caveats |
| `POST /api/incidents/{id}/investigate` | operator | runs the RCA loop |
| `GET /api/incidents/{id}/rca` | viewer | latest RCA with the spec §26 `explanation` chain |
| `POST /api/reports/generate` | operator | `{incident_id}` |
| `GET /api/reports?incident_id=`, `/api/reports/{id}?format=json\|markdown\|html` | viewer | HTML is served with a strict CSP |
| `GET /api/agent/status`, `/api/agent/actions`, `/api/agent/runs[/{id}]` | viewer | policy table, pending approvals |
| `POST /api/agent/investigate` | operator | `{scenario, incident_id?}` |
| `POST /api/agent/approve/{action_id}` | approver | `{decision: approve\|deny, comment}`; the run's initiator cannot approve |
| `POST /api/agent/execute/{action_id}` | operator (admin for HIGH_RISK) | executes approved actions only |
| `GET /api/deployments`, `/api/security/findings` | viewer | |
| `GET /api/audit?action=&limit=&offset=` | operator | |
| `GET /api/audit/verify` | admin | hash-chain verification |

Errors are JSON `{"detail": ...}`. Unexpected server errors return `500 {"detail": "internal server error",
"request_id": ...}` without internals. Every response carries `X-Request-ID`. Limits: `429` with `Retry-After`
when rate-limited, `413` above the request body limit.
