#!/usr/bin/env bash
# Builds and starts the Docker stack under an isolated compose project with a
# throwaway env file, checks health and core API flows, then removes the
# project's containers and volumes. Never touches .env or another project.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PROJECT="aegis-smoke"
PORT="${SMOKE_PORT:-18000}"
UI_PORT="${SMOKE_UI_PORT:-18080}"
export BACKEND_PORT="$PORT" FRONTEND_PORT="$UI_PORT"
cleanup() {
  docker compose -p "$PROJECT" --env-file "$WORK/env" -f "$REPO_ROOT/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
python3 "$REPO_ROOT/scripts/init_env.py" --env-file "$WORK/env" --tokens-file "$WORK/tokens" >/dev/null
token() { grep "^$1=" "$WORK/tokens" | cut -d= -f2-; }
compose() { docker compose -p "$PROJECT" --env-file "$WORK/env" -f "$REPO_ROOT/docker-compose.yml" "$@"; }

compose build ${SMOKE_BUILD_ARGS:-}
compose up -d
for _ in $(seq 1 90); do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q backend)" 2>/dev/null || true)"
  [ "$status" = "healthy" ] && break
  sleep 2
done
echo "backend health status: ${status:-unknown}"
[ "${status:-}" = "healthy" ] || { compose logs backend | tail -50; exit 1; }

api() { curl -fsS -H "Authorization: Bearer $(token "$1")" "${@:3}" "http://127.0.0.1:$PORT$2"; }
echo "health: $(curl -fsS "http://127.0.0.1:$PORT/api/health")"
incidents="$(api viewer /api/incidents)"
echo "incidents: $incidents"
echo "$incidents" | grep -q '"INC-2026-001"'
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/incidents")"
echo "unauthenticated /api/incidents -> $code"; [ "$code" = "401" ]
rca="$(api operator /api/incidents/INC-2026-001/investigate -X POST)"
echo "$rca" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("rca:", d["status"], d["provider"], d["confidence"], d["root_cause"][:70])'
report="$(api operator /api/reports/generate -X POST -H 'Content-Type: application/json' -d '{"incident_id":"INC-2026-001"}')"
echo "$report" | python3 -c 'import json,sys; print("report:", json.load(sys.stdin)["report_id"])'
agent="$(api operator /api/agent/investigate -X POST -H 'Content-Type: application/json' -d '{"scenario":"failed_ci"}')"
echo "$agent" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("agent:", d["status"], [(a["tool"], a["status"]) for a in d["actions"]])
pending = [a["tool"] for a in d["actions"] if a["status"] == "awaiting_approval"]
assert d["status"] == "awaiting_approval" and pending == ["apply_patch"], "agent did not reach the patch approval step"'
echo "audit chain: $(api admin /api/audit/verify)"
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$UI_PORT/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl -fsS "http://127.0.0.1:$UI_PORT/" | grep -q '<div id="root">' && echo "frontend: index served"
echo "frontend proxy: $(curl -fsS -H "Authorization: Bearer $(token viewer)" "http://127.0.0.1:$UI_PORT/api/network/overview" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("health_score", d["health_score"], "active_incidents", d["active_incidents"])')"
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$UI_PORT/metrics")"
echo "frontend /metrics -> $code (served by the SPA fallback, not proxied)"
curl -fsS "http://127.0.0.1:$UI_PORT/metrics" | grep -q "aegis_http_requests_total" && { echo "metrics leaked through proxy"; exit 1; } || true
compose logs backend 2>&1 | grep -E "libcallanalyzer|Running upgrade|bootstrap pipeline completed" | head -5
if [ "${SMOKE_UI_CHECK:-0}" = "1" ]; then
  # Browser check of every dashboard page (Playwright container on the host network).
  mkdir -p "${SMOKE_SCREENSHOTS:-$WORK/shots}"
  docker run --rm --network host -v "$REPO_ROOT/scripts":/check -v "${SMOKE_SCREENSHOTS:-$WORK/shots}":/shots \
    -w /tmp mcr.microsoft.com/playwright:v1.49.1-noble \
    sh -c "npm init -y >/dev/null && npm i --no-audit --no-fund playwright@1.49.1 >/dev/null && cp /check/ui_check.mjs . && node ui_check.mjs http://127.0.0.1:$UI_PORT '$(token operator)' /shots"
fi
echo "SMOKE TEST PASSED"
