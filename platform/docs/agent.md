# DevSecOps agent

Source: `backend/app/agents/`. Contract: `ARCHITECTURE.md` §3.5.

**Loop.** OBSERVE → ANALYZE → PLAN → ACT → VERIFY → CLOSE. The phase never moves backwards. A deterministic
playbook per scenario chooses the next tool from earlier results, and each action's rationale is stored
before it runs.

**Policy.**

| Risk class | Behaviour | Tools |
|---|---|---|
| READ_ONLY | automatic | inspect_repository, inspect_git_diff, run_unit_tests, run_linter, run_tests, run_security_scan, inspect_dependencies, inspect_container, inspect_logs, inspect_metrics |
| LOW_RISK | automatic | create_incident, request_rca, generate_patch, generate_report, close_incident |
| REQUIRES_APPROVAL | approver (not the initiator) approves; operator+ executes | apply_patch, modify_dependency, restart_service |
| HIGH_RISK | off unless `AGENT_ALLOW_HIGH_RISK=true`; then approval + admin execution | rollback_deployment |
| BLOCKED | never | delete_infrastructure |

**Approving and executing an action.**

```bash
curl -s -H "Authorization: Bearer $OPERATOR" -X POST localhost:8000/api/agent/investigate \
     -H 'Content-Type: application/json' -d '{"scenario":"failed_ci"}'          # stops at apply_patch
curl -s -H "Authorization: Bearer $APPROVER" -X POST localhost:8000/api/agent/approve/<action_id> \
     -H 'Content-Type: application/json' -d '{"decision":"approve"}'
curl -s -H "Authorization: Bearer $OPERATOR" -X POST localhost:8000/api/agent/execute/<action_id>
```

**Sandbox.** Code scenarios run in a disposable copy of `demo-workspace/` under `AGENT_WORKSPACE_ROOT`, each
with its own git history. Commands are restricted to `python -m pytest|pyflakes` and allowlisted git
subcommands; they use argv lists only, a confined working directory, a scrubbed environment and timeouts.

**Simulations.**
- Vulnerability data comes from `agents/data/advisories.json` (fictional packages, `DEMO-CVE-*` ids).
- The production rollback re-simulates the scenario with the deployment reverted, in a verification run
  that opens no incidents. Recovery means the last 30 minutes are within the detection tolerances of the
  pre-incident baseline, with no open anomalies.
