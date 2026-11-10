# Security

See README §8 for the control summary and `ARCHITECTURE.md` §3.7–3.7a and §4 for details.

## Threat model (prototype)

| Boundary | Threat | Mitigation |
|---|---|---|
| CSV input → C parser | malformed or oversized input, memory errors | bounded lines/fields, strict validation, ASan/UBSan/LSan and fault-injection tests |
| HTTP clients → API | unauthenticated access, privilege escalation, injection, floods | bearer tokens (hashed), ordered roles, pattern-validated parameters, body limit, rate limiting, audited denials |
| LLM output → RCA/agent | prompt injection via data, fabricated evidence, command execution | tool results marked as data; read-only allowlisted tools; schema and citation validation; the LLM never chooses agent commands |
| Agent → OS | arbitrary command execution, escape from workspace | fixed executables, argv-only, allowlisted subcommands, confined working directory, scrubbed environment, timeouts, `shell=False` (AST-enforced) |
| Reports → browsers | stored XSS | Jinja2 autoescape, Markdown cell escaping, CSP, sandboxed iframe in the dashboard |
| Operators | tampering with history | hash-chained audit log with verification |

## Operational guidance

- Generate credentials with `make env`. Keep `.env` and `.aegis-tokens` private; both are git- and
  docker-ignored.
- Keep `AGENT_ALLOW_HIGH_RISK=false` except for demonstrations.
- `/metrics` has no authentication. In Docker it isn't routed through the dashboard proxy; keep it internal.
- This is a prototype: no TLS termination, external identity provider or secret manager is included.
