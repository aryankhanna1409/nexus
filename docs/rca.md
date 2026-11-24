# Root-cause analysis

Source: `backend/app/rca/`, providers in `backend/app/llm/`. Contract: `ARCHITECTURE.md` §3.4.

1. The engine sends the provider a short incident summary (ids, cells and symptom names, but no raw data)
   and the schemas of nine read-only tools: `get_call_statistics`, `get_cell_statistics`, `get_metric_history`,
   `get_anomalies`, `get_related_events`, `get_recent_deployments`, `get_security_events`, `get_logs`,
   `compare_baseline`.
2. Each tool call is validated twice: by a strict JSON schema at the provider, then by a Pydantic model before
   execution. Unknown tools, invalid arguments, out-of-scope incidents, time ranges longer than 24 h and
   oversized results come back as tool errors. Nothing is executed outside the registry.
3. The final answer must be a JSON `RCAAnswer`:
   - `facts`, each citing tool-call ids;
   - `inferences`;
   - `hypotheses`, each with confidence ≤ 0.95 and supporting/contradicting evidence;
   - `recommended_actions` with risk classes;
   - `verification_steps`.

   Citations must refer to tool calls that actually succeeded. Invalid answers are returned with feedback,
   for up to three attempts. After that the RCA is stored as `failed` and no cause is invented.
4. The result is stored with every tool call, recommendations become rows, and the incident timeline gets
   `ai_investigation_started` and `root_cause_identified` (or `investigation_failed`). The API returns the
   spec §26 explanation chain.

**Mock provider.** `LLM_PROVIDER=mock`, the default, is a deterministic rule-based investigator. It follows a
fixed evidence-gathering plan through the same tools and loop, and its answer passes the same validation. It
is clearly labelled `mock` in every output.

**Real providers.**
- `anthropic`: official SDK, default model `claude-opus-5-5`. Effort is set explicitly, tools are strict,
  server-side refusal fallbacks are on, refusals are detected before content is read, and assistant content is
  echoed back unchanged.
- `openai`: Chat Completions with strict function tools.
- `local`: an OpenAI-compatible endpoint.

Live calls are only covered by the opt-in test `AEGIS_RUN_LIVE_LLM_TESTS=1`.
