# Build a Complete AI-Driven Network Operations & DevSecOps Platform

You are a senior software architect, AI engineer, DevSecOps engineer, and full-stack developer.

Build a **complete, production-style prototype project** that integrates the following three capabilities into one coherent system:

1. **C library for call-log analysis with AI-assisted root-cause investigation**
2. **AI-generated analytics and anomaly reports from network counters and metrics**
3. **An autonomous AI agent for DevSecOps**

Do not build three disconnected mini-projects. Build one unified platform in which these capabilities share data, investigation workflows, AI tools, alerts, reports, and an autonomous agent.

The project should be technically substantial enough to demonstrate software engineering, AI/LLM integration, systems programming, observability, anomaly detection, root-cause analysis, and autonomous DevSecOps.

---

# 1. Project Concept

Name the project:

**Aegis-Net**

The platform should simulate/ingest operational data from a telecommunications/network environment and automatically:

- Analyze call logs/CDRs
- Detect abnormal call behavior
- Analyze network counters and KPIs
- Detect anomalies
- Correlate events across call logs and network metrics
- Perform AI-assisted root-cause analysis
- Generate human-readable incident reports
- Recommend remediation actions
- Execute safe automated DevSecOps actions through an autonomous agent
- Maintain an audit trail of every AI decision and action

The architecture should resemble a realistic enterprise NOC/SRE/DevSecOps platform.

---

# 2. Overall Architecture

Use this high-level pipeline:

```text
                         ┌─────────────────────────┐
                         │       Data Sources       │
                         ├─────────────────────────┤
                         │ Call Logs / CDRs         │
                         │ Network Counters         │
                         │ Application Metrics      │
                         │ Security Events          │
                         │ CI/CD Events             │
                         │ Git Repository           │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │     Data Ingestion       │
                         │ Python + C Library       │
                         └────────────┬────────────┘
                                      │
                                      ▼
                  ┌──────────────────────────────────────┐
                  │       Analytics & Detection Layer     │
                  ├──────────────────────────────────────┤
                  │ CDR Analysis                          │
                  │ Statistical Analytics                 │
                  │ Anomaly Detection                     │
                  │ KPI Analysis                          │
                  │ Correlation Engine                    │
                  └──────────────────┬───────────────────┘
                                     │
                                     ▼
                  ┌──────────────────────────────────────┐
                  │       AI Investigation Engine         │
                  ├──────────────────────────────────────┤
                  │ LLM Reasoning                         │
                  │ Tool Calling                          │
                  │ Root Cause Analysis                    │
                  │ Evidence Collection                    │
                  │ Hypothesis Generation                  │
                  │ Confidence Scoring                     │
                  └──────────────────┬───────────────────┘
                                     │
                    ┌────────────────┴─────────────────┐
                    ▼                                  ▼
        ┌──────────────────────┐           ┌──────────────────────┐
        │ Reporting Engine     │           │ Autonomous Agent     │
        ├──────────────────────┤           ├──────────────────────┤
        │ Incident Report      │           │ DevSecOps            │
        │ Network Report       │           │ CI/CD                 │
        │ Analytics            │           │ Security              │
        │ Root Cause            │           │ Remediation           │
        │ Recommendations      │           │ Validation             │
        └──────────┬───────────┘           └──────────┬───────────┘
                   │                                  │
                   └────────────────┬─────────────────┘
                                    ▼
                         ┌─────────────────────────┐
                         │       Web Dashboard      │
                         ├─────────────────────────┤
                         │ Incidents                │
                         │ Network KPIs             │
                         │ Anomalies                │
                         │ RCA                       │
                         │ Reports                  │
                         │ Agent Actions            │
                         │ Security                 │
                         └─────────────────────────┘
```

---

# 3. C Library — Call Log Analysis

Implement an actual reusable C library.

Do NOT merely write Python code pretending to be a C library.

Create:

```text
libcallanalyzer/
├── include/
│   └── call_analyzer.h
├── src/
│   ├── parser.c
│   ├── analyzer.c
│   ├── statistics.c
│   ├── anomaly.c
│   └── utils.c
├── tests/
│   └── test_call_analyzer.c
├── CMakeLists.txt
└── README.md
```

The library should expose a clean public API.

Example:

```c
typedef struct {
    char timestamp[32];
    char caller[32];
    char callee[32];
    char cell_id[32];
    int duration;
    int status_code;
    int signal_strength;
    int packet_loss;
} CallRecord;

typedef struct {
    int total_calls;
    int successful_calls;
    int dropped_calls;
    double drop_rate;
    double average_duration;
    double average_signal;
} CallStatistics;

int parse_call_log(
    const char *filepath,
    CallRecord **records,
    size_t *count
);

int calculate_statistics(
    const CallRecord *records,
    size_t count,
    CallStatistics *stats
);

int detect_call_anomalies(
    const CallRecord *records,
    size_t count,
    /* anomaly output */
);

void free_call_records(CallRecord *records);
```

The library must support:

- CSV call logs
- Parsing
- Validation
- Aggregation
- Call-drop analysis
- Duration analysis
- Cell/tower analysis
- Signal-strength analysis
- Failure-code analysis
- Time-window aggregation
- Caller/callee behavior
- Geographic/cell-level aggregation
- Outlier detection
- Error handling
- Memory management

Pay attention to:

- memory safety
- buffer boundaries
- malformed input
- NULL handling
- integer overflow
- memory leaks
- clean API design

Compile with:

```bash
-Wall -Wextra -Wpedantic
```

and preferably support:

```bash
-fsanitize=address,undefined
```

---

# 4. Python Binding for the C Library

Expose the C library to Python.

Prefer:

- ctypes, cffi, or pybind11

Use Python as the orchestration layer while keeping computational/log-processing functionality in the C library.

The Python layer should be able to execute:

```python
from call_analyzer import analyze_call_log

result = analyze_call_log("data/call_logs.csv")
```

Return structured JSON/Python dictionaries containing:

- total calls
- success rate
- drop rate
- average duration
- cell-level statistics
- failure-code statistics
- detected anomalies
- suspicious time windows

---

# 5. Network Counter & Metric Analytics

Create a realistic network telemetry simulator.

Generate metrics such as:

### Radio/network metrics

- throughput
- latency
- packet loss
- jitter
- RSSI
- RSRP
- RSRQ
- SINR
- handover success rate
- handover failure rate
- call setup success rate
- call drop rate
- retransmission rate
- CPU utilization
- memory utilization
- active users
- bandwidth utilization

Create realistic time-series data.

Do NOT generate completely random independent values.

Introduce realistic correlations.

For example:

```text
High CPU
   ↓
Packet processing degradation
   ↓
Latency increases
   ↓
Packet loss increases
   ↓
Call drops increase
```

Also simulate incidents such as:

- overloaded base station
- failing network interface
- packet-loss burst
- abnormal traffic spike
- degraded radio signal
- software deployment regression
- memory leak
- security attack
- misconfiguration

---

# 6. Anomaly Detection

Implement an analytics engine capable of detecting anomalies.

Start with interpretable techniques:

- moving averages
- rolling standard deviation
- Z-score
- EWMA
- threshold-based detection
- rate-of-change detection

Then optionally implement:

- Isolation Forest
- DBSCAN
- clustering-based detection

Every anomaly should contain:

```json
{
  "metric": "packet_loss",
  "timestamp": "...",
  "value": 18.4,
  "baseline": 2.1,
  "severity": "critical",
  "anomaly_score": 0.97,
  "related_metrics": [
    "latency",
    "call_drop_rate",
    "throughput"
  ]
}
```

---

# 7. Correlation Engine

This is a critical component.

Do not simply report individual anomalies.

Correlate:

```text
Call logs
+
Network counters
+
Application metrics
+
Security events
+
Deployment events
```

Example:

```text
14:05 deployment occurred
       ↓
14:07 CPU increased
       ↓
14:08 latency increased
       ↓
14:08 packet loss increased
       ↓
14:09 call drops increased
       ↓
14:10 anomaly detected
```

The system should infer that these events are probably related.

Create an incident object:

```json
{
  "incident_id": "INC-2026-001",
  "severity": "HIGH",
  "start_time": "...",
  "affected_cells": ["CELL-102", "CELL-103"],
  "symptoms": [],
  "events": [],
  "suspected_causes": [],
  "confidence": 0.91
}
```

---

# 8. AI Root Cause Analysis Engine

Build an AI investigation layer using an LLM.

The LLM must NOT receive only a giant raw prompt containing all data.

Give it structured tools.

Implement tools such as:

```text
get_call_statistics()
get_cell_statistics(cell_id)
get_metric_history(metric, start, end)
get_anomalies(time_range)
get_related_events(incident_id)
get_recent_deployments()
get_security_events()
get_logs(service, time_range)
compare_baseline(metric, time_range)
```

The AI investigator should reason through evidence.

Example workflow:

```text
Incident detected
        ↓
AI Investigator
        ↓
Collect evidence
        ↓
Generate hypotheses
        ↓
Query tools
        ↓
Compare hypotheses
        ↓
Identify probable root cause
        ↓
Assign confidence
        ↓
Recommend remediation
```

The RCA response should contain:

```json
{
  "root_cause": "...",
  "confidence": 0.89,
  "evidence": [],
  "alternative_hypotheses": [],
  "impact": "...",
  "recommended_actions": [],
  "verification_steps": []
}
```

The AI should distinguish:

- observed facts
- inferred relationships
- hypotheses
- recommendations

Never present an AI inference as an established fact.

---

# 9. AI-Generated Network Report

Create an AI reporting engine.

Given the analytics results, automatically produce:

### Executive Summary

What happened?

### KPI Analysis

What changed?

### Anomaly Analysis

Which metrics deviated?

### Correlation Analysis

Which metrics/events appear connected?

### Root Cause

What is the most likely explanation?

### Impact

What services/cells/users may have been affected?

### Recommendations

What should the engineering team do?

### Confidence

How certain is the analysis?

Generate both:

- JSON
- Markdown
- HTML

Optionally generate PDF.

Example report:

```text
NETWORK HEALTH & INCIDENT ANALYSIS

Incident: INC-2026-001
Severity: HIGH

Executive Summary
-----------------
Network performance degraded between 14:07 and 14:22.

Key Findings
-------------
• Packet loss increased from 1.8% to 17.4%
• Latency increased by 240%
• Call-drop rate increased from 1.2% to 8.7%
• CPU utilization reached 94%

Root Cause
----------
Most likely cause: a software deployment caused excessive
CPU utilization on the packet-processing service.

Confidence: 91%

Recommended Actions
-------------------
1. Roll back deployment.
2. Validate CPU utilization.
3. Monitor packet loss.
4. Verify call-drop rate returns to baseline.
```

---

# 10. Autonomous DevSecOps Agent

Create the third major component: an autonomous AI agent.

The agent should monitor:

```text
Git repository
CI/CD pipeline
Application logs
Security scanner
Infrastructure metrics
Network incidents
```

The agent should have tools such as:

```text
inspect_repository()
inspect_git_diff()
run_unit_tests()
run_linter()
run_security_scan()
inspect_dependencies()
inspect_container()
inspect_logs()
inspect_metrics()
create_incident()
generate_patch()
run_tests()
generate_report()
rollback_deployment()
```

The agent should follow a structured loop:

```text
OBSERVE
   ↓
ANALYZE
   ↓
PLAN
   ↓
ACT
   ↓
VERIFY
   ↓
LEARN / CLOSE
```

---

# 11. DevSecOps Scenarios

Implement realistic scenarios.

### Scenario 1 — Vulnerable Dependency

Agent detects:

```text
package X
CVE-XXXX
CRITICAL
```

Agent:

1. identifies dependency
2. checks available safe version
3. proposes upgrade
4. modifies dependency file
5. runs tests
6. runs security scan
7. reports result

Do not automatically deploy unless explicitly configured.

---

### Scenario 2 — Failed CI Build

Agent detects failed pipeline.

It should:

1. inspect logs
2. identify failing test
3. inspect recent Git changes
4. formulate hypothesis
5. propose patch
6. generate patch
7. run tests
8. verify
9. produce report

---

### Scenario 3 — Production Anomaly

Network analytics detects:

```text
Latency ↑
Packet loss ↑
Call drops ↑
CPU ↑
```

Agent:

1. opens incident
2. gathers telemetry
3. asks RCA engine for investigation
4. identifies likely deployment regression
5. checks recent deployment
6. recommends rollback
7. optionally executes rollback only if policy permits
8. verifies recovery
9. closes incident

---

# 12. Safety Model for Autonomous Actions

Do NOT create an unrestricted AI agent.

Implement an action policy.

Classify actions:

```text
READ_ONLY
LOW_RISK
REQUIRES_APPROVAL
HIGH_RISK
```

Examples:

```text
Read logs             → READ_ONLY
Run tests             → READ_ONLY
Run security scan     → READ_ONLY
Create report         → LOW_RISK
Create patch          → LOW_RISK
Modify dependency     → REQUIRES_APPROVAL
Restart service       → REQUIRES_APPROVAL
Rollback production   → HIGH_RISK
Delete infrastructure → BLOCKED
```

The agent must explain why an action is being taken before execution.

Every action must be logged.

---

# 13. Dashboard

Build a web dashboard.

Recommended stack:

Frontend:

- React
- TypeScript
- Tailwind CSS
- Recharts or Plotly

Backend:

- Python
- FastAPI

Database:

- PostgreSQL

Optional:

- Redis for queues/caching

Dashboard pages:

```text
Dashboard
│
├── Network Overview
├── Call Analytics
├── Anomalies
├── Incidents
├── Root Cause Analysis
├── AI Reports
├── DevSecOps Agent
├── Security
└── Audit Log
```

Dashboard should show:

- network health score
- active incidents
- anomaly count
- call-drop rate
- latency
- packet loss
- throughput
- CPU
- affected cells
- incident timeline
- RCA confidence
- AI agent actions

Use charts heavily.

---

# 14. Incident Timeline

Provide an interactive incident timeline.

Example:

```text
14:05 ─ Deployment
14:07 ─ CPU anomaly
14:08 ─ Latency anomaly
14:08 ─ Packet loss anomaly
14:09 ─ Call-drop anomaly
14:10 ─ Incident created
14:11 ─ AI investigation started
14:13 ─ Root cause identified
14:15 ─ Remediation approved
14:16 ─ Rollback executed
14:19 ─ Metrics recovered
14:20 ─ Incident resolved
```

---

# 15. Data Model

Create proper schemas for:

```text
CallRecord
NetworkMetric
Anomaly
Incident
IncidentEvent
RootCauseAnalysis
Recommendation
AgentAction
SecurityFinding
Deployment
AuditLog
```

Use Pydantic models on the API layer.

---

# 16. API Design

Create REST APIs such as:

```text
GET /api/health

GET /api/calls/statistics
GET /api/calls/anomalies

GET /api/network/metrics
GET /api/network/anomalies

GET /api/incidents
GET /api/incidents/{id}

POST /api/incidents/{id}/investigate

GET /api/incidents/{id}/rca

POST /api/reports/generate

GET /api/reports/{id}

GET /api/agent/status
GET /api/agent/actions

POST /api/agent/investigate
POST /api/agent/approve/{action_id}
POST /api/agent/execute/{action_id}

GET /api/audit
```

Include OpenAPI documentation automatically through FastAPI.

---

# 17. Database

Use PostgreSQL.

Create migrations.

Do not store everything as arbitrary JSON.

Use proper relational tables for important entities while allowing JSON fields for AI evidence and tool outputs where appropriate.

---

# 18. Project Structure

Use a clean monorepo:

```text
nexus-ai/
│
├── README.md
├── docker-compose.yml
├── .env.example
├── Makefile
│
├── c-library/
│   ├── include/
│   ├── src/
│   ├── tests/
│   ├── CMakeLists.txt
│   └── README.md
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── agents/
│   │   ├── analytics/
│   │   ├── rca/
│   │   ├── reporting/
│   │   ├── security/
│   │   └── main.py
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── hooks/
│   │   └── types/
│
├── data/
│   ├── call_logs/
│   ├── network_metrics/
│   ├── incidents/
│   └── security/
│
├── scripts/
│   ├── generate_call_logs.py
│   ├── generate_network_metrics.py
│   └── simulate_incident.py
│
├── reports/
│
├── tests/
│
└── docs/
    ├── architecture.md
    ├── api.md
    ├── agent.md
    ├── rca.md
    └── security.md
```

---

# 19. Docker

Everything should run locally with:

```bash
docker compose up --build
```

Services:

```text
frontend
backend
postgres
redis
```

The C library should be compiled as part of the backend build or exposed through a shared library.

---

# 20. AI Provider Abstraction

Do not hard-code the application around one LLM provider.

Create:

```python
class LLMProvider:
    def generate(...)
    def tool_call(...)
```

Implement a provider abstraction so the project can support:

- Anthropic Claude
- OpenAI
- local models

Use environment variables:

```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
MODEL_NAME=
```

Never commit API keys.

---

# 21. Observability

Instrument the application itself.

Add:

- structured logging
- request IDs
- agent execution IDs
- incident IDs
- latency metrics
- error metrics
- audit logs

Where practical, support:

- OpenTelemetry
- Prometheus
- Grafana

---

# 22. Testing

This is important.

Do not stop after getting the application to run.

Implement:

### C tests

- parser tests
- malformed CSV tests
- memory tests
- statistics tests
- anomaly tests

### Python tests

- analytics
- anomaly detection
- correlation
- RCA schemas
- agent policies
- API endpoints

### Frontend tests

At least basic component tests.

### Integration tests

Test:

```text
data → analytics → anomaly → incident → RCA → report
```

Also test:

```text
security finding → agent → proposed action → approval → execution → verification
```

---

# 23. Demo Mode

Create a one-command demo:

```bash
make demo
```

The demo should:

1. generate realistic telemetry
2. inject a known incident
3. process call logs
4. detect anomalies
5. correlate events
6. create an incident
7. run AI RCA
8. generate a report
9. invoke the DevSecOps agent
10. show proposed remediation
11. execute safe actions
12. verify recovery
13. display the final incident report

The demo should work without external infrastructure.

If no LLM API key is available, implement a deterministic mock AI provider so the entire project remains demonstrable offline.

---

# 24. Seeded Incident

Create at least one sophisticated seeded incident.

Example:

A deployment introduces a memory leak in a packet-processing service.

Consequences:

```text
Memory utilization ↑
CPU utilization ↑
Packet processing latency ↑
Packet loss ↑
Throughput ↓
Call drops ↑
```

The system should correlate these signals.

There should also be a deployment event shortly before the anomaly.

The AI investigator should conclude that the deployment is the leading hypothesis because:

1. the deployment preceded the degradation
2. CPU/memory increased afterward
3. network performance deteriorated
4. call failures increased
5. rollback restores baseline metrics

The system should explicitly show the evidence chain.

---

# 25. UI Requirements

Make the UI look like a serious enterprise NOC/SRE product.

Do NOT create a generic CRUD dashboard.

Use:

- dark operations-console aesthetic
- status indicators
- KPI cards
- time-series charts
- incident severity indicators
- timeline visualization
- anomaly markers
- RCA evidence panels
- agent action panel
- audit trail

The main dashboard should immediately answer:

```text
Is the network healthy?
What is broken?
How severe is it?
Why is it broken?
What is the AI doing about it?
Has the remediation worked?
```

---

# 26. Explainability

For every AI RCA, show:

```text
Observed Evidence
        ↓
Correlated Events
        ↓
Candidate Hypotheses
        ↓
Hypothesis Evaluation
        ↓
Most Likely Root Cause
        ↓
Confidence
        ↓
Recommended Remediation
```

Do not expose hidden chain-of-thought.

Instead expose concise evidence and decision summaries.

---

# 27. Security Requirements

Implement:

- API authentication
- role-based access control
- agent permissions
- action approval
- secrets through environment variables
- input validation
- command execution sandboxing
- audit logs
- rate limiting
- safe subprocess handling
- no arbitrary shell execution from LLM-generated strings

The LLM must never directly execute arbitrary commands.

Use an allowlisted tool layer.

---

# 28. Documentation

Write a high-quality README containing:

1. Project overview
2. Architecture
3. Why C is used
4. AI architecture
5. RCA workflow
6. Anomaly detection
7. DevSecOps agent
8. Security model
9. Installation
10. Configuration
11. Running the demo
12. API documentation
13. Testing
14. Example incident
15. Limitations
16. Future improvements

Also create architecture diagrams using Mermaid.

---

# 29. Engineering Standards

Follow these rules:

- production-quality naming
- type hints in Python
- modular architecture
- SOLID principles where appropriate
- meaningful error handling
- structured logging
- no giant monolithic files
- no hard-coded secrets
- no fake implementations disguised as real functionality
- no unnecessary dependencies
- no placeholder functions unless clearly marked
- no TODOs for core functionality
- no copied boilerplate that is not actually integrated

Every major component must actually work together.

---

# 30. Development Strategy

Build the project incrementally.

Phase 1:
C call-analysis library.

Phase 2:
Python bindings.

Phase 3:
Network telemetry generator.

Phase 4:
Analytics and anomaly detection.

Phase 5:
Correlation engine.

Phase 6:
FastAPI backend and PostgreSQL.

Phase 7:
AI RCA engine with tool calling.

Phase 8:
AI report generator.

Phase 9:
Autonomous DevSecOps agent.

Phase 10:
React dashboard.

Phase 11:
Security and audit system.

Phase 12:
Dockerization.

Phase 13:
Automated tests.

Phase 14:
End-to-end demo.

After each phase, run tests and fix failures before moving to the next phase.

---

# 31. Most Important Requirement

Do not merely produce an architecture document.

Actually BUILD THE PROJECT.

Create the complete source tree and implementation.

The final result should be something I can clone, configure an API key, run:

```bash
docker compose up --build
```

and then access the dashboard.

Also provide:

```bash
make test
make demo
make clean
```

The final answer should contain:

1. Project structure
2. Implementation
3. Setup instructions
4. Environment configuration
5. Architecture explanation
6. Demo instructions
7. API documentation
8. Testing instructions
9. Example output
10. Known limitations

Before considering the project complete, perform a self-audit:

- Does the C library actually compile?
- Do C tests pass?
- Does Python correctly call the C library?
- Does the telemetry generator produce correlated data?
- Does anomaly detection actually detect the seeded incident?
- Does correlation produce a meaningful incident?
- Does the RCA engine receive structured evidence?
- Does the AI report contain evidence and confidence?
- Does the DevSecOps agent use controlled tools?
- Are dangerous actions approval-gated?
- Does the dashboard consume real backend data?
- Does the complete demo work end-to-end?
- Does `docker compose up --build` work from a clean environment?
- Are there hard-coded secrets?
- Are there broken imports, placeholder functions, or dead code?

Fix every issue discovered during the audit before declaring the project complete.

Prioritize correctness and integration over superficial feature count.