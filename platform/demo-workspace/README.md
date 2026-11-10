# demo-workspace (synthetic)

A tiny, fictional "packet-gateway" service used **only** as the DevSecOps
agent's sandbox. The agent never edits this template: each agent run copies it
into a disposable directory under `AGENT_WORKSPACE_ROOT`, initialises a
private git repository there, and works on that copy.

Dependencies in `requirements.txt` are fictional package names. They are never
installed. The security scanner checks them against Aegis-Net's synthetic
advisory database, whose identifiers use the `DEMO-CVE-` prefix and do not
refer to real vulnerabilities.
