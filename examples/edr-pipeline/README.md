# EDR Pipeline (Example)

This example demonstrates an **EDR-style loop** using `hushd` as the collector:

1. **Detect**: send simulated agent actions to `POST /api/v1/check`
2. **Collect**: pull the audit stream via `GET /api/v1/audit?format=jsonl`
3. **Triage**: summarize denied events into an incident report

## Quick Start

```bash
cd examples/edr-pipeline

export HUSHD_API_KEY="$(openssl rand -hex 32)"
docker compose up -d --build

node simulate.js
node triage.js
```

