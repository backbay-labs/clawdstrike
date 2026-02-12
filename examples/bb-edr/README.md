# bb-edr (Agentic EDR Example)

This example demonstrates an **agentic EDR-style loop** for OpenClaw agents:

1. **Detect**: record policy decisions (allowed/denied) as audit events
2. **Triage**: summarize denied activity and group by guard
3. **Respond**: write an incident report and optionally emit a simple blocklist artifact

It uses `@clawdstrike/openclaw` as the policy engine + OpenClaw integration layer.

> This is a teaching example. It does **not** implement OS-level telemetry or syscall interception.

## Quick Start (no OpenClaw required)

```bash
cd examples/bb-edr

# Validate the policy schema
npm run policy:lint

# Generate a demo audit log from scenario.json
npm run simulate

# Triage denied events into a report
npm run triage

# Inspect denied events
npm run audit:denied
```

## Files

- `policy.yaml` — policy enforced by clawdstrike
- `scenario.json` — a small set of simulated tool actions
- `simulate.js` — writes `.hush/audit.jsonl` from the scenario
- `triage.js` — reads `.hush/audit.jsonl` and writes `reports/`
- `openclaw.json` — OpenClaw configuration (enables `@clawdstrike/openclaw` in **audit** mode)
- `skills/edr-triage/SKILL.md` — how an OpenClaw triage agent should operate

## Using with OpenClaw

If you have OpenClaw installed, you can point an agent at the same audit log and policy:

```bash
openclaw run --config ./openclaw.json
```

Suggested prompts:

- “Read `.hush/audit.jsonl` and write a short incident report to `./reports/incident.md`.”
- “Explain the denied events and recommend the smallest policy changes to allow only the legitimate ones.”

## Adapting this to your own agentic EDR

- Replace `scenario.json` with events generated from your real tool boundary (or your own telemetry).
- Extend `triage.js` into a responder that creates structured tickets, enriches with context, and gates actions with `policy_check`.
