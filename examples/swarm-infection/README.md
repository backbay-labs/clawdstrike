# Swarm Infection Demo

This demo shows a realistic swarm failure mode: **one compromised agent poisons shared context**
and attempts to steer benign agents into dangerous tool usage.

It runs two phases back-to-back:

1. **Naive swarm (no ingestion boundary):** the poison lands in shared memory. A benign agent later attempts a forbidden action.
2. **Hardened swarm (ingestion boundary enabled):** the poison is blocked at ingestion via `prompt_injection` on `Custom("untrusted_text")`.

In both phases, all tool execution is fail-closed through a tool boundary (`@clawdstrike/openai`)
backed by hushd (`@clawdstrike/engine-remote`). The blue team watches the hushd SSE stream for
real-time attribution.

## Code Tour

- `clawdstrike.ts`: the "meat" (memory boundary + tool boundary + SSE attribution wiring)
- `index.ts`: the deterministic swarm scenario + on-screen narration/output

## Run

```bash
./run.sh
```

## Visual (HTML)

Open the narrative diagram:

```bash
open narrative.html
```

## Prereqs (manual)

If you want to run hushd yourself:

```bash
cargo run -p hushd --bin hushd -- start --port 9876 --ruleset strict
HUSHD_URL=http://127.0.0.1:9876 npx tsx index.ts
```
