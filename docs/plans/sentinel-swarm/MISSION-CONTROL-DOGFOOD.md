# Mission Control Dogfood Plan

## Goal

Prove the live Mission Control operator flow in the real workbench shell, not just in unit tests.

This dogfood loop should verify:

1. A fresh operator can create runtime-bound sentinels from the UI.
2. A `claude_code` sentinel shows the current web-runtime truth: blocked launch posture when the embedded MCP bridge is unavailable.
3. An `openclaw` sentinel becomes launch-ready when a live hushd endpoint reports online agents, and launching the mission emits runtime evidence and findings in the UI.

## Scope

This loop targets the mounted workbench desktop shell in `apps/workbench` via a real Playwright-driven browser session.

It does not try to fake native Tauri behavior. In the browser runtime:

- `claude_code` should be observed as blocked unless the embedded MCP bridge is actually present.
- `openclaw` readiness is driven by live hushd agent status.

## Harness Shape

The smoke harness should:

1. Start the Vite workbench dev server when needed.
2. Open a fresh Playwright session and clear prior local/session/IndexedDB state.
3. Seed a live hushd heartbeat for an OpenClaw-capable endpoint/runtime so the fleet connection shows at least one online agent.
4. Use the real Settings UI to connect the workbench to hushd.
5. Use the real Sentinel Create wizard to create:
   - one `claude_code` sentinel
   - one `openclaw` sentinel
6. Use the real Mission Control UI to launch:
   - one blocked Claude mission
   - one ready OpenClaw mission
7. Capture screenshots, page text snapshots, console/network logs, and a machine-readable `summary.json`.

## Pass Criteria

The dogfood run is successful when all of the following are true:

1. Fleet connection succeeds against live hushd and the UI shows `Fleet Summary`.
2. The Claude mission shows `Runtime Readiness` as `Blocked`.
3. Launching the Claude mission creates a blocked mission record in the Mission Control queue.
4. The OpenClaw mission shows `Runtime Readiness` as `Ready`.
5. Launching the OpenClaw mission produces:
   - runtime timeline entries
   - evidence entries
   - at least one linked finding in the mission detail view

## Artifacts

Artifacts should be written under:

`output/playwright/workbench-mission-control-dogfood/<timestamp>/`

Expected outputs:

- `settings-connected.png` / `.txt`
- `sentinel-claude-created.png` / `.txt`
- `sentinel-openclaw-created.png` / `.txt`
- `missions-claude-blocked.png` / `.txt`
- `missions-openclaw-ready.png` / `.txt`
- `missions-openclaw-launched.png` / `.txt`
- `console-errors.txt`
- `network.txt`
- `summary.json`

## Command

Primary entrypoint:

```bash
bash scripts/workbench-mission-control-dogfood.sh
```

Useful knobs:

- `WORKBENCH_MISSION_DOGFOOD_HEADED=1`
- `WORKBENCH_MISSION_DOGFOOD_START_DEV=0`
- `WORKBENCH_MISSION_DOGFOOD_BASE_URL=http://127.0.0.1:1421`
- `HUSHD_URL=http://127.0.0.1:9876`
- `HUSHD_API_KEY=...`

## Follow-on

If native Tauri dogfooding becomes part of the routine, add a second phase that runs the same operator flow against `npm --prefix apps/workbench run tauri:dev` and upgrades the Claude branch from `blocked` validation to `ready` validation.
