# OpenClaw Runtime Compatibility Validation (2026-02-26)

## Objective

Close launch finding S4/S5 with runtime evidence against a live OpenClaw runtime.

## Environment

- Date: **2026-02-26**
- OpenClaw runtime: `2026.2.15`
- Plugin source loaded from:
  - `/Users/connor/Medica/backbay/standalone/clawdstrike-sdks/packages/adapters/clawdstrike-openclaw/dist/plugin.js`
- Isolated runtime state:
  - `OPENCLAW_STATE_DIR=/tmp/openclaw-pr101-validate-ViUNoh`
  - `OPENCLAW_CONFIG_PATH=/tmp/openclaw-pr101-validate-ViUNoh/openclaw.json`

## Runtime Evidence

1. Named hook registration is accepted by runtime.
   - Command: `openclaw plugins info clawdstrike-security --json`
   - Observed `hookNames`:
     - `clawdstrike:cua-bridge:before-tool-call`
     - `clawdstrike:tool-preflight:before-tool-call`
     - `clawdstrike:cua-bridge:tool-call`
     - `clawdstrike:tool-preflight:tool-call`
     - `clawdstrike:tool-guard:tool-result-persist`
     - `clawdstrike:agent-bootstrap`

2. Gateway runtime initializes hook runner with Clawdstrike hooks.
   - Runtime log evidence:
     - `hook runner initialized with 6 registered hooks`
     - `[gateway] [clawdstrike] Plugin registered`
   - No `hook registration missing name` warning was observed after the named-hook change.

3. Gateway methods execute while plugin is loaded.
   - `openclaw gateway call --json health` returns `ok: true`.
   - `chat.send`, `chat.history`, and `agent.wait` calls succeed under the same runtime.

## Code-Level Compatibility Mitigation

- `src/plugin.ts` now registers hooks with explicit names and legacy fallbacks:
  - `registerHook(event, handler, { name, entry: { hook: { name } } })`
  - Fallbacks: `{ name }`, then legacy `registerHook(event, handler)`, then `api.on(...)`.
- `src/hooks/tool-preflight/handler.ts` and `src/hooks/cua-bridge/handler.ts` now support both:
  - legacy mutation path: `event.preventDefault = true`
  - modern `before_tool_call` return path: `{ block: true, blockReason, params }`

## Automated Validation Added

- `tests/plugin-runtime-compat.test.ts`
  - validates named-hook registration
  - validates fallback behavior for older runtimes
  - validates `api.on` fallback
- Added `before_tool_call` block-result tests in:
  - `tests/tool-preflight.test.ts`
  - `src/hooks/cua-bridge/handler.test.ts`
- Added runtime CI scripts:
  - `scripts/openclaw-plugin-runtime-smoke.sh` (asserts plugin loads and expected hook names are registered via `openclaw plugins info ... --json`)
  - `scripts/openclaw-plugin-blocked-call-e2e.sh` (asserts destructive `bash` command path is blocked end-to-end and target file is not created)

## Conclusion

S4/S5 are closed by combined runtime evidence and dual-path compatibility implementation.
Runtime CI now validates hook registration and blocked-command behavior on each run.
