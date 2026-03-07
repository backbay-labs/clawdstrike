# ClawdStrike TUI

**Local-first security operations cockpit for AI agent workflows**

ClawdStrike TUI is a beta operator cockpit for local security review of AI agent activity. It combines local runtime health, hushd security state, supported hunt workflows, and evidence handoff into one terminal interface, with optional task dispatch still available through the same CLI.

## Features

- **Operator Dashboard** - Local health, hushd status, stream freshness, active investigation state
- **Security Surfaces** - Integrations, security overview, audit log, and policy viewer
- **Supported Hunt Loop** - watch, scan, timeline, query, report, and report history
- **Evidence Handoff** - Export markdown + JSON bundles with receipt/audit trace metadata
- **Workcell Isolation** - Git worktree sandboxes for safe concurrent execution
- **Optional Agent Actions** - dispatch, speculate, gates, beads, and rollout status

## Interactive TUI

Run the TUI through the main CLI with `clawdstrike tui`, or use the package-local binary as `clawdstrike-tui`:

```
 ██████╗██╗      █████╗ ██╗    ██╗██████╗
██╔════╝██║     ██╔══██╗██║    ██║██╔══██╗
██║     ██║     ███████║██║ █╗ ██║██║  ██║
██║     ██║     ██╔══██║██║███╗██║██║  ██║
╚██████╗███████╗██║  ██║╚███╔███╔╝██████╔╝
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═════╝
                  ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
                  ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
                  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
                  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
                  ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
                  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
```

**Keyboard Shortcuts:**

| Key | Action |
|-----|--------|
| `Enter` | Dispatch the current prompt |
| `Tab` | Cycle home focus between prompt and actions |
| `Esc` | Toggle prompt and nav focus |
| `Ctrl+N` | Cycle agents |
| `Ctrl+P` | Open command palette |
| `Ctrl+S` | Security overview |
| `S/A/P/I` | Security / audit / policy / integrations in nav focus |
| `W/X/T/Q/E/H` | Watch / scan / timeline / query / report / history in nav focus |
| `g` | Run quality gates |
| `b` | View work graph (beads) |
| `r` | View active rollouts |
| `?` | Help |
| `q` | Quit |
| `↑/↓` or `j/k` | Navigate / scroll |
| `↑↓←→` | Move across home actions after `Tab` |

## Security Integration

ClawdStrike TUI connects to a running [hushd](../../crates/services/hushd/) daemon for ambient security enforcement:

- **Status bar indicator** — `◆sec` turns green when hushd is connected, dim when unavailable
- **Live event ticker** — Latest security decisions stream on the main screen via SSE
- **Security overview** (`Ctrl+S`) — Real-time event table and audit statistics
- **Audit log** (`a`) — Paginated table of all policy decisions with filtering
- **Policy viewer** (`p`) — Active policy name, version, hash, and guard list
- **Pre-dispatch check** — Optionally validates prompts against hushd policy before sending to agents (fail-open)
- **ClawdStrike quality gate** — Posts agent diffs to hushd for patch integrity and secret leak scanning

All security features degrade gracefully when hushd is not running.

## Installation

```bash
cd apps/terminal
bun install
```

The beta TUI runtime currently requires `bun` on the machine running `clawdstrike tui`.

### Wrapper And Doctor Notes

- `clawdstrike tui doctor --json` reports the active runtime under `runtime.source`, `runtime.script_path`, and `runtime.bun_version`.
- The Rust wrapper resolves the TUI runtime in this order:
  1. `CLAWDSTRIKE_TUI_DIR`
  2. installed bundle beside the CLI binary at `../share/clawdstrike/tui/cli.js`
  3. repo source fallback at `apps/terminal/src/cli/index.ts`
- If `bun` on `PATH` is a crashing shim layer, `doctor` will still show the selected runtime, but launch can fail before the TUI starts. In that case, put the real Bun binary earlier on `PATH` than the shim.
- A concrete failure we hit during dogfooding was a `~/.proto/shims/bun` wrapper panic on macOS. Pointing `PATH` at the real Bun binary fixed the issue without changing any TUI code.

## Codex Agent Pack

The terminal subtree includes a Codex agent pack for live dogfooding, UI polish,
release hardening, and multi-agent debugging.

- Usage guide: [docs/codex-agent-pack.md](./docs/codex-agent-pack.md)
- Repo-wide swarm playbook: [../../docs/plans/multi-agent/codex-swarm-playbook.md](../../docs/plans/multi-agent/codex-swarm-playbook.md)
- Project config: [.codex/config.toml](../../.codex/config.toml)
- Terminal working agreement: [AGENTS.md](./AGENTS.md)

## Dispatch UX Planning Docs

These docs describe planned dispatch work, not current shipped behavior.

Recommended reading order:

1. Product spec: [docs/dispatch-ux-spec.md](./docs/dispatch-ux-spec.md)
2. Implementation plan: [docs/dispatch-ux-plan.md](./docs/dispatch-ux-plan.md)
3. Phase 1 engineering breakdown: [docs/dispatch-phase1-engineering.md](./docs/dispatch-phase1-engineering.md)
4. Later-phase overview: [docs/dispatch-phases2-5-overview.md](./docs/dispatch-phases2-5-overview.md)
5. Phase 2 engineering breakdown: [docs/dispatch-phase2-engineering.md](./docs/dispatch-phase2-engineering.md)
6. Phase 3 engineering breakdown: [docs/dispatch-phase3-engineering.md](./docs/dispatch-phase3-engineering.md)
7. Phase 4 engineering breakdown: [docs/dispatch-phase4-engineering.md](./docs/dispatch-phase4-engineering.md)
8. Phase 5 engineering breakdown: [docs/dispatch-phase5-engineering.md](./docs/dispatch-phase5-engineering.md)
9. Embedded PTY follow-on spec: [docs/embedded-pty-surface-spec.md](./docs/embedded-pty-surface-spec.md)
10. Embedded PTY follow-on plan: [docs/embedded-pty-surface-plan.md](./docs/embedded-pty-surface-plan.md)
11. Embedded PTY Phase 6 engineering breakdown: [docs/embedded-pty-phase6-engineering.md](./docs/embedded-pty-phase6-engineering.md)

## CLI Usage

```bash
# Run via the main Rust CLI
clawdstrike tui <command>

# In a repo checkout, this exercises the current branch even if a globally
# installed clawdstrike binary is older:
cargo run -q -p hush-cli --bin clawdstrike -- tui --cwd apps/terminal

# Or run the package-local TUI binary
bun run cli <command>
bun link
clawdstrike-tui <command>
```

### Commands

```bash
clawdstrike tui                     # Launch interactive TUI
clawdstrike tui dispatch <prompt>   # Submit task for AI execution
clawdstrike tui speculate <prompt>  # Run with multiple agents
clawdstrike tui gate [gates...]     # Run quality gates
clawdstrike tui beads list          # List issues
clawdstrike tui beads ready         # Get ready issues
clawdstrike tui beads create <title> # Create issue
clawdstrike tui status              # Show kernel status
clawdstrike tui init                # Initialize in current directory
clawdstrike tui doctor              # Inspect local environment and services
clawdstrike tui help                # Show CLI help
```

### Supported vs Experimental

Supported beta screens:
- main dashboard
- integrations
- security
- audit
- policy
- result
- hunt watch
- hunt scan
- hunt timeline
- hunt query
- hunt report
- hunt report history

Experimental screens:
- hunt rule builder
- hunt diff
- hunt mitre
- hunt playbook

### Options

```bash
-t, --toolchain <name>   # Force toolchain (codex, claude, opencode, crush)
-s, --strategy <name>    # Vote strategy (first_pass, best_score, consensus)
-g, --gate <name>        # Gates to run (can repeat)
--timeout <ms>           # Execution timeout
-j, --json               # JSON output
--no-color               # Disable colors
--cwd <path>             # Working directory
-p, --project <id>       # Project identifier
```

### Examples

```bash
# Simple dispatch
clawdstrike dispatch "Fix the null pointer in auth.ts"

# Operator bootstrap
clawdstrike tui init
clawdstrike tui doctor --json
clawdstrike tui

# Force Claude toolchain
clawdstrike dispatch -t claude "Add unit tests for utils.ts"

# Speculate with best score voting
clawdstrike speculate -s best_score "Refactor the database module"

# Run specific gates (including security)
clawdstrike gate pytest mypy clawdstrike

# List open issues as JSON
clawdstrike beads list -j
```

## Programmatic Usage

The package API remains unstable during beta. The supported public interface is `clawdstrike tui` through the main Rust CLI.

```typescript
import {
  init,
  shutdown,
  Router,
  Dispatcher,
  Workcell,
  Verifier,
  Speculate,
  Beads,
  Telemetry,
  Hushd,
  tools,
  executeTool,
} from "@clawdstrike/tui"

// Initialize (also starts hushd client)
await init({
  beadsPath: ".beads",
  telemetryDir: ".clawdstrike/runs",
})

// Route a task
const routing = await Router.route({
  prompt: "Fix the bug in auth.ts",
  context: { cwd: process.cwd(), projectId: "my-project" },
})

// Execute via tool
const result = await executeTool("dispatch", {
  prompt: "Fix the bug",
  toolchain: "claude",
})

// Check hushd connectivity
const client = Hushd.getClient()
const connected = await client.probe()

// Cleanup
await shutdown()
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  CLI / Tools                                                │
│  dispatch, speculate, gate commands                         │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  Router                                                     │
│  Rule-based routing with priority, labels, patterns         │
└────────────────────────────┬────────────────────────────────┘
                             │
         ┌───────────────────┤
         │ (optional)        │
┌────────▼────────┐  ┌──────▼──────────────────────────────┐
│  hushd Policy   │  │  Dispatcher                         │
│  Pre-check      │  │  Adapters: codex | claude |         │
│  (fail-open)    │  │  opencode | crush                   │
└─────────────────┘  └──────┬──────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  Workcell Pool                                              │
│  Git worktree isolation with lifecycle management           │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  Verifier                                                   │
│  Gates: pytest, mypy, ruff, clawdstrike                     │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  hushd (optional)                                           │
│  Patch integrity + secret leak scanning via HTTP API        │
└─────────────────────────────────────────────────────────────┘
```

## Toolchains

| Toolchain | CLI | Best For |
|-----------|-----|----------|
| `codex` | OpenAI Codex CLI | Complex reasoning, architecture |
| `claude` | Claude Code | General purpose, fast |
| `opencode` | OpenCode | Local execution, no network |
| `crush` | Multi-provider | Fallback with retries |

## Vote Strategies

When using `speculate`, multiple agents run in parallel and results are voted on:

| Strategy | Description |
|----------|-------------|
| `first_pass` | First result passing all gates wins (fastest) |
| `best_score` | Highest gate score wins (best quality) |
| `consensus` | Most similar patch wins (most deterministic) |

## Quality Gates

| Gate | Critical | Description |
|------|----------|-------------|
| `pytest` | Yes | Run Python tests |
| `mypy` | Yes | Type check Python |
| `ruff` | No | Lint and format Python |
| `clawdstrike` | No | Policy check via hushd (patch integrity, secret leak) |

## Module Structure

```
src/
├── cli/           # Command-line interface
├── router/        # Task routing rules
├── dispatcher/    # Toolchain adapters
│   └── adapters/  # codex, claude, opencode, crush
├── workcell/      # Git worktree management
├── verifier/      # Quality gates
│   └── gates/     # pytest, mypy, ruff, clawdstrike
├── speculate/     # Parallel execution + voting
├── beads/         # Work graph (JSONL)
├── hushd/         # Security daemon client
│   ├── types.ts   # hushd API types
│   ├── client.ts  # HTTP + SSE client
│   └── index.ts   # Namespace entry point
├── telemetry/     # Execution tracking
├── health/        # Integration health checks
├── tui/           # Terminal UI and formatting
│   ├── index.ts   # TUI formatting utilities
│   └── app.ts     # Interactive TUI application
├── mcp/           # MCP server (JSON-RPC)
├── tools/         # MCP tool definitions
├── patch/         # Patch lifecycle
├── types.ts       # Zod schemas
└── index.ts       # Main exports
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAWDSTRIKE_HUSHD_URL` | `http://127.0.0.1:9876` | hushd daemon URL |
| `CLAWDSTRIKE_SANDBOX` | - | Sandbox mode for codex adapter |
| `NO_COLOR` | - | Disable color output |

## Development

```bash
# Run tests
bun test

# Type check
bun run typecheck

# Run CLI in dev mode
bun run cli help

# Launch TUI
bun run cli
```

## Testing

335 tests covering:
- Type validation and Zod schemas
- Router rules and routing decisions
- Dispatcher adapters (codex, claude, opencode, crush)
- Workcell pool management and git operations
- Verifier gates and scoring (including clawdstrike gate)
- Speculate voting strategies
- Beads JSONL operations
- Telemetry tracking
- hushd client (mocked fetch)
- Health check integrations
- TUI formatting
- MCP server protocol
- CLI argument parsing and integration

```bash
bun test                 # All tests
bun test test/router     # Router tests only
bun test -t "hushd"      # hushd client tests
bun test -t "speculate"  # Tests matching pattern
```

## License

MIT
