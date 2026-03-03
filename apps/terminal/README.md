# ClawdStrike TUI

**Security-aware orchestration engine for AI coding agents**

ClawdStrike TUI dispatches coding tasks to native AI CLIs (Codex, Claude Code, OpenCode) with intelligent routing, parallel execution with voting, and quality gates — all with ambient runtime security enforcement via [hushd](../../crates/services/hushd/).

## Features

- **Intelligent Routing** - Route tasks based on risk, size, labels, and prompt patterns
- **Speculate+Vote** - Run multiple agents in parallel, select best result
- **Quality Gates** - pytest, mypy, ruff, and ClawdStrike policy checks
- **Workcell Isolation** - Git worktree sandboxes for safe concurrent execution
- **Security Integration** - Live hushd connection with SSE event streaming, audit log, and policy viewer
- **Telemetry** - Execution tracking with rollout persistence
- **Interactive TUI** - Full-screen gothic terminal dashboard with security indicators

## Interactive TUI

Running `clawdstrike` without arguments launches an interactive terminal UI:

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
| `d` | Quick dispatch |
| `s` | Quick speculate |
| `g` | Run quality gates |
| `b` | View work graph (beads) |
| `r` | View active rollouts |
| `Ctrl+S` | Security overview |
| `a` | Audit log |
| `p` | Policy viewer |
| `h` | Help |
| `q` | Quit |
| `↑/↓` or `j/k` | Navigate / scroll |
| `Enter` | Select item |

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

## CLI Usage

```bash
# Run via bun
bun run cli <command>

# Or link globally
bun link
clawdstrike <command>
```

### Commands

```bash
clawdstrike                         # Launch interactive TUI
clawdstrike dispatch <prompt>       # Submit task for AI execution
clawdstrike speculate <prompt>      # Run with multiple agents
clawdstrike gate [gates...]         # Run quality gates
clawdstrike beads list              # List issues
clawdstrike beads ready             # Get ready issues
clawdstrike beads create <title>    # Create issue
clawdstrike status                  # Show kernel status
clawdstrike init                    # Initialize in current directory
clawdstrike help                    # Show CLI help
```

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
| `CLAWDSTRIKE_HUSHD_URL` | `http://127.0.0.1:8080` | hushd daemon URL |
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
