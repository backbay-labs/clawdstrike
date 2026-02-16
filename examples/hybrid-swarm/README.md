# Hybrid Swarm Example

Full integration demonstrating adapter-based tool interception, hushd attribution, SSE monitoring, and audit queries in a 3-phase pipeline.

## Architecture

```
+-----------------------------------------------------+
|                   Shared Session                     |
|                                                      |
|  Phase 1: Planner                                    |
|  +--------------+    +------------+    +--------+    |
|  | ClaudeAdapter |-->| StrikeCell |-->|        |    |
|  +--------------+    +------------+    |        |    |
|                                        | hushd  |    |
|  Phase 2: Coder                        |        |    |
|  +----------------+  +------------+    |/check  |    |
|  |VercelAIAdapter |->| StrikeCell |-->|/audit  |    |
|  |  wrapTools()   |  +------------+    |/events |    |
|  +----------------+                    |        |    |
|                                        |        |    |
|  Phase 3: Reviewer                     |        |    |
|  +------------------+ +------------+   |        |    |
|  | ToolBoundary     |>| StrikeCell |-->|        |    |
|  | wrapDispatcher() | +------------+   +--------+    |
|  +------------------+                                |
|                                                      |
|  Phase 4: Audit + Summary                            |
|  - Per-agent audit queries                           |
|  - Session-wide audit                                |
|  - Adapter session summaries                         |
|  - SSE event capture                                 |
+-----------------------------------------------------+
```

## Agents

| Phase | Agent    | Adapter                 | Actions                    |
|-------|----------|------------------------|----------------------------|
| 1     | Planner  | `ClaudeAdapter`        | read_file, list_dir, plan  |
| 2     | Coder    | `VercelAIAdapter`      | write_file, shell_exec     |
| 3     | Reviewer | `FrameworkToolBoundary` | read_file, search, write   |

## Prerequisites

```bash
cargo run -p hushd -- --ruleset strict
```

## Run

```bash
npm install
npx tsx index.ts
```

## What It Demonstrates

- **Dual enforcement**: adapter-level interception AND hushd server-side checks
- **Attribution**: every check includes `agent_id` and `session_id`
- **Session summaries**: `finalizeContext()` returns per-agent statistics
- **Audit trail**: query by agent, session, or aggregate
- **SSE monitoring**: real-time event stream with agent attribution
- **Dashboard**: open `http://localhost:3100` while running to see events live
