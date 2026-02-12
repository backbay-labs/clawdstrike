# Clawdstrike SDR

A Tauri 2.0 desktop application for the **Clawdstrike** security platform.

## Overview

Clawdstrike SDR provides a visual interface for security engineers and developers to monitor, debug, and configure AI agent security policies.

## Features

### Views

| View | Description |
|------|-------------|
| **Event Stream** | Real-time daemon SSE events with filtering and receipt details |
| **Policy Viewer** | Browse active policy YAML and run policy checks |
| **Policy Tester** | Simulate policy checks against the active policy |
| **Swarm Map** | 3D visualization shell for agent topology (daemon agent/delegation APIs are not yet exposed) |
| **OpenClaw Fleet** | OpenClaw Gateway control plane for nodes, presence, approvals, and device pairing |
| **Forensics River** | Live/replay OpenClaw session telemetry with integrated Policy Workbench (editor + tester) |
| **Marketplace** | Discover and install community policies |
| **Workflows** | Workflow management UI (execution/verification remains backend-dependent) |
| **Settings** | Daemon connection and preferences |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+1-8` | Navigate to view by index |
| `Cmd+,` | Settings |
| `Cmd+K` | Command palette |
| `Cmd+[/]` | Previous/next view |
| `Esc` | Close modal/panel |

## Tech Stack

- **Frontend**: React 19 + TypeScript + Vite + Tailwind CSS 4
- **Backend**: Tauri 2.0 + Rust
- **3D**: React Three Fiber + Drei
- **State**: React Context + useSyncExternalStore pattern

## Development

### Prerequisites

- Node.js 24+
- Rust 1.93+
- Tauri CLI (`cargo install tauri-cli`)

### Setup

```bash
# Install dependencies
npm install

# Start development server (frontend only)
npm run dev

# Start with Tauri (full app)
npm run tauri:dev
```

### Build

```bash
# Build frontend
npm run build

# Build complete app
npm run tauri:build
```

### Unsigned macOS Artifacts (CI)

Manual workflow for unsigned desktop installers:

- Workflow: `.github/workflows/desktop-release.yml`
- Trigger: GitHub Actions -> **Desktop Artifacts (Unsigned)** -> Run workflow
- Outputs:
  - `.dmg`
  - `.app.tar.gz`
  - `SHA256SUMS`

CLI trigger example:

```bash
gh workflow run "Desktop Artifacts (Unsigned)" -f ref=main
```

### Type Check

```bash
npm run typecheck
```

### Tests + Lint

```bash
npm run lint
npm run typecheck
npm test -- --run

# Tauri backend (Rust) tests
CARGO_NET_OFFLINE=true cargo test --manifest-path src-tauri/Cargo.toml
```

### OpenClaw Gateway

- Operator UI: **OpenClaw Fleet**
- Tailnet discovery/probe requires Tauri + the local `openclaw` CLI
- Dev scenarios + test mapping: `docs/openclaw-gateway-testing.md`
- Gateway URL input normalizes `http(s)://...` to `ws(s)://...` on save

#### Quick start (local gateway ↔ desktop ↔ node)

```bash
# Run a local gateway (token auth recommended)
openclaw gateway run --force --token "dev-token"

# If the gateway rejects the app origin, allow Vite + Tauri origins and restart
openclaw config set --json gateway.controlUi.allowedOrigins \
  '["http://localhost:1420","tauri://localhost"]'
openclaw gateway restart

# Start the Clawdstrike SDR app (Tauri)
npm run tauri:dev
```

Optional (populate `node.list` + enable `system.run`):

```bash
openclaw node install
openclaw node restart
```

## Project Structure

```
apps/desktop/
├── src/                    # React frontend
│   ├── shell/             # App shell (layout, navigation, sessions)
│   ├── features/          # Feature views
│   │   ├── events/        # Event Stream
│   │   ├── policies/      # Policy Viewer + Tester
│   │   ├── swarm/         # 3D Swarm Map
│   │   ├── marketplace/   # Policy marketplace
│   │   ├── workflows/     # Automation
│   │   └── settings/      # Configuration
│   ├── context/           # React contexts
│   ├── services/          # API clients
│   ├── hooks/             # Custom hooks
│   ├── types/             # TypeScript types
│   └── components/        # Shared UI components
├── src-tauri/             # Rust backend
│   └── src/
│       ├── commands/      # Tauri commands
│       └── state.rs       # App state
├── package.json
├── vite.config.ts
└── tailwind.config.ts
```

## Configuration

### Daemon Connection

By default, Clawdstrike SDR connects to `http://localhost:9876`. Configure this in Settings or use the environment variable:

```bash
VITE_HUSHD_URL=http://localhost:9876
```

Policy Workbench rollout flag (enabled by default):

```bash
# disable the integrated Forensics River policy editor/tester panel
VITE_POLICY_WORKBENCH=0
```

Local dev/session override (persists in browser storage):

```js
localStorage.setItem("sdr:feature:policy-workbench", "0"); // force disable
localStorage.setItem("sdr:feature:policy-workbench", "1"); // force enable
localStorage.removeItem("sdr:feature:policy-workbench");   // fall back to env/default
```

Rollout/rollback guide: `../../docs/ops/policy-workbench-rollout.md`

## API Integration

The desktop app communicates with the hushd daemon via REST API:

- `GET /health` - Health check
- `GET /api/v1/policy` - Fetch current policy
- `POST /api/v1/policy/validate` - Validate draft policy YAML
- `PUT /api/v1/policy` - Save/activate updated policy YAML
- `POST /api/v1/check` - Check action against policy
- `POST /api/v1/eval` - Evaluate canonical `PolicyEvent`
- `GET /api/v1/audit` - Query audit log
- `GET /api/v1/events` - SSE event stream

Current daemon API does **not** expose:

- `GET /api/v1/agents`
- `GET /api/v1/delegations`

## License

MIT
