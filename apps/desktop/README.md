# SDR Desktop

A Tauri 2.0 desktop application for **Swarm Detection Response (SDR)** - a companion to the clawdstrike-sdr security framework.

## Overview

SDR Desktop provides a visual interface for security engineers and developers to monitor, debug, and configure AI agent security policies.

## Features

### Views

| View | Description |
|------|-------------|
| **Event Stream** | Real-time daemon SSE events with filtering and receipt details |
| **Policy Viewer** | Browse active policy YAML and run policy checks |
| **Policy Tester** | Simulate policy checks against the active policy |
| **Swarm Map** | 3D visualization shell for agent topology (daemon agent/delegation APIs are not yet exposed) |
| **OpenClaw Fleet** | OpenClaw Gateway control plane for nodes, presence, approvals, and device pairing |
| **Forensics River** | Live/replay OpenClaw session telemetry (work-in-progress) |
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

# Start the SDR Desktop app (Tauri)
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

By default, SDR Desktop connects to `http://localhost:9876`. Configure this in Settings or use the environment variable:

```bash
VITE_HUSHD_URL=http://localhost:9876
```

## API Integration

The desktop app communicates with the hushd daemon via REST API:

- `GET /health` - Health check
- `GET /api/v1/policy` - Fetch current policy
- `POST /api/v1/check` - Check action against policy
- `GET /api/v1/audit` - Query audit log
- `GET /api/v1/events` - SSE event stream

Current daemon API does **not** expose:

- `POST /api/v1/policy/validate`
- `GET /api/v1/agents`
- `GET /api/v1/delegations`

## License

MIT
