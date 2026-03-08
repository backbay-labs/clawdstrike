# Huntronomer Target Architecture

> **Status:** Draft | **Date:** 2026-03-07
> **Depends on:** `docs/specs/15-adaptive-sdr-architecture.md`

## Goal

Refactor the restored desktop app into a desktop-first Huntronomer product with four flagship
surfaces:

1. `Signal Wire`
2. `Huntboard`
3. `Receipt Vault / Replay Lens`
4. `Case Room / Profile`

The desktop app should stop behaving like a plugin container and start behaving like one coherent
keyboard-forward operating environment.

## Product-to-Code Mapping

| Product need | Current substrate | Target direction |
| --- | --- | --- |
| Global desktop shell | `src/shell/**` | Keep; simplify and re-theme |
| Signal discovery | no equivalent | Build new `src/features/wire/**` stack |
| Hunt execution / supervision | `src/features/forensics/**`, OpenClaw runtime | Recompose into `src/features/huntboard/**` |
| Proof inspection / replay | `src/features/events/**`, `src/services/tauri.ts` | Build `src/features/replay/**` and `src/features/vault/**` |
| Identity, watchlists, reputation | no equivalent | Build `src/features/profile/**`, `src/features/watchlists/**` |

## Proposed Desktop Routes

- `/wire`
- `/hunt/:huntId`
- `/hunt/:huntId/:view`
- `/vault`
- `/vault/:receiptId`
- `/cases`
- `/cases/:caseId`
- `/profile`
- `/profile/:subjectId`
- `/settings`

The root route should resolve to `/wire`, not to a plugin index.

## Layered Architecture

### 1. Shell Layer

Owns:

- workspace and session selection
- global omnibox / command strip
- keyboard routing
- docked panels, inspectors, and persistent shell chrome

Current base:

- `apps/desktop/src/shell/ShellLayout.tsx`
- `apps/desktop/src/shell/components/NavRail.tsx`
- `apps/desktop/src/shell/components/CommandPalette.tsx`
- `apps/desktop/src/shell/sessions/**`

### 2. Huntronomer Domain Layer

Create a dedicated domain package inside the app:

- `apps/desktop/src/domain/huntronomer/models.ts`
- `apps/desktop/src/domain/huntronomer/envelopes.ts`
- `apps/desktop/src/domain/huntronomer/actions.ts`
- `apps/desktop/src/domain/huntronomer/selectors.ts`
- `apps/desktop/src/domain/huntronomer/mock-data.ts`

This layer should normalize the core objects defined in Spec 16:

- `Signal`
- `Hunt`
- `SwarmRun`
- `Receipt`
- `Brief`
- `Rule`
- `Case`
- `ProfileRecord`

### 3. Surface Controller Layer

Create surface-focused feature folders:

- `apps/desktop/src/features/wire/**`
- `apps/desktop/src/features/huntboard/**`
- `apps/desktop/src/features/vault/**`
- `apps/desktop/src/features/replay/**`
- `apps/desktop/src/features/cases/**`
- `apps/desktop/src/features/profile/**`

Each surface should consume the normalized domain objects rather than binding directly to daemon or
gateway transport formats.

### 4. Integration Layer

Keep and expand these adapters:

- `apps/desktop/src/services/tauri.ts`
- `apps/desktop/src/services/eventStream.ts`
- `apps/desktop/src/services/openclaw/gatewayClient.ts`
- `apps/desktop/src/context/OpenClawContext.tsx`

These become transport adapters that project runtime data into the Huntronomer domain model.

## Surface Responsibilities

### Signal Wire

Responsibilities:

- typed, dense feed of signals, hunts, receipts, briefs
- watchlist-aware filtering
- keyboard selection model
- right-side context pane
- one-step `Fork Hunt` and `Assign Swarm`

Notable new modules:

- `features/wire/WireView.tsx`
- `features/wire/WireFeed.tsx`
- `features/wire/WireContextPane.tsx`
- `features/wire/WireWatchlistsPane.tsx`
- `features/wire/WirePulseBar.tsx`

### Huntboard

Responsibilities:

- preserve source signal context
- supervise swarm runs
- expose `Atlas`, `Flow`, `Timeline`, and `Replay` subviews
- show approvals, denials, policies, and evidence without losing lineage

Reuse path:

- fold current `ForensicsRiverView` and related overlays into the Huntboard center canvas
- attach OpenClaw runtime summaries and approval queues as operator sidecars

### Receipt Vault / Replay Lens

Responsibilities:

- signed receipt inspection
- compare and replay entry points
- proof lineage, signer, policy version, and evidence pointers
- explicit degraded or stale states

Reuse path:

- evolve `EventStreamView` and `ReceiptPanel` into a proof-oriented browsing surface

### Case Room / Profile

Responsibilities:

- durable promoted hunt records
- authored briefs and citations
- lightweight reputation and validation history
- followable people, teams, techniques, and hunts

This is mostly new UI and model work in v1.

## Interaction Contract

The defining transition is:

`Wire selection -> Fork Hunt / Assign Swarm -> Huntboard opens with preserved context`

Preserved context must include:

- source object ID and type
- selected entities and tags
- confidence and severity
- linked receipts
- visibility scope
- initial swarm profile and posture choice

## State Strategy

The app does not currently carry a dedicated query/store framework. Keep the first Huntronomer pass
lightweight:

- use React context for shared app state that truly spans surfaces
- keep normalized domain selectors in pure TypeScript modules
- isolate transport adapters behind service hooks
- only introduce a heavier state layer if the first wire + huntboard pass proves React context to
  be insufficient

## Design System Direction

Adopt one system across shell and surfaces:

- obsidian / graphite foundations
- muted gold structural lines
- restrained crimson for threat and denial accents
- cool steel neutrals for telemetry
- denser rows, fewer oversized cards
- premium operator typography and calmer animation

The design should feel like a threat observatory, not a cyberpunk demo reel and not a soft SaaS
dashboard.

## Non-Negotiable Invariants

1. The home screen is the Signal Wire.
2. Every execution-backed claim links back to receipts, posture, and replay.
3. The Huntboard is an execution transition, not a disconnected separate tool.
4. Visibility is explicit on every major object.
5. The product is keyboard-first across navigation, selection, and action dispatch.
