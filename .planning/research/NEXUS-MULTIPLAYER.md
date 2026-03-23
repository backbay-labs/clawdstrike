# Feature Research: Nexus Force Graph + Observatory Multiplayer

**Project:** ClawdStrike Workbench — Huntronomer Integration
**Researched:** 2026-03-19
**Mode:** Feature (Feasibility + Ecosystem)
**Overall confidence:** MEDIUM-HIGH

---

## Feature 1: Nexus as Force-Directed Graph

### Current State

`NexusTab` renders `ObservatoryWorldCanvas` in `atlas` mode with 9 `Strikecell` nodes
arranged at fixed polar-coordinate positions (`HUNT_STATION_PLACEMENTS`, angles baked into
`stations.ts`). The `NexusLayoutMode` type already includes `"force-directed"` as a union
member in `types.ts` — it was anticipated. No physics simulation runs today; positions are
computed in `stationWorldPosition()` via pure trig.

The existing `ObservatoryWorldCanvas` is **not** the right host for force layout. It owns its
own camera rig, station sphere rendering, and orbital controls — all built around the fixed
6-station ring geometry of the observatory. A force graph is a different rendering primitive.

---

### Approach Comparison

#### Option A: Rapier (@react-three/rapier 2.2 — already installed)

**How it would work:** Bodies at node positions, spring constraints (`ImpulseSpring`) between
connected nodes, repulsive impulses applied each frame via `useBeforePhysicsStep`. Drag via
pointer raycasting + kinematic body takeover.

**Verdict: Do not use for this.**

Rapier is a rigid-body collision engine designed for character physics, vehicles, and
destructibles. Its spring joints (`ImpulseSpring`) have stiffness/damping tunable for
mechanical contact, not graph aesthetics. The per-frame "apply repulsion to every pair"
pattern requires O(n^2) impulse calls that Rapier was not designed to batch efficiently at the
level d3-force handles internally. The WASM startup cost is amortized in the workbench only
because Rapier is lazy-loaded exclusively for the observatory flow-mode Easter egg — adding
graph force simulation would either bloat that bundle boundary or require a second Rapier world
(a documented footgun). The `PROJECT.md` "Out of Scope" section explicitly says "Full Rapier
physics in workbench." The spirit is clear.

**Confidence:** HIGH — code inspection + documented out-of-scope decision.

---

#### Option B: d3-force-3d via r3f-forcegraph (RECOMMENDED)

`vasturiano/r3f-forcegraph` is React Three Fiber bindings around `three-forcegraph`, which
itself wraps `d3-force-3d`. The physics runs entirely on the JS thread as a velocity-Verlet
integrator; no WASM. The component exposes a `<R3fForceGraph>` that lives inside an R3F
`<Canvas>` and calls its own `tickFrame()` in the render loop.

**Performance at 9–50 nodes:** d3-force-3d is explicitly designed for this scale. The library
ships demos with hundreds of nodes at 60 fps. At 9 strikecells the simulation reaches alpha
convergence (stable layout) in ~1–2 seconds, after which the engine stops ticking and the
scene goes idle. `frameloop="demand"` on the Canvas is compatible with this because the
library provides `tickFrame()` for manual stepping — you call it inside `useFrame` and only
invalidate the canvas while `alpha > alphaMin`.

**Peer dep concern:** `r3f-forcegraph` wraps `three-forcegraph` which depends on `three` and
a specific `@react-three/fiber` version. The workbench runs R3F 9 + three 0.170. The
vasturiano ecosystem generally tracks r3f major versions closely; verify the exact peer dep
before installing. If the peer dep is stale, use `three-forcegraph` directly (imperative API,
`useEffect` mount/unmount into a `<group ref>`) — this avoids the peer dep constraint entirely
at cost of ~40 lines of boilerplate.

**Integration with ObservatoryWorldCanvas:** The force graph should NOT be rendered inside the
existing `ObservatoryWorldCanvas`. That component's `WorldCameraRig` and station-sphere
rendering are observatory-specific. The correct approach is a new `NexusForceCanvas`
component: a standalone `<Canvas>` with its own camera and OrbitControls, rendered by
`NexusTab` when `layoutMode === "force-directed"`. `NexusTab` already owns the
`layoutMode` toggle concept (the `NexusLayoutMode` union is there). The `NexusForceCanvas`
reads from `nexus-store` (strikecells + connections) and translates them to `graphData` for
the force engine. Clicks on nodes call `onSelectStrikecell` which routes via
`STRIKECELL_ROUTE_MAP` exactly as today.

**Draggable nodes:** `r3f-forcegraph` (and `three-forcegraph`) expose `onNodeDrag`,
`onNodeDragEnd`, and `nodePositionUpdate` callbacks. When a node is dragged, its position is
pinned (fx/fy/fz set), the simulation is reheated (`d3ReheatSimulation()`), and on drag-end
the pin is released. This is the standard d3-force drag pattern.

**Confidence:** HIGH — library is production-grade, R3F bindings exist, pattern is well-documented.

---

#### Option C: Custom spring physics in useFrame

**How it would work:** Store node positions in a `useRef`-held Float32Array, apply Hooke's
law (attract neighbors) + Coulomb repulsion (all pairs) each frame, update Three.js mesh
positions directly.

**Verdict: Viable but unnecessary.** At 50 nodes, naive O(n^2) repulsion runs ~2500
operations per frame — trivial for JS. The implementation is ~150 lines. The advantage is
zero new dependencies and full control over visual behavior. The disadvantage is you re-implement
what d3-force-3d already does correctly (Barnes-Hut approximation for large n, alpha cooling,
collision detection if needed). For a 9-node strikecell graph this is not unreasonable, but the
maintenance burden is real. Use this only if `r3f-forcegraph` peer dep conflicts prove
unresolvable.

**Confidence:** MEDIUM — feasible, not recommended as first choice.

---

### Recommended Implementation Plan

1. Add `r3f-forcegraph` (or `three-forcegraph` if peer dep conflicts). Verify against R3F 9 +
   three 0.170 before committing.
2. Add `connections: StrikecellConnection[]` to `nexus-store` (the type already exists in
   `types.ts`; the store just uses `strikecells[]` today).
3. Create `NexusForceCanvas.tsx` — a new `<Canvas>` with `OrbitControls`, renders
   `<R3fForceGraph graphData={...}>` wired to strikecells + connections.
4. Add a `layoutMode` field to `nexus-store` (default `"atlas"`, user can toggle to
   `"force-directed"`).
5. `NexusTab` conditionally renders `<NexusForceCanvas>` or `<ObservatoryWorldCanvas mode="atlas">`
   based on `layoutMode`.
6. Wire `onNodeClick` in `NexusForceCanvas` to the same `openApp` logic as `handleSelectStation`.

**New dependencies:**
- `r3f-forcegraph` (~80KB gzipped) — or `three-forcegraph` + `d3-force-3d`
- No WASM, no Rapier impact

**Complexity estimate:** MEDIUM. ~3–4 days of work. The hard part is the `NexusForceCanvas`
component and connecting node click → route bridge. The store changes are trivial.

**Blocking questions:**
- Does `r3f-forcegraph` peer dep accept R3F 9? Check `node_modules` resolution before
  starting. If not, use `three-forcegraph` directly.
- What connection data populates `StrikecellConnection[]` in production? Today all strikecells
  are offline with no connections. Demo data needs to be authored for the force layout to be
  non-trivial.
- Should `NexusForceCanvas` share the same `<Canvas>` as `ObservatoryWorldCanvas`? Answer: no.
  They are different scenes with different camera contracts. Separate canvases.

---

## Feature 2: Observatory Multiplayer via Tauri + NATS

### Transport Audit: What Spine Provides

The `spine` crate (`crates/libs/spine/src/nats_transport.rs`) provides:

- `connect(servers)` / `connect_with_auth(servers, auth)` — async NATS client via `async_nats`
- `jetstream(client)` — JetStream context
- `ensure_kv(js, bucket, replicas)` — KV bucket provisioning
- `ensure_stream(js, name, subjects, replicas)` — stream provisioning

This is a **server-side Rust API**. It is used by `hushd`, `clawdstrike-brokerd`, and the
spine-cli. There is no NATS client in the Tauri workbench backend (`src-tauri/Cargo.toml` does
not include `async-nats` or `spine` as dependencies). The Tauri backend today is:
`hush-core`, `clawdstrike`, `hunt-correlate`, `hunt-query`, `clawdstrike-ocsf` — security
evaluation libs only, no transport.

**Conclusion:** Spine gives us a proven NATS integration pattern in Rust, but the workbench
would need net-new Tauri command infrastructure to use it. Nothing is pre-wired.

**Confidence:** HIGH — read the Cargo.toml directly.

---

### Transport Options for Multiplayer

#### Option A: nats.js WebSocket from the renderer (RECOMMENDED for prototyping)

`@nats-io/nats-core` v3.3.1 (released 2026-02-11) ships WebSocket transport as part of the
core package. The webview window can open a WebSocket connection directly to a NATS server
configured with `websocket { port: 4222 no_tls: true }` (dev) or WSS (prod). This requires
**zero Rust changes** — the renderer connects and subscribes directly.

```typescript
import { wsconnect } from "@nats-io/nats-core";
const nc = await wsconnect({ servers: "ws://localhost:4222" });
const sub = nc.subscribe("observatory.presence.>");
```

The Tauri HTTP plugin is already installed (`tauri-plugin-http`), but WebSocket in Tauri's
webview uses the system WebSocket API directly — no special plugin needed. The
`tauri-plugin-websocket` plugin exists but is not required when the app uses a standard
browser WebSocket API (which nats.js uses internally).

**Server-side requirement:** NATS server must be running locally (or reachable) with WebSocket
enabled. This is an **external dependency** — the workbench does not embed a NATS server.
Operators must have `nats-server` running (or `hushd` running and exposing NATS). This is
realistic in a security operations context where hushd + spine are already deployed, but it is
a hard runtime requirement.

**Confidence:** HIGH — nats.js WebSocket works in browsers; Tauri webview has standard W3C
WebSocket. The server-side requirement is the real constraint.

---

#### Option B: Tauri Rust backend bridges NATS to renderer via emit

Add `async-nats` (or `spine`) to `src-tauri/Cargo.toml`. On connect, spawn a Tokio task that
subscribes to `observatory.>` subjects and calls `app_handle.emit("observatory-event", payload)`
to forward to the renderer. The renderer listens via `@tauri-apps/api/event`.

**Pros:** Renderer never touches NATS directly; all auth/connection management stays in Rust;
can use spine's `connect_with_auth` for NKey/creds auth that the webview can't hold securely.

**Cons:** Tauri's own docs note "events are not designed for low latency or high throughput."
For 3D real-time (position updates at 20–60 Hz), this path adds IPC serialization overhead
(JSON stringify/parse across the Tauri bridge) on top of NATS. For presence heartbeats
(~1 Hz) this is fine; for continuous probe position streaming at 30 Hz it may lag.

**Confidence:** MEDIUM — pattern works, latency at high-frequency 3D update rates is untested.

---

#### Option C: Custom WebSocket server in Tauri backend (no NATS)

Spawn a local `tokio::net` WebSocket server in the Tauri backend using `tokio-tungstenite`.
Renderer connects via the browser WebSocket API. State is shared between connected workbench
instances via this local hub.

**Verdict: Do not use.** This reinvents NATS publish/subscribe for a single-machine hub,
doesn't survive firewall/network operator scenarios, and has no pub/sub subjects model. The
spine ecosystem already made the NATS bet; stay consistent.

---

### State That Needs Syncing

For a useful multiplayer observatory, the minimum sync surface is:

| State | Update Rate | Sync Priority | Notes |
|-------|-------------|---------------|-------|
| Operator presence (operator ID, display name, spirit kind + accent) | Connect/disconnect + heartbeat ~1 Hz | HIGH | Who is in the room |
| Active station selection per operator | On selection change | HIGH | Show other operators' focus point |
| Probe fire events | On trigger | HIGH | Ring effect visible to all |
| Probe cursor position (float x/y on station) | 20 Hz | LOW | Fancy; high bandwidth |
| Spirit companion orbit position | 30 Hz | LOW | Very expensive; see rendering below |
| Hunt mode / atlas-vs-flow toggle | On toggle | MEDIUM | Room-level state |

The core multiplayer loop is: **presence + station selection + probe events**. That is
~3 messages/sec per operator at steady state — very manageable for NATS.

**Recommended NATS subject schema:**
```
observatory.room.<huntId>.presence.<operatorId>    -- heartbeat, JetStream KV
observatory.room.<huntId>.station.<operatorId>     -- active station, pub/sub
observatory.room.<huntId>.probe                    -- probe fired (no operatorId fan-out)
```

---

### Rendering Other Operators in the Scene

**Operator cursors on stations:** The simplest and highest-value approach. When operator B
has station "targets" active, render a small colored ring or floating label above that station
sphere in the scene. This requires only `operatorId → activeStationId` state, which is low
frequency. Implement as a new `RemoteOperatorOverlay` component inside `ObservatoryScene`.

**Spirit companions:** Each operator has a spirit kind + accent color. Rendering remote
spirit orbs is feasible (they are procedural geometry, no GLTF assets needed). Position them
in orbit around the center node with per-operator offsets. The risk is visual noise with 3+
operators. **Defer until presence + station cursors are validated.**

**Character controller (flow mode) positions:** Real-time 3D character positions require
continuous streaming at 20–30 Hz. With NATS this is achievable at the network level
(sub-10ms pub/sub on LAN), but the rendering side needs interpolation (dead-reckoning or
lerp) to stay smooth. This is significant scope. **Out of scope for initial multiplayer.**

**Latency requirement:** For station selection and probe events, <500ms is fine (these are
click-rate interactions). For character positions, <100ms is the practical threshold for
smooth motion. The WebSocket path to a local NATS server will be 2–10ms round-trip on LAN,
well inside both thresholds. Over WAN (distributed team), expect 50–200ms — acceptable for
presence, choppy for continuous 3D positions.

**Confidence:** MEDIUM — the latency numbers are from general WebSocket + NATS documentation,
not benchmarks on this specific stack.

---

### Tauri NATS Connection: Does it exist?

**Today:** No. The Tauri `src-tauri/Cargo.toml` has no `async-nats`, no `spine` dependency.
The workbench backend knows nothing about NATS. The observatory-store has a `connected: boolean`
field with a `setConnected` action — this was clearly designed with a future connection in mind,
but nothing drives it.

**What needs building for Option A (renderer-side nats.js):**
1. Add `@nats-io/nats-core` to `package.json`.
2. Create a `nats-client.ts` service (singleton, connects on first use, gracefully handles no
   server).
3. Create `useObservatoryPresence` hook: subscribes to `observatory.room.*.presence.*`,
   populates a `remoteOperators` slice in `observatory-store` (new state field).
4. Publish own presence on mount, unsubscribe on unmount.
5. `RemoteOperatorOverlay` component renders colored station rings in `ObservatoryScene`.

**What needs building for Option B (Tauri-bridged):**
1. Add `async-nats` to `src-tauri/Cargo.toml`.
2. Add `NatsState` (Arc<Mutex<Option<async_nats::Client>>>) to Tauri managed state.
3. Add `nats_connect`, `nats_publish`, `nats_subscribe` Tauri commands.
4. Add listener task: spawned in `setup()`, emits `"observatory-event"` to frontend.
5. Frontend subscribes to Tauri events, populates `observatory-store`.

---

### Complexity Estimates

| Feature | Estimate | Notes |
|---------|----------|-------|
| Force graph (r3f-forcegraph) | MEDIUM — 3–4 days | New canvas component + store additions |
| Force graph (custom spring) | MEDIUM — 4–5 days | More code, no dep risk |
| Multiplayer presence only (Option A, renderer NATS) | HIGH — 1–2 weeks | NATS server requirement, new store slice, overlay rendering |
| Multiplayer presence + probes (Option A) | HIGH — 2–3 weeks | Adds probe fan-out, probe ring for remote operators |
| Multiplayer with Tauri bridge (Option B) | HIGH — 3–4 weeks | Rust NATS integration, command plumbing, IPC latency tuning |
| Full multiplayer with character positions | VERY HIGH — 5+ weeks | Dead-reckoning, high-freq streaming, significant scope |

---

### Blocking Questions for Multiplayer

1. **Is a NATS server available in the deployment context?** Multiplayer only works if operators
   share access to a NATS server. Is `hushd`/spine deployed in the environments where
   workbench will be used? If not, this feature has no runtime transport.

2. **What is the operator identity model?** Remote presence requires stable operator IDs.
   The workbench has Stronghold (key storage) and `sign_receipt_persistent` — an Ed25519 keypair
   per workbench instance exists. Using the persistent public key as operator ID would be
   natural and already aligns with the spine identity model.

3. **Is multiplayer a single-machine (split-screen) or network feature?** "Multiple operators
   see each other" implies network. But if this is demo/dev-only, a mock `remoteOperators`
   slice in the store (hardcoded fake operators) lets you build the rendering layer before
   touching NATS.

4. **Which renderer wins for spirit companion multiplayer: orb or VRM?** `PROJECT.md` says
   "VRM avatar rendering — too heavy for IDE." Spirit orbs (procedural sphere + ring) are the
   right abstraction and consistent with the existing `CoreNode` pattern.

5. **Should remote probe effects be signed?** The spine envelope model could sign probe events
   as receipts. This is philosophically consistent with the ClawdStrike identity model but adds
   significant complexity. Recommend unsigned for initial multiplayer; receipts are for
   enforcement, not presence.

---

## Prioritization Recommendation

**Build in this order:**

1. Force graph (Option B — `r3f-forcegraph`): Self-contained, no server dependency, high
   visual impact, the `NexusLayoutMode` type already anticipated it. Ship as a layout mode
   toggle in `NexusTab`. **No blocking questions — start immediately.**

2. Multiplayer presence rendering layer with mock data: Build `remoteOperators` slice in
   `observatory-store`, `RemoteOperatorOverlay` in `ObservatoryScene`, and the presence UI
   (station cursor rings, floating operator labels). Use hardcoded fake operators in dev.
   This lets the rendering work be validated before any NATS wiring. **Start after question 1
   (NATS server availability) is answered.**

3. Wire Option A (renderer-side `@nats-io/nats-core`) only after confirming a NATS server is
   available in the target environment. The mock-data layer means the rendering already works;
   the NATS wiring is a drop-in `nats-client.ts` substitution.

4. **Do not build** character-position multiplayer, signed probe receipts, or Tauri-bridged
   NATS unless presence + station cursors are validated and users demand more.

---

## Sources

- [r3f-forcegraph — vasturiano](https://github.com/vasturiano/r3f-forcegraph) — MEDIUM confidence (GitHub README, no official versioned docs)
- [d3-force-3d — vasturiano](https://github.com/vasturiano/d3-force-3d) — HIGH confidence (official library)
- [three-forcegraph — vasturiano](https://github.com/vasturiano/three-forcegraph) — MEDIUM confidence
- [nats.js — nats-io](https://github.com/nats-io/nats.js) — HIGH confidence (official NATS org, v3.3.1 as of 2026-02-11)
- [NATS WebSocket docs](https://docs.nats.io/running-a-nats-service/configuration/websocket) — HIGH confidence (official NATS docs)
- [Tauri: Calling the Frontend from Rust](https://v2.tauri.app/develop/calling-frontend/) — HIGH confidence (official Tauri v2 docs)
- [react-three/rapier](https://github.com/pmndrs/react-three-rapier) — HIGH confidence (official pmndrs repo)
- Codebase inspection: `NexusTab.tsx`, `types.ts`, `nexus-store.ts`, `ObservatoryWorldCanvas.tsx`, `observatory-store.ts`, `src-tauri/Cargo.toml`, `spine/src/nats_transport.rs` — HIGH confidence (direct read)
