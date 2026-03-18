# Hunt Observatory Character Controller Plan

> **Status:** Proposed
> **Date:** 2026-03-09
> **Audience:** Desktop, hunt-observatory, runtime, and dogfood implementers
> **Scope:** Add a controllable user character with real physics, jump, and flip behavior to the
> Hunt Observatory world

## Purpose

This plan hardens the next observatory initiative: a user-controlled avatar that can move through
the shared hunt world, jump, and perform authored flips without breaking the room model.

The goal is not to turn Huntronomer into an open-world game.
The goal is to make the observatory feel inhabited and navigable while preserving its operator
meaning.

## Product Rules

- The observatory remains one stable hunt world.
- The character is an **operator avatar**, not a hero NPC.
- Movement should feel responsive and physical, but not arcade-chaotic.
- Jumps and flips should be authored and readable, not ragdoll slapstick.
- Station travel, probe reads, and world interactions must still work with mouse and rails.
- The first ship target is a high-quality third-person prototype in the observatory, not a
  generalized avatar system across the whole shell.

## Recommended Technical Stack

- Physics: `@react-three/rapier`
- Character controller substrate: `ecctrl`
- Avatar format: `GLB` first, `VRM` second

### Why `GLB` first

`GLB` is the fastest route to a stable first playable controller:

- simpler asset loading
- simpler animation clip handling
- fewer package/runtime concerns than `VRM`
- easier to swap placeholder and production humanoids

`VRM` can land after the controller loop is proven.

## Delivery Phases

| Phase | Goal | Exit Criteria |
| --- | --- | --- |
| `CC-P0` | Stack and contracts | physics/controller deps and local player contracts exist |
| `CC-P1` | Player runtime | observatory mounts a controllable rigid-body avatar with move/jump |
| `CC-P2` | Authored move-set | jump, flip triggers, landing, and camera follow are coherent |
| `CC-P3` | World integration | station focus, probe behavior, and player coexist in one world |
| `CC-P4` | Verification and dogfood | browser/native dogfood prove movement, jump, and flips live |

## Concrete File Targets

### Shared / orchestrator-owned

- `apps/desktop/package.json`
- `apps/desktop/vite.config.ts`
- `apps/desktop/tsconfig.json`
- `apps/desktop/src/features/hunt-observatory/index.ts`
- `apps/desktop/src/features/hunt-observatory/world/ObservatoryWorldCanvas.tsx`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-character-controller-plan.md`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-character-controller-swarm-plan.md`
- `docs/plans/clawdstrike/huntronomer/README.md`

### New local player subtree

- `apps/desktop/src/features/hunt-observatory/character/**`

Suggested structure:

```text
apps/desktop/src/features/hunt-observatory/character/
  index.ts
  types.ts
  input/
    useObservatoryPlayerInput.ts
  controller/
    ObservatoryPlayerController.tsx
    useObservatoryPlayerRuntime.ts
  animation/
    useObservatoryPlayerAnimation.ts
    moveSet.ts
  avatar/
    ObservatoryPlayerAvatar.tsx
    useAvatarAsset.ts
  physics/
    colliders.ts
    spawn.ts
```

## Core Contracts

```ts
type ObservatoryPlayerAction =
  | "idle"
  | "walk"
  | "run"
  | "jump-start"
  | "jump-air"
  | "land"
  | "flip-front"
  | "flip-back";

type ObservatoryPlayerIntent = {
  moveX: number;
  moveY: number;
  jump: boolean;
  flipFront: boolean;
  flipBack: boolean;
  sprint: boolean;
};

type ObservatoryPlayerState = {
  position: [number, number, number];
  velocity: [number, number, number];
  grounded: boolean;
  activeAction: ObservatoryPlayerAction;
  facingRadians: number;
  stationId: HuntStationId | null;
};
```

## Interaction Rules

- `WASD`: move
- `Shift`: sprint
- `Space`: jump
- `Q`: front flip
- `E`: back flip
- station clicks still navigate the world; they do not disable the avatar
- when the player is moving manually, camera follow takes precedence over station fly-to
- station fly-to should settle behind or near the player if the player is already in world

## Camera Rules

- Third-person follow is the default while the player is active.
- Station-arrival choreography still exists, but should hand off smoothly to follow mode.
- Camera should not clip through district structures.
- First pass can use spring follow + orbit constraints; advanced collision camera can come later.

## World Integration Rules

- The player spawns near the thesis core by default.
- Each station district should expose a soft landing area or walkable plate.
- Probe interactions should still work; if the player is active, probe can trail or anchor nearby.
- The player should not bulldoze district geometry. Use collision layers and walkable bounds.

## Asset Plan

### First asset

- One lightweight humanoid `GLB`
- must include at least:
  - idle
  - walk
  - run
  - jump
  - flip
  - land

### Fallback

- if no production humanoid is ready, ship with:
  - visible capsule or stylized observatory shell body
  - same controller runtime
  - same input and camera

## Verification

Minimum commands:

- `npm --prefix apps/desktop run typecheck`
- `npm --prefix apps/desktop test -- --run`
- `npm --prefix apps/desktop run build`
- `scripts/huntronomer-playwright-smoke.sh`

Required live proof:

- browser dogfood with observatory route mounted
- native Tauri run with avatar movement
- artifact-backed screenshots or short capture proving:
  - spawn
  - walk/run
  - jump
  - front flip
  - back flip

## Acceptance Gate

The initiative is complete when:

- the observatory mounts one controllable player character
- movement feels stable and physical
- jump and at least one flip are reliable and visually legible
- station/world navigation still works
- the room remains readable instead of collapsing into demo-game noise
