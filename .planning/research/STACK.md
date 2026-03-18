# Stack Research

**Domain:** R3F/3D integration into a VS Code-like IDE workbench (Tauri 2 + React 19)
**Researched:** 2026-03-18
**Confidence:** HIGH — verified against official R3F/drei docs, source code audit of huntronomer-workspace-orch, and multiple cross-checked sources.

---

## Situation Summary

The workbench already has `@react-three/fiber ^9.0.0`, `@react-three/drei ^10.0.0`, and `@react-three/rapier ^2.2.0` listed as dependencies in `apps/desktop/package.json` (the huntronomer source app). The target workbench app (`apps/workbench/package.json`) does **not** yet include any R3F packages — they must be added. No new framework choices are needed; the decisions were made in the huntronomer branch and are validated here.

---

## Recommended Stack

### Core Technologies (all NEW additions to apps/workbench)

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `@react-three/fiber` | `^9.0.0` | React renderer for Three.js — powers all Canvas embeds | v9 is the R3F major that pairs with React 19; v8 is incompatible. Already in huntronomer source at this version. |
| `@react-three/drei` | `^10.0.0` | R3F helper components (OrbitControls, Stars, Html, Line, useGLTF, PerformanceMonitor, View) | v10 is the drei major for R3F v9. Source uses `Line`, `OrbitControls`, `Stars`, `useGLTF`, `Html`, `Environment` — all stable drei exports. |
| `three` | `^0.170.0` | Three.js peer dependency | Huntronomer source pins `^0.170.0`; drei 10 / R3F 9 require three ≥ 0.168. |
| `@react-three/rapier` | `^2.2.0` | Physics for observatory flow mode (character controller) | Rapier v2 is the version that adds R3F v9 + React 19 support. Only needed for the observatory flow-mode Easter egg (character controller + `Physics` wrapper). |

### Supporting Libraries (all already in `apps/desktop`; add to workbench selectively)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `@types/three` | `^0.170.0` | TypeScript types for Three.js | Always, as dev dep — required for typed refs (`useRef<THREE.Mesh>`) |
| `ecctrl` | `^1.0.97` | Character controller built on Rapier | Only for observatory flow mode. NOT needed for Tier 1 or Tier 2 work. Listed in `apps/desktop` deps. |
| `@pixiv/three-vrm` | NOT needed | VRM avatar rendering from huntronomer source | Explicitly out-of-scope per PROJECT.md ("VRM avatar rendering — too heavy for IDE"). Do not add. |

### Libraries Already in apps/workbench (no action needed)

| Library | Current Version | 3D Role |
|---------|-----------------|---------|
| `motion` | `^12.33.0` | CSS/DOM animations for spirit field stain, accent color transitions (Tier 1 — no R3F required) |
| `zustand` | `^5.0.12` | State for spirit-store.ts, observatory-store.ts (2 new stores) |

---

## Integration Points with Existing Stack

### Zustand Stores (NEW, no library change)

Two new stores use the existing Zustand `^5.0.12` + `createSelectors` pattern already in the workbench.

```typescript
// spirit-store.ts — mirrors workbench-dev's pattern
// observatory-store.ts — mirrors workbench-dev's pattern
```

No additional state library is needed. Both stores follow the established `createSelectors` utility from Phase A.

### Pane System Integration

The binary tree pane system (already built) renders pane content by `appId`. The 3D views slot in as new `appId` values (`observatory`, `nexus`, `spirit-chamber`). The pane system renders them in a `div` with `position: relative; height: 100%` — exactly what R3F `Canvas` needs. No pane system changes required.

### Canvas-per-View vs Single Canvas with `View`

This is the most important architectural decision for IDE embedding:

**Chosen approach: separate Canvas per pane tab, with `frameloop="demand"` on background/companion canvases.**

Rationale:
- The workbench uses a binary tree pane system where panes mount/unmount as tabs are opened and closed. `drei View` requires a single persistent parent `Canvas` with `Canvas eventSource={containerRef}` — this conflicts with pane mounting/unmounting semantics.
- Browser WebGL context limit is ~8-16 contexts. The workbench will have at most 3 simultaneous R3F canvases (observatory pane, mini spirit companion, forensics river). This is well within budget.
- `drei View` z-index constraint (issue #2471) breaks dialog/modal stacking — the workbench uses modal dialogs.
- Separate canvases with proper `frameloop` settings are simpler and more resilient than scissoring for this pane architecture.

**When to use `frameloop="demand"`:** Mini spirit companion in sidebar (renders only on spirit state change), forensics river tape (renders only on new event data). Use `invalidate()` when driving from Zustand store subscription.

**When to use `frameloop="always"`:** Observatory world canvas (character controller + continuous animation), cyber nexus (live data updates).

---

## Canvas Configuration Pattern

Established in huntronomer source (`ObservatoryWorldCanvas.tsx`):

```typescript
<Canvas
  dpr={[1, 1.8]}                          // adaptive resolution — never fixed 2x
  camera={{ position: [...], fov: 45 }}
  gl={{ antialias: true, alpha: false, powerPreference: "high-performance" }}
  style={{ background: "..." }}
>
  <Suspense fallback={null}>
    {/* scene content */}
  </Suspense>
</Canvas>
```

**Do not change this pattern.** `alpha: false` avoids compositing cost. `dpr={[1, 1.8]}` caps Retina overhead. `powerPreference: "high-performance"` on macOS (Tauri target) selects discrete GPU.

For **mini/ambient canvases** (spirit orb, companion sidebar), add:

```typescript
frameloop="demand"
gl={{ antialias: false, alpha: true, powerPreference: "default" }}
dpr={[1, 1.5]}
```

`alpha: true` needed for transparent overlay on sidebar background. `antialias: false` acceptable at small size.

---

## Performance Monitoring (dev only)

| Tool | Version | Purpose | Notes |
|------|---------|---------|-------|
| `r3f-perf` | latest | GPU/CPU stats overlay inside Canvas | Dev dependency only; gate with `import.meta.env.DEV`. Never ships to prod. |

`PerformanceMonitor` from drei is the production adaptive quality tool — it's already in drei 10 and requires no new package.

---

## What NOT to Add

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `@react-three/offscreen` | Still at v0.0.8, experimental, Safari incompatible, not production-ready as of 2026-03-18 | `frameloop="demand"` + `invalidate()` gives sufficient CPU relief for non-animating panels |
| `@pixiv/three-vrm` | Explicitly out-of-scope (spirit orb is the right abstraction, not VRM avatar) | Custom geometry from `sceneVisuals.tsx` |
| `@react-three/postprocessing` | Not used in huntronomer source; adds bundle weight for bloom/effects not needed in IDE panels | `meshStandardMaterial` emissive + emissiveIntensity handles glow at much lower cost |
| `drei View` (scissor) | Conflicts with binary pane mount/unmount, z-index issues with modals, requires persistent parent canvas | Separate `Canvas` per pane with `frameloop` control |
| `leva` | Debug GUI library; workbench uses command palette for configuration | Command palette (already built) |
| Full `@react-three/rapier` in all scenes | Physics is heavyweight; only the observatory flow mode needs it | Omit `Physics` wrapper from spirit companion and nexus canvas |

---

## Alternatives Considered

| Recommended | Alternative | When Alternative Makes Sense |
|-------------|-------------|------------------------------|
| R3F `Canvas` per pane tab | `drei View` single canvas | Better for scroll-based marketing sites where Views never unmount; bad for a pane system |
| `frameloop="demand"` + `invalidate()` for idle canvases | `@react-three/offscreen` worker | Offscreen would be better once Safari support lands and v1 ships; revisit in 2027 |
| `three ^0.170.0` | Latest three patch | Pin minor, not patch — drei and R3F peerDep ranges allow latest three 0.17x |

---

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| `@react-three/fiber@9.x` | `react@19.x`, `three@0.168+` | v9 specifically designed for React 19; v8 will not work |
| `@react-three/drei@10.x` | `@react-three/fiber@9.x` | Major versions are coupled; do not mix drei 9 with fiber 9 |
| `@react-three/rapier@2.x` | `@react-three/fiber@9.x`, `react@19.x` | v2 added R3F v9 support; v1 was for R3F v8 |
| `ecctrl@1.x` | `@react-three/rapier@2.x` | ecctrl depends on rapier; only pull in for observatory flow mode |
| `three@0.170.0` | `@react-three/fiber@9.x`, `@react-three/drei@10.x` | Matches huntronomer source; `@types/three@0.170.0` required to match |

---

## Installation

```bash
# Add to apps/workbench — core R3F stack
bun add @react-three/fiber@^9.0.0 @react-three/drei@^10.0.0 three@^0.170.0

# Physics (only when building observatory flow mode, Phase 3)
bun add @react-three/rapier@^2.2.0

# Character controller (only when building observatory flow mode, Phase 3)
bun add ecctrl@^1.0.97

# TypeScript types (dev)
bun add -D @types/three@^0.170.0

# Performance monitoring (dev only)
bun add -D r3f-perf
```

---

## Stack Patterns by Variant

**If rendering a full immersive pane (observatory, nexus):**
- Use `frameloop="always"`, `alpha: false`, `dpr={[1, 1.8]}`
- Wrap scene in `<Suspense fallback={null}>`
- Add `<PerformanceMonitor onDecline={() => setDpr(1)} onIncline={() => setDpr(1.5)}>` inside Canvas

**If rendering a mini ambient embed (spirit companion sidebar, spirit orb in ActivityBar):**
- Use `frameloop="demand"`, `alpha: true`, `dpr={[1, 1.5]}`, `antialias: false`
- Drive re-renders by calling `invalidate()` in a Zustand store subscription
- Keep geometry count low (< 500 triangles); no shadows

**If rendering the forensics river "Tape" tab:**
- Use `frameloop="demand"`, connect to event stream, call `invalidate()` on new events
- Disable physics entirely — no `<Physics>` wrapper needed

**If adding HTML labels inside a 3D scene (spirit labels, station names):**
- Use `drei <Html>` with `distanceFactor` + `style={{ pointerEvents: "none" }}`
- Do NOT use `transform` prop on Html when canvas is not fullscreen — causes misalignment in panel context

---

## Sources

- R3F official docs (r3f.docs.pmnd.rs) — Canvas props, frameloop, dpr, v9 migration guide — HIGH confidence
- Drei official docs (drei.docs.pmnd.rs) — PerformanceMonitor, View, Html — HIGH confidence
- Huntronomer source audit (`apps/desktop/package.json`, `ObservatoryWorldCanvas.tsx`, `NexusSpiritCompanion.tsx`) — direct dependency evidence — HIGH confidence
- `apps/workbench/package.json` — confirmed R3F packages absent, need to be added — HIGH confidence
- GitHub: pmndrs/react-three-offscreen (v0.0.8 status) — confirmed experimental/pre-production — HIGH confidence
- GitHub discussions: drei issue #2471 (View z-index), fiber discussion #2716 (multiple canvas) — MEDIUM confidence
- WebSearch: drei View pattern for multi-panel, Tauri WebGL context loss reports — MEDIUM confidence

---
*Stack research for: R3F/3D integration into ClawdStrike Workbench IDE*
*Researched: 2026-03-18*
