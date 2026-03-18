# Architecture Research

**Domain:** 3D R3F canvas integration into a VS Code-like IDE workbench (Tauri 2 + React 19 + Zustand)
**Researched:** 2026-03-18
**Confidence:** HIGH — based on direct inspection of both source codebases

## Standard Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                         DesktopLayout                                │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐  ┌─────────┐  │
│  │ActivityBar│  │SidebarPanel  │  │   Main Column    │  │RightSide│  │
│  │  48px    │  │240px (resiz.)│  │  (flex-1 min-w-0)│  │  bar    │  │
│  │          │  │              │  │ ┌────────────────┐│  │  320px  │  │
│  │spirit orb│  │  hunt panel  │  │ │   PaneRoot     ││  │(resiz.) │  │
│  │badge     │  │  (seam data) │  │ │ ┌────────────┐ ││  │         │  │
│  │          │  │              │  │ │ │PaneContainer│ ││  │Spirit   │  │
│  └──────────┘  └──────────────┘  │ │ │ ┌────────┐ │ ││  │Companion│  │
│                                  │ │ │ │R3F Tab │ │ ││  │Canvas   │  │
│                                  │ │ │ └────────┘ │ ││  │         │  │
│                                  │ │ └────────────┘ ││  └─────────┘  │
│                                  │ └────────────────┘│               │
│                                  │  ┌──────────────┐ │               │
│                                  │  │  BottomPane  │ │               │
│                                  │  │  (tape tab)  │ │               │
│                                  │  └──────────────┘ │               │
│                                  └──────────────────┘                │
└──────────────────────────────────────────────────────────────────────┘

Zustand Store Layer (cross-cutting):
┌────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐
│spirit-store│  │observatory-store │  │  Existing 11 stores          │
│  (new)     │  │  (new)           │  │  (pane, activity-bar,        │
│            │  │                  │  │   right-sidebar, bottom-pane)│
└────────────┘  └──────────────────┘  └─────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Lives In |
|-----------|---------------|----------|
| `ActivityBar` | Icon rail with spirit orb badge when spirit is bound; observatory seam powers badge counts | `features/activity-bar/` |
| `SidebarPanel` | Left sidebar showing hunt panel with seam-derived artifact counts | `features/activity-bar/` |
| `PaneRoot` | Binary tree of panes; renders 3D tabs as routes (observatory, nexus, spirit-chamber) | `features/panes/` |
| `PaneContainer` | Wraps `PaneRouteRenderer`; the `overflow-auto` div is the 3D canvas parent | `features/panes/` |
| `PaneRouteRenderer` | Uses `useRoutes` — new 3D routes registered here to land R3F canvases as tabs | `features/panes/` |
| `RightSidebar` | Currently Speakeasy-only; add panel switch to show `SpiritCompanionCanvas` (mini R3F) | `features/right-sidebar/` |
| `BottomPane` | Add "Tape" tab housing `ForensicsRiverMiniView` | `features/bottom-pane/` |
| `spirit-store` | Bound spirit state: kind, accentColor, mood, motion envelope; drives CSS field stain + orb | `features/spirit/` (new) |
| `observatory-store` | Active hunt ID, seam summary, station counts; feeds activity bar badges | `features/observatory/` (new) |
| `SpiritCreationChamber` | Pane tab (`/spirit-chamber`); pure CSS animation canvas, zero R3F, drop-in port | `features/spirit/` (new) |
| `ObservatoryWorldCanvas` | Pane tab (`/observatory`); full R3F + Rapier scene; character controller opt-in | `features/observatory/` (new) |
| `CyberNexusView` | Pane tab (`/nexus`); R3F graph canvas + overlay UI; heavy, only mount when active | `features/nexus/` (new) |
| `ForensicsRiverMiniView` | BottomPane "Tape" tab; `@backbay/glia-three` RiverView, slim embed | `features/forensics/` (new) |

## Recommended Project Structure

```
apps/workbench/src/
├── features/
│   ├── spirit/                    # NEW — spirit state + CSS field stain
│   │   ├── spirit-store.ts        # Zustand store: bound spirit, mood, accentColor
│   │   ├── spirit-field-stain.ts  # Pure CSS gradient builder (port from huntronomer)
│   │   ├── spirit-math.ts         # sceneMath port: motion envelope math
│   │   ├── spirit-visuals.ts      # sceneVisuals port: CSS animation values
│   │   ├── spirit-defaults.ts     # defaults.ts port: kind → meta map
│   │   ├── spirit-types.ts        # HuntSpiritState, HuntSpiritKind, etc.
│   │   └── components/
│   │       ├── spirit-orb.tsx     # Animated ActivityBar orb (SVG/CSS, no R3F)
│   │       ├── spirit-chamber-tab.tsx  # Pane route for /spirit-chamber
│   │       └── spirit-companion-canvas.tsx  # Mini R3F in RightSidebar
│   ├── observatory/               # NEW — observatory seam + full tab
│   │   ├── observatory-store.ts   # Zustand store: activeHuntId, seam summary
│   │   ├── observatory-seam.ts    # buildHuntObservatorySeamSummary port
│   │   ├── observatory-types.ts   # HuntObservatorySceneState, actors, etc.
│   │   ├── observatory-world.ts   # deriveObservatoryWorld port
│   │   └── components/
│   │       └── observatory-tab.tsx  # Pane route for /observatory (wraps ObservatoryWorldCanvas)
│   ├── nexus/                     # NEW — cyber nexus "Hunt Deck" tab
│   │   ├── nexus-state.ts         # NexusStateContext port → local useReducer or Zustand slice
│   │   ├── nexus-types.ts
│   │   └── components/
│   │       ├── nexus-tab.tsx      # Pane route for /nexus
│   │       ├── nexus-canvas.tsx   # ObservatoryWorldCanvas embed
│   │       └── nexus-spirit-companion.tsx
│   ├── forensics/                 # NEW — forensics river mini-view
│   │   └── components/
│   │       └── forensics-tape-tab.tsx  # BottomPane "Tape" embed
│   ├── activity-bar/              # MODIFY — add spirit orb + seam badge
│   ├── right-sidebar/             # MODIFY — add spirit companion panel
│   └── bottom-pane/               # MODIFY — add "tape" tab
```

### Structure Rationale

- **features/ domain directories:** Each 3D surface is a self-contained feature with its own store slice, types, and components. This matches the existing workbench pattern (`panes/`, `activity-bar/`, `right-sidebar/`).
- **spirit/ separated from observatory/:** Spirit state is ambient (affects CSS everywhere). Observatory state is scoped to hunt-deck views. They communicate via derived selectors, not direct coupling.
- **No shared R3F `<Canvas>` singleton:** Each R3F surface owns its own `<Canvas>`. Sharing one canvas across split panes is technically possible but creates lifecycle complexity without meaningful performance benefit at this scale.

## Architectural Patterns

### Pattern 1: Route-as-Pane-Tab for 3D Views

**What:** New 3D views are registered as routes in `WORKBENCH_ROUTE_OBJECTS`. The pane system renders them via `PaneRouteRenderer`, which calls `useRoutes`. Any route can be opened as a tab via `usePaneStore.getState().openApp(route)`.

**When to use:** For full-pane 3D views (observatory, nexus, spirit-chamber). The route becomes the tab handle. This requires zero changes to `PaneRoot` or `PaneContainer`.

**Trade-offs:** Routes must be unique paths. The 3D canvas mounts/unmounts on tab focus change. This is the desired behavior for performance — see Pattern 3.

**Example:**
```typescript
// workbench-routes.tsx additions
const ObservatoryTab = lazy(() =>
  import("@/features/observatory/components/observatory-tab").then((m) => ({
    default: m.ObservatoryTab,
  })),
);

const NexusTab = lazy(() =>
  import("@/features/nexus/components/nexus-tab").then((m) => ({
    default: m.NexusTab,
  })),
);

// In WORKBENCH_ROUTE_OBJECTS:
{ path: "observatory", element: <Suspense fallback={<div className="flex-1" />}><ObservatoryTab /></Suspense> },
{ path: "nexus",       element: <Suspense fallback={<div className="flex-1" />}><NexusTab /></Suspense> },
{ path: "spirit-chamber", element: <SpiritChamberTab /> },

// In getWorkbenchRouteLabel:
if (url.pathname === "/observatory") return "Observatory";
if (url.pathname === "/nexus") return "Hunt Deck";
if (url.pathname === "/spirit-chamber") return "Spirit Chamber";

// Commands registered in init-commands.tsx:
registry.register({
  id: "observatory.open",
  label: "Open Observatory",
  execute: () => usePaneStore.getState().openApp("/observatory"),
});
```

### Pattern 2: CSS Field Stain via spirit-store CSS Variables

**What:** When a spirit is bound, `spirit-store` exposes the accent color and spirit kind. A React effect (or CSS-in-JS at DesktopLayout) applies CSS custom properties (`--spirit-accent`, `--spirit-kind`) to `document.documentElement`. Panel backgrounds layer the field stain as a `::before` pseudo-element or an absolutely positioned div with `mix-blend-mode: screen`.

**When to use:** For all ambient spirit color effects (panel stains, activity bar badge color, tab accent lines). Keeps the stain logic in CSS rather than JS re-renders.

**Trade-offs:** CSS vars approach means one global update instead of per-component subscriptions. The `buildSpiritFieldStainStyle()` function from huntronomer returns `CSSProperties`, which is already compatible — pass the result as inline style on a positioned overlay div inside each surface that needs staining.

**Example:**
```typescript
// spirit-store.ts exposes:
interface SpiritStoreState {
  boundSpirit: HuntSpiritState | null;
  runtimeState: HuntSpiritRuntimeState;
  // derived:
  accentColor: string;   // from getHuntSpiritMeta(kind).accentColor
  fieldStrength: number; // 0-1
}

// In DesktopLayout (or a <SpiritFieldInjector /> side-effect component):
useEffect(() => {
  document.documentElement.style.setProperty("--spirit-accent", accentColor);
  document.documentElement.style.setProperty("--spirit-field", String(fieldStrength));
}, [accentColor, fieldStrength]);

// Panel surfaces that receive the stain render:
<div className="absolute inset-0 pointer-events-none" style={buildSpiritFieldStainStyle({
  kind, accentColor, receiveState, surface, focusXPercent, focusYPercent
})} />
```

### Pattern 3: R3F Canvas Lifecycle Tied to Pane Focus

**What:** The `PaneContainer` wraps content in a `motion.div` that is `overflow-auto`. When a tab is not active, the pane-route-renderer still renders the component but the tab is visually hidden (the PaneTabBar switches the visible tab; the inactive route is not rendered at all — `useRoutes` returns the matching element only for the active route string).

Looking at `PaneRouteRenderer`: it calls `useRoutes(WORKBENCH_ROUTE_OBJECTS, normalizeWorkbenchRoute(route))`. Each `PaneContainer` renders the route of its active view. When a tab becomes inactive (user switches tabs in the same pane), the route's element unmounts from that pane. This means R3F canvases naturally unmount/remount on tab switch.

**Implication:** No explicit "pause when not focused" logic needed for pane tabs. The canvas unmounts. For the RightSidebar companion canvas and the BottomPane tape tab, they mount when the panel is visible and unmount when collapsed — already handled by the conditional render in `DesktopLayout` (`rightSidebarVisible && <RightSidebar />`).

**Performance consideration:** R3F `<Canvas>` with `frameloop="demand"` stops rendering frames when there is no interaction. Use this for the companion canvas and tape tab. The full observatory tab can use `frameloop="always"` for the ambient animation but should respond to a `usePaneStore` subscription to pause the render loop when the pane is not the active pane in split-pane mode.

**Example:**
```typescript
// In ObservatoryTab: suspend rendering when pane is not visible
const activePaneRoute = usePaneStore((state) =>
  getActivePaneRoute(state.root, state.activePaneId),
);
const isVisible = activePaneRoute === "/observatory";

// Pass to canvas:
<Canvas frameloop={isVisible ? "always" : "demand"} />
```

### Pattern 4: Route Bridge — Station Clicks to openApp()

**What:** The huntronomer `routeBridge.ts` maps pathname segments to app IDs. In the workbench, the equivalent is `usePaneStore.getState().openApp(route)`. When a user clicks a station in the Observatory or a strikecell in the Nexus, call `openApp` with the relevant route.

**When to use:** Anywhere a 3D surface needs to navigate the IDE (station → policy editor, strikecell → fleet view, etc.).

**Trade-offs:** This is one-way from 3D surface to pane store. The reverse (IDE navigation updating the 3D scene selection) is handled by the observatory-store/spirit-store reading from the pane store's active route — a derived selector, not a direct subscription loop.

**Example:**
```typescript
// In ObservatoryTab or NexusTab:
function handleStationClick(stationId: HuntStationId) {
  const route = STATION_ROUTE_MAP[stationId]; // e.g. "signal" → "/findings"
  usePaneStore.getState().openApp(route);
}
```

## Data Flow

### Spirit State Flow

```
[spirit-store]
    boundSpirit, runtimeState, accentColor, fieldStrength
         |
         ├──→ DesktopLayout (CSS var injector)
         │       --spirit-accent, --spirit-field on <html>
         │
         ├──→ ActivityBar
         │       spirit orb SVG animation driven by runtimeState.motion
         │       replaces static icon when boundSpirit !== null
         │
         ├──→ SpiritChamberTab (/spirit-chamber)
         │       renders SpiritManifestationCanvas using spirit kind + motion
         │
         ├──→ SpiritCompanionCanvas (RightSidebar panel)
         │       mini R3F Canvas, driven by runtimeState
         │
         └──→ Panel field stains (NexusTab, ForensicsTapeTab)
                buildSpiritFieldStainStyle() as inline overlay div

Commands (spirit.bind, spirit.release) → spirit-store.actions
```

### Observatory/Seam Data Flow

```
[observatory-store]
    activeHuntId, seamSummary (HuntObservatorySeamSummary)
         |
         ├──→ ActivityBar
         │       badge counts from seamSummary.stations[].count
         │
         ├──→ SidebarPanel (hunt section)
         │       station list with seam counts
         │
         ├──→ ObservatoryTab (/observatory)
         │       passes sceneState to ObservatoryWorldCanvas
         │
         └──→ NexusTab (/nexus)
                atlasRead derived from seamSummary + spirit-store

Commands (observatory.open, observatory.probe) → observatory-store.actions
observatory-store reads from usePaneStore (active route) to infer context
```

### Pane System Integration

```
[User: opens observatory command]
    ↓
init-commands.tsx → usePaneStore.getState().openApp("/observatory")
    ↓
pane-store: addViewToGroup({ route: "/observatory", label: "Observatory" })
    ↓
PaneContainer renders PaneRouteRenderer with route="/observatory"
    ↓
useRoutes matches ObservatoryTab → mounts R3F Canvas
    ↓
ObservatoryTab subscribes to observatory-store + spirit-store
    ↓
[User: clicks station in ObservatoryTab]
    ↓
handleStationClick → usePaneStore.getState().openApp("/findings")
    ↓
PaneContainer updates active view, ObservatoryTab route stays live in tab bar
```

### Store Interaction Map

```
spirit-store ←──────────────────────────────── Commands (spirit.bind / spirit.release)
     │
     │ read: accentColor, runtimeState, motion
     ↓
ActivityBar, panel stains, SpiritChamberTab, SpiritCompanionCanvas

observatory-store ←──────────────────────────── Commands (observatory.probe)
     │        ↑
     │        └── reads usePaneStore.activePaneRoute for context inference
     │
     │ read: seamSummary, sceneState
     ↓
ActivityBar badges, ObservatoryTab, NexusTab

pane-store (unchanged) ←───────────────────── Commands (observatory.open, nexus.open)
     │
     │ openApp("/observatory"), openApp("/nexus"), openApp("/spirit-chamber")
     ↓
PaneRouteRenderer → mounts 3D tab components

right-sidebar-store (modified) ←─────────────── Commands (spirit.showCompanion)
     │ activePanel: "speakeasy" | "spirit-companion"
     ↓
RightSidebar renders SpeakeasyPanel OR SpiritCompanionCanvas

bottom-pane-store (modified)
     │ activeTab: "terminal" | "problems" | "output" | "audit" | "tape"
     ↓
BottomPane renders ForensicsTapeTab when "tape" is active
```

## Scaling Considerations

This is a desktop Tauri app. "Scale" means performance at runtime, not user count.

| Concern | Mitigation |
|---------|-----------|
| Multiple R3F canvases active simultaneously | Only one heavy canvas (observatory or nexus) should be in a pane at a time. The companion canvas uses `frameloop="demand"` and is small (right sidebar width ≈ 320px). The tape tab mini view is also demand-rendered. Maximum concurrent R3F instances: 2 (one pane tab + one sidebar/bottom embed). |
| Observatory canvas with Rapier physics | Character controller physics loop runs at 60fps. Use `frameloop="always"` only for observatory tab. Gate with `isVisible` check from pane store. |
| Spirit field stain re-renders | Field stain is CSS gradient on a positioned div. Updating it requires only the overlay div's inline style to change — no React tree re-render. The `buildSpiritFieldStainStyle()` call is memoized on `(kind, accentColor, receiveState, focusX, focusY)`. |
| Large NexusCanvas with many strikecells | NexusCanvas uses ObservatoryWorldCanvas (same R3F scene, atlas mode). The Three.js instancing in the existing implementation already handles the node count. Port the existing approach unchanged. |
| GLTF/texture loading (astronaut avatar) | Use `useGLTF.preload()` for the observatory character assets when the observatory tab is first opened, not at app boot. Preload in `ObservatoryTab` on component mount using `useEffect`. |

## Anti-Patterns

### Anti-Pattern 1: Shared R3F `<Canvas>` Singleton

**What people do:** Create one global `<Canvas>` rendered in `DesktopLayout` to "save resources," portaling 3D content into it.

**Why it's wrong:** React Three Fiber `<Canvas>` manages its own renderer lifecycle and React root. Portaling into a canvas from outside its React subtree requires `createPortal` from R3F (not React DOM), breaks standard component tree access to context, and makes mount/unmount lifecycle unclear. The Zustand stores can't gate rendering properly. The existing workbench pane system already handles unmounting naturally — let it.

**Do this instead:** Each 3D view owns its own `<Canvas>`. Keep them small for embeds (`frameloop="demand"`, reduced pixel ratio). The observatory tab is the only "always-on" full canvas.

### Anti-Pattern 2: spirit-store Depending on observatory-store

**What people do:** Put spirit bind/release logic inside observatory-store because "the spirit is part of the hunt."

**Why it's wrong:** Spirit is ambient — it affects CSS field stains in nexus, forensics river, and the right-sidebar companion, none of which are hunt-observatory concerns. Coupling them means toggling the spirit orb triggers observatory re-renders.

**Do this instead:** `spirit-store` is purely about the bound spirit's kind/mood/motion. `observatory-store` reads from `spirit-store` via selector when it needs the spirit field bias (e.g., to compute station emphasis in the scene). One-way dependency: `observatory-store → spirit-store`, never the reverse.

### Anti-Pattern 3: WorkbenchStateProvider Context for Spirit/Observatory State

**What people do:** Add `spiritState` and `observatoryState` to the existing monolithic `WorkbenchStateProvider` context (as seen in the huntronomer source — the old `useWorkbench()` hook carries all state).

**Why it's wrong:** The workbench already migrated away from this pattern (1846-line monolith → 3 focused Zustand stores). Adding spirit/observatory state back into a context provider re-creates the same problem: any component reading spirit state gets re-rendered when observatory state changes.

**Do this instead:** Two independent Zustand stores with `createSelectors`. Components subscribe to only the slices they need. Spirit state consumers (`ActivityBar`, panel stains) never re-render when observatory seam data changes.

### Anti-Pattern 4: Registering 3D Routes Outside WORKBENCH_ROUTE_OBJECTS

**What people do:** Add a separate router for 3D views, or render them directly in a custom `PaneContainer` variant that bypasses the route system.

**Why it's wrong:** `PaneRouteRenderer` calls `useRoutes(WORKBENCH_ROUTE_OBJECTS, route)`. Any route not in `WORKBENCH_ROUTE_OBJECTS` renders nothing. More importantly, `getWorkbenchRouteLabel` and `normalizeWorkbenchRoute` need to know about new routes for tab labels and URL normalization to work correctly.

**Do this instead:** Add `/observatory`, `/nexus`, `/spirit-chamber` to `WORKBENCH_ROUTE_OBJECTS` with `lazy()` + `<Suspense>` wrappers. Add labels in `getWorkbenchRouteLabel`. That is the only registration point needed.

## Integration Points

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `spirit-store` → `ActivityBar` | Zustand selector subscription | Orb replaces static icon; badge color uses accentColor |
| `spirit-store` → `DesktopLayout` | `useEffect` → CSS var on `<html>` | Single injection point for ambient field stain |
| `spirit-store` → `SpiritChamberTab` | Direct Zustand read | Chamber reads kind + motion for manifestation canvas |
| `spirit-store` → `SpiritCompanionCanvas` | Direct Zustand read | Mini R3F in right sidebar |
| `observatory-store` → `ActivityBar` | Zustand selector | Seam station counts → badge numbers |
| `observatory-store` → `ObservatoryTab` | Direct Zustand read | Derives scene state for R3F canvas |
| `observatory-store` → `NexusTab` | Direct Zustand read | Atlas mode for nexus canvas |
| `pane-store` (existing) → `ObservatoryTab` | Read activePaneRoute | Gate canvas render loop |
| `pane-store` (existing) → `Commands` | `openApp()` mutation | Commands open 3D tabs as pane views |
| `right-sidebar-store` (modified) | add `"spirit-companion"` panel | RightSidebar panel switch |
| `bottom-pane-store` (modified) | add `"tape"` tab | BottomPane tab addition |
| `ObservatoryTab` → `pane-store` | `openApp()` on station click | Route bridge: station → IDE view |
| `NexusTab` → `pane-store` | `openApp()` on strikecell action | Route bridge: nexus → IDE view |
| `ForensicsTapeTab` → `spirit-store` | Read accentColor for river overlay | HuntSpiritOverlay CSS tint |

### External Dependencies to Add

| Package | Version | Purpose | Already in workbench? |
|---------|---------|---------|----------------------|
| `@react-three/fiber` | ^9.0.0 | R3F core | No — must add |
| `@react-three/drei` | ^10.0.0 | R3F helpers (OrbitControls, Stars, Line, useGLTF) | No — must add |
| `@react-three/rapier` | ^2.2.0 | Physics for observatory character | No — must add |
| `three` | ^0.170.0 | Three.js core | No — must add |
| `@backbay/glia-three` | ^0.2.0-alpha.5 | ForensicsRiverView (River component) | No — must add |

All five packages are already installed in the huntronomer source app. They are workspace-compatible. Add to `apps/workbench/package.json` dependencies.

## Suggested Build Order (Tier Dependencies)

```
Tier 1 (no R3F required — CSS/state only)
  spirit-store.ts + spirit-types.ts
       ↓
  spirit-field-stain.ts (port of fieldStain.ts)
       ↓
  SpiritFieldInjector → DesktopLayout CSS vars
       ↓
  ActivityBar spirit orb (SVG/CSS animation, no R3F)
       ↓
  observatory-store.ts + observatory-seam.ts
       ↓
  ActivityBar seam badge counts
       ↓
  Route bridge wiring: commands → openApp()

Tier 2 (R3F embeds — install packages first)
  Install @react-three/fiber, drei, rapier, three, glia-three
       ↓
  SpiritChamberTab (CSS canvas, no R3F — but needs spirit-store from Tier 1)
       ↓
  SpiritCompanionCanvas (mini R3F, demand frameloop)
       ↓
  ForensicsTapeTab (glia-three River embed, demand frameloop)

Tier 3 (full R3F pane tabs — depends on Tier 1 stores + Tier 2 packages)
  deriveObservatoryWorld port → observatory-world.ts
       ↓
  ObservatoryTab with ObservatoryWorldCanvas (atlas mode, no character)
       ↓
  NexusTab with NexusCanvas (uses ObservatoryWorldCanvas internally)
       ↓
  Observatory character controller Easter-egg (opt-in flow mode)
```

Tier 1 has zero new npm dependencies and is pure state + CSS logic — safe to build and test before any R3F packages land. Tier 2 requires the package additions but the canvases are small embeds. Tier 3 contains the largest components and should be gated behind the stores being stable.

## Sources

- Direct inspection: `apps/workbench/src/components/desktop/desktop-layout.tsx`
- Direct inspection: `apps/workbench/src/features/panes/pane-store.ts`, `pane-root.tsx`, `pane-container.tsx`, `pane-route-renderer.tsx`
- Direct inspection: `apps/workbench/src/features/activity-bar/`, `right-sidebar/`, `bottom-pane/`
- Direct inspection: `apps/workbench/src/components/desktop/workbench-routes.tsx`
- Direct inspection: huntronomer source — `spirit/types.ts`, `spirit/fieldStain.ts`, `observatorySeam.ts`
- Direct inspection: huntronomer source — `features/hunt-observatory/types.ts`, `world/ObservatoryWorldCanvas.tsx` (imports)
- Direct inspection: huntronomer source — `features/cyber-nexus/CyberNexusView.tsx`, `components/NexusCanvas.tsx`
- Direct inspection: huntronomer source — `features/forensics/ForensicsRiverView.tsx`
- Direct inspection: huntronomer source — `spirit-ritual/canvas/SpiritManifestationCanvas.tsx`
- Direct inspection: huntronomer source — `apps/desktop/package.json` for R3F package versions
- Confidence: HIGH — all findings from first-party source code, no external sources required

---
*Architecture research for: 3D R3F integration into VS Code-like Tauri workbench*
*Researched: 2026-03-18*
