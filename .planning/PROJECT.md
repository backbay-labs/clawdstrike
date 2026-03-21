# ClawdStrike Workbench IDE

## What This Is

ClawdStrike Workbench is a Tauri 2 + React 19 desktop security IDE with an immersive 3D observatory space flight experience. Operators author policies, run simulations, and investigate hunts in a VS Code-like pane system — then fly a ship through a space environment to navigate between observatory stations, discover threats, and follow mission-guided investigation paths.

## Core Value

Security operators work across multiple views simultaneously with a spirit-driven immersive layer — flying between floating space stations in an observatory that makes threat investigation feel like exploration.

## Requirements

### Validated

- ✓ Activity bar + sidebar shell — v1.0
- ✓ Binary tree pane system with split/close/resize — v1.0
- ✓ Bottom pane with Terminal, Problems, Output tabs — v1.0
- ✓ 11 Zustand stores with createSelectors pattern — v1.0
- ✓ Command registry with 50+ commands and Cmd+K palette — v1.0
- ✓ Explorer panel with detection project file tree — v1.0
- ✓ Speakeasy Ed25519-signed chat panel — v1.0
- ✓ 19 routable page components (all existing features) — v1.0
- ✓ Multi-policy store decomposition (3 Zustand stores + bridge) — v1.0
- ✓ In-file search (Cmd+F, Cmd+H) — v1.1
- ✓ Global search (Cmd+Shift+F) with results panel — v1.1
- ✓ File tree mutations (create, rename, delete, status indicators) — v1.1
- ✓ Tab overflow scrolling, context menu, terminal splits — v1.1
- ✓ Spirit + observatory Zustand stores, CSS field stain, accent color, seam badges — v2.0
- ✓ R3F infrastructure, spirit companion mini-canvas, spirit chamber pane tab — v2.0
- ✓ Observatory world as full editor pane (atlas + flow modes), probe commands — v2.0
- ✓ Cyber nexus Hunt Deck pane tab, spirit creation chamber — v2.0
- ✓ Spirit mood reactivity, editor palette shifting, observatory minimap — v3.0
- ✓ Observatory GLB hero props, spirit affinity rings — v3.0
- ✓ Spirit XP evolution with persistent progression, level-gated geometry layers — v3.0
- ✓ Multi-station probe missions with HUD, evidence 3D preview — v3.0
- ✓ Nexus force-directed graph with physics clustering — v3.0
- ✓ Post-processing pipeline (bloom, vignette, SMAA, DOF, LUT per spirit) — v4.0
- ✓ Camera cinematics (fly-by, dynamic FOV, screen shake, mission focus pull) — v4.0
- ✓ Particle effects (landing dust, probe discharge, station motes, spirit trail, thruster exhaust) — v4.0
- ✓ Character polish (locomotion blending, squash-stretch, breathing, sprint lean) — v4.0
- ✓ World detail (HDR skybox, procedural districts, env props, 24 NPC crew, 3D beacons, tooltips) — v4.0
- ✓ Explainability + multi-lane pressure + smoothing/hysteresis — v5.0
- ✓ Guided probes + compound missions + analyst presets — v5.0
- ✓ Replay intelligence + cooperative timeline markers — v5.0
- ✓ Runtime decomposition + event-driven invalidation + LOD + resource pooling — v5.0
- ✓ Cinematic context + ghost memory + hunt weather — v5.0
- ✓ Space-scale world (300-unit radius, WebGPU renderer, logarithmic depth buffer) — v6.0
- ✓ Ship flight controller (velocity+quaternion, 3 speed tiers, chase camera, thruster VFX) — v6.0
- ✓ Space environment art (Star Nest starfield, nebula clouds, space lanes, depth fog) — v6.0
- ✓ Station LOD + Fresnel glow + docking rings + three-zone docking system — v6.0
- ✓ Space flight HUD (speed bar, compass, brackets, arrows, distance — 60fps ref-mutation) — v6.0
- ✓ Star chart minimap + click-to-autopilot + boost transitions + arrival cinematics — v6.0
- ✓ Progressive station discovery + mission waypoint trails + narrative flight — v6.0
- ✓ Clean cockpit HUD — glassmorphism status strip, left drawer, hotkey panel switching — v7.0
- ✓ Panel registry with mutual exclusion + analyst preset toggle segments — v7.0
- ✓ Four rebuilt analyst panels (Explainability, Mission, Replay, Ghost Memory) — v7.0
- ✓ Flight HUD glassmorphism restyle + repositioning — v7.0

### Active

### Out of Scope

- Full VS Code extension API — overkill; MCP plugin is the right model
- Tree-sitter code editor — CodeMirror + schema-aware completions is correct for YAML/Sigma/YARA
- Vim emulation — not needed for security policy editing
- Full file system abstraction — workbench has its own DetectionProject tree
- Database viewer — irrelevant to security policy IDE
- AI chat side panel — ClawdStrike is the security layer, not an agent (Speakeasy is operator chat)
- VR/XR support — desktop-first; VR deferred indefinitely
- Full Newtonian physics — arcade flight feel better for analyst tool
- Combat/weapons — observatory is investigation, not combat
- Procedural planet generation — stations are the destination, not planets
- Real GLTF station models (v6.0) — procedural primitives first; GLBs are v7.0 polish
- Multiple camera modes — chase camera only for v6.0; cockpit view deferred

## Context

### Shipped State (v6.0)
- 59 files modified, +10,365 / -2,112 LOC in v6.0 alone
- Tech stack: Tauri 2, React 19, TypeScript, Zustand, React Three Fiber 9, drei 10, wawa-vfx, three 0.171+
- WebGL2 renderer with logarithmic depth buffer (WebGPU deferred — postprocessing library incompatibility)
- 40 v6.0 requirements fully satisfied (audit passed)
- 7 milestones shipped (v1.0 IDE Pivot, v2.0 Huntronomer Integration, v3.0 Spirit & Observatory Evolution, v4.0 AAA Observatory Experience, v5.0 Observatory Analyst Experience, v6.0 Observatory Space Flight)

### Huntronomer Source
Source 3D code lives in `clawdstrike-worktrees/huntronomer-workspace-orch` (branch `feature/huntronomer-workspace-orchestrator`, committed @ `1586fe2a1`).

### Two App Architectures
- `apps/desktop/` — Old huntronomer shell (NavRail + plugins, session-based, has all 3D features)
- `apps/workbench/` — New IDE workbench (ActivityBar + SidebarPanel + PaneRoot + BottomPane + StatusBar)

### Design System
- shadcn/ui primitives (16 components in components/ui/)
- Tailwind CSS, dark theme only
- React Three Fiber 9 + drei 10 + wawa-vfx for 3D
- Monospace typography throughout

## Constraints

- **Framework**: Tauri 2 + React 19 + TypeScript — existing stack, no changes
- **State**: Zustand + immer — already migrated, no going back to Context
- **Routing**: HashRouter required for Tauri file:// protocol
- **Terminal**: ghostty-web + PTY — existing integration
- **Graph**: @xyflow/react — existing swarm board integration
- **Editor**: CodeMirror — existing policy editor integration
- **Renderer**: three 0.171+ with WebGL2 + logarithmic depth buffer (WebGPU deferred until postprocessing supports it)
- **Compatibility**: All existing routes must remain reachable
- **Testing**: All existing tests must pass after each phase

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Activity bar + sidebar panels (not redesigned nav) | VS Code model proven; reuses existing sigil icons | ✓ Good |
| Current routes become "apps" (zero page component changes) | Minimizes risk; pages render in panes instead of full-page | ✓ Good |
| Sidebar panels are lightweight summaries, not full pages | Full dashboards open as editor tabs; sidebar for glance-and-navigate | ✓ Good |
| Observatory as TAB/PANE not a panel | Like VS Code Markdown Preview — full pane view, not squeezed sidebar | ✓ Good |
| Character controller is opt-in Easter-egg | Only in observatory tab flow mode; not default experience | ✓ Good |
| Mini R3F canvas in right sidebar | Right sidebar already has resize handle; spirit companion fits naturally | ✓ Good |
| 2 new Zustand stores (spirit-store, observatory-store) | Minimal new state surface; typed spirit/observatory state | ✓ Good |
| Velocity-based flight (no Rapier) | Simpler, more controllable, no overhead for zero-G arcade feel | ✓ Good |
| WebGPU renderer with WebGL2 fallback | Future-proof; three 0.171+ one-liner swap; existing materials work as-is | ✓ Good |
| DOM-based HUD (not R3F overlays) | 60fps ref-mutation avoids React re-renders; CSS overlay doesn't fight Canvas | ✓ Good |
| Three-zone docking system | Approach→magnet-pull→dock-lock feels natural; avoids binary snap | ✓ Good |
| Star chart replaces SVG ring minimap | Space-scale positions need real XZ mapping; click-to-autopilot needs dots | ✓ Good |
| Progressive station discovery (session-only) | Rewards exploration without persistent state complexity | ✓ Good |

---
*Last updated: 2026-03-21 after v7.0 Observatory Production HUD milestone completion*
