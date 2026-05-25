# Tauri Default Icons — Pending Decision

**Verified on:** 2026-05-24
**Branch:** `cleanup/waves-abce`

## Current State

Three Tauri apps in `apps/` ship with the **default Tauri "T" placeholder
icon set**, byte-identical across all three apps:

| App | `productName` | `identifier` |
| --- | --- | --- |
| `apps/agent/src-tauri` | `Clawdstrike Agent` | `dev.clawdstrike.agent` |
| `apps/desktop/src-tauri` | `Huntronomer` | `com.backbaylabs.clawdstrike.desktop` |
| `apps/workbench/src-tauri` | `ClawdStrike Workbench` | `com.clawdstrike.workbench` |

### MD5 verification (every icon is identical across the three apps)

```
icon.png      9418b9b0e421e3ff0744aef7960f511c  (210,547 bytes)
icon.icns     65b5ef45ccb2efc1cd05fdf5d1e8b856  (809,117 bytes)
32x32.png     332a56695e4931ea0747be607be6014a  ( 2,428 bytes)
```

Same pattern holds for `64x64.png`, `128x128.png`, `128x128@2x.png`,
and `icon.ico` — all three apps carry byte-identical copies of the
Tauri scaffold's default "T" sigil.

## Why This Matters

Per Tauri convention, each app's `tauri.conf.json` declares its icon
manifest under `bundle.icon[]` (verified at
`apps/agent/src-tauri/tauri.conf.json:20-27` and matching siblings).
The bundler embeds these icons into:

- macOS: `.icns` (Dock, Finder, About panel)
- Windows: `.ico` (taskbar, Start menu, .exe icon)
- Linux: `.png` set (window manager, .desktop file)

Three differently-named apps shipping the same Tauri "T" icon is an
immediately-visible quality problem at runtime: users opening the Dock
or taskbar see three identical "T" tiles labeled "Agent", "Huntronomer",
and "Workbench". This is a launch-blocker for any production release
that lists more than one of these apps in a release artifact.

## Required For Production

Per the Tauri icon convention, each shipping app needs the following
seven files in its `src-tauri/icons/` directory:

| File | Purpose |
| --- | --- |
| `icon.png` | Source mark, used by Tauri to fan out other formats |
| `icon.icns` | macOS bundle |
| `icon.ico` | Windows bundle |
| `32x32.png` | Small UI icon |
| `64x64.png` | Medium UI icon |
| `128x128.png` | Large UI icon |
| `128x128@2x.png` | Large UI icon, 2x DPI |

So replacement scope is **~7 files × 3 apps = 21 files** if each app
gets a distinct brand mark, or **7 files** if the apps consolidate to
a single unified mark (then duplicated into each app's icons/).

## Decisions Needed From the User

1. **Which shipping apps survive?**
   - `apps/agent` — Clawdstrike Agent (system-extension host)
   - `apps/desktop` — Huntronomer (3D nexus dashboard)
   - `apps/workbench` — ClawdStrike Workbench (policy/IDE workbench)
   If any of these is being deprecated, only the survivors need icons.

2. **Where are the brand assets?**
   No `*.svg`, `*.ai`, `*.afdesign`, `*.figma`, or other source files
   for a ClawdStrike claw/strike mark were found anywhere under
   `apps/`, `infra/`, `docs/`, or `packages/` on this branch (verified
   via `find` for `claw`, `sigil`, `brand`, and `logo` patterns). The
   `chore/cleanup-tier-ab` branch carries commit `645c38501`
   (`chore(brand): replace default Tauri 'T' icons with ClawdStrike
   claw sigil`) — that commit may contain the source asset and the
   per-app icon outputs. **Action:** confirm whether the user wants
   to cherry-pick that commit (see `CLEANUP-BRANCHES-RECOMMENDATIONS.md`)
   or wants a fresh brand mark.

3. **Per-app mark or single unified mark?**
   - **Per-app marks:** distinct visual identity for Agent vs.
     Huntronomer vs. Workbench. Costs more design time but lets users
     distinguish them at a glance in the Dock/taskbar. Matches the
     reality that they are functionally different apps with different
     `productName` values.
   - **Single unified mark:** one ClawdStrike mark used by all three.
     Cheapest path. Users would still see "Agent", "Huntronomer", and
     "Workbench" labels under identical icons in the Dock — same
     quality problem as today but with a real mark instead of "T".

## Recommended Path

If the user has no specific brand work in progress:

- **Cheap, ship-blocking only:** cherry-pick `645c38501` from
  `chore/cleanup-tier-ab` to take the claw-sigil mark across all
  three apps. This unblocks releases at the cost of three apps
  sharing one mark.
- **Right thing:** design three distinct marks (one per `productName`)
  with a shared visual system. Out of scope for the cleanup wave.

Either way, **this is not something the wave-C agent should do
unilaterally** — picking a brand mark is a product decision that
belongs to the user.
