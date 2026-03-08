# Huntronomer Swarm Execution Plan

> **Status:** Historical | **Date:** 2026-03-07
> **Purpose:** Historical reference for the earlier Huntronomer surface-refactor swarm
> **Metadata status:** Superseded by `docs/plans/clawdstrike/huntronomer/workspace-shell/swarm-plan.md`

This plan captured the earlier Huntronomer surface-refactor swarm. It remains useful as historical
context for the Wire, Huntboard, Vault, and trust-surface rollout, but the active `.codex/swarm`
metadata now points at the workspace-shell initiative.

## 1. Execution Goal

Execute the Huntronomer desktop refactor end to end without a single giant branch and without
letting multiple workers collide in shared shell files.

The active swarm topology follows five rules:

1. The Huntronomer event model lands before most surface work.
2. Shared shell registration and route wiring stay orchestrator-owned.
3. Surface lanes work mostly in new feature folders or tightly bounded existing folders.
4. Proof and huntboard integration advance in parallel only after projection contracts are stable.
5. Final cross-surface verification waits until Wire, Huntboard, Vault, and trust surfaces all
   exist.

## 2. Orchestrator-Owned Shared Files

These files stay under `ORCH` ownership to avoid high-conflict merges:

- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`
- `docs/plans/clawdstrike/huntronomer/**`
- `apps/desktop/src/shell/ShellApp.tsx`
- `apps/desktop/src/shell/ShellLayout.tsx`
- `apps/desktop/src/shell/plugins/registry.tsx`
- `apps/desktop/src/styles.css`
- repo-level verification and release wiring such as `.github/workflows/**`, `mise.toml`, and
  package-level verification scripts

Worker lanes may create new files that are later imported by these shared files, but they should
leave the final shared-file integration to `ORCH`.

## 3. Lane Map

| Lane | Purpose | Owned Paths | Depends On | Verification |
| --- | --- | --- | --- | --- |
| `ORCH` | shared wiring, merge sequencing, wave advancement, final integration | `.codex/swarm/**`, `docs/plans/clawdstrike/huntronomer/**`, shared shell files listed above | none | `git diff --stat`, `bun run typecheck`, `bun run build` after each merge wave |
| `H1` | shell IA and design foundation | `apps/desktop/src/shell/components/NavRail.tsx`, `apps/desktop/src/shell/components/CommandPalette.tsx`, `apps/desktop/src/shell/components/ProfileMenu.tsx`, `apps/desktop/src/shell/components/TopCommandStrip.tsx`, `apps/desktop/src/theme/**` | `ORCH` | `cd apps/desktop && bun run typecheck` |
| `H2` | Huntronomer domain model and fixtures | `apps/desktop/src/domain/huntronomer/**`, `apps/desktop/src/features/wire/lib/**`, `apps/desktop/src/test/fixtures/huntronomer/**` | `ORCH` | `cd apps/desktop && bun run typecheck` |
| `H3` | Signal Wire surface | `apps/desktop/src/features/wire/**` | `H1`, `H2` | `cd apps/desktop && bun run typecheck` |
| `H4` | transport projection adapters for daemon and OpenClaw data | `apps/desktop/src/services/eventStream.ts`, `apps/desktop/src/services/openclaw/gatewayClient.ts`, `apps/desktop/src/services/huntronomerProjection.ts`, `apps/desktop/src/context/OpenClawContext.tsx`, `apps/desktop/src/types/events.ts` | `H2` | `cd apps/desktop && bun run typecheck` |
| `H5` | Huntboard composition and forensics migration | `apps/desktop/src/features/huntboard/**`, `apps/desktop/src/features/forensics/**`, `apps/desktop/src/features/cyber-nexus/**`, `apps/desktop/src/features/openclaw/**` | `H2`, `H3`, `H4` | `cd apps/desktop && bun run typecheck && bun run build` |
| `H6` | Receipt Vault / Replay and proof UI integration | `apps/desktop/src/features/events/**`, `apps/desktop/src/features/vault/**`, `apps/desktop/src/features/replay/**`, `apps/desktop/src/services/tauri.ts`, `apps/desktop/src-tauri/src/commands/receipts.rs` | `H2`, `H4` | `cd apps/desktop && bun run typecheck && cargo check --manifest-path src-tauri/Cargo.toml` |
| `H7` | Cases, profile, and watchlists | `apps/desktop/src/features/cases/**`, `apps/desktop/src/features/profile/**`, `apps/desktop/src/features/watchlists/**` | `H2`, `H3`, `H5`, `H6` | `cd apps/desktop && bun run typecheck && bun run build` |
| `H8` | integration verification, fixtures, and route/handoff tests | `apps/desktop/src/**/*.test.ts`, `apps/desktop/src/**/*.test.tsx`, `apps/desktop/vitest.config.ts` | `H3`, `H5`, `H6`, `H7` | `cd apps/desktop && bun run test && bun run typecheck && bun run build` |

## 4. Ticket Breakdown

### ORCH

- `ORCH-T1`: keep docs, lanes, and waves aligned with the live program
- `ORCH-T2`: integrate worker output into shared shell files and route registry
- `ORCH-T3`: enforce merge order, review gates, and end-of-wave verification

### H1

- `H1-T1`: build the Huntronomer top command strip and shell destination model
- `H1-T2`: refactor the rail and command palette to match `Wire / Huntboard / Vault / Cases / Profile / Settings`
- `H1-T3`: establish dedicated Huntronomer theme assets and shell-level visual tokens

### H2

- `H2-T1`: implement Spec 16 core types, envelopes, and action vocabulary
- `H2-T2`: add launch-context, proof-link, and future-compatible placeholder models for `Case`, `ProfileRecord`, and watchlist scopes
- `H2-T3`: add selectors and fixture-backed mock data for `Signal`, `Hunt`, `Receipt`, and `Brief`

### H3

- `H3-T1`: scaffold `WireView` and the typed feed from fixtures
- `H3-T2`: add keyboard selection, right context pane, and row-level actions
- `H3-T3`: add watchlists pane, filter strip, and pulse tape

### H4

- `H4-T1`: project daemon audit events into normalized proof-oriented envelopes
- `H4-T2`: project OpenClaw runtime into `SwarmRun` and live `Hunt` summaries
- `H4-T3`: make stale, degraded, and partial-proof states explicit in adapter outputs

### H5

- `H5-T1`: carve a `features/huntboard/**` shell around the current forensics river
- `H5-T2`: migrate `ForensicsRiverView` and related overlays into Huntboard subviews
- `H5-T3`: accept `HuntLaunchContext` and wire in operator sidecars, approvals, and runtime summaries

### H6

- `H6-T1`: replace placeholder receipt verification UI with live Tauri-backed proof actions
- `H6-T2`: build `Vault` and `Replay` surfaces around normalized receipt models
- `H6-T3`: add compare, replay, and deep-link entry points for proof flows

### H7

- `H7-T1`: implement Cases and the `Promote` flow from Huntboard or Wire
- `H7-T2`: implement Profile and Watchlists surfaces with persisted scope state
- `H7-T3`: wire `Validate`, `Challenge`, `Watch`, and `Cite` affordances into trust-bearing surfaces

### H8

- `H8-T1`: add fixture-driven tests for domain models and Wire rendering
- `H8-T2`: add route and handoff tests for `Wire -> Huntboard -> Vault`
- `H8-T3`: run final desktop verification and fix integration regressions

## 5. Dependency Graph

### Workstream Graph

```text
ORCH
├── H1
├── H2
│   ├── H3
│   ├── H4
│   └── H6
│       └── H7
├── H3
│   ├── H5
│   ├── H7
│   └── H8
├── H4
│   ├── H5
│   └── H6
├── H5
│   ├── H7
│   └── H8
├── H6
│   ├── H7
│   └── H8
└── H7
    └── H8
```

### Critical Ticket Edges

- `H2-T1 -> H3-T1`: the Wire cannot render canonical objects before the object model exists
- `H2-T2 -> H5-T3`: Huntboard launch depends on the normalized launch context contract
- `H2-T3 -> H3-T1`: the first Wire pass should use shared fixtures, not ad hoc view-local data
- `H4-T1 -> H6-T2`: Vault and Replay need normalized proof inputs before UI hardening
- `H4-T2 -> H5-T3`: Huntboard operator sidecars depend on projected swarm summaries
- `H3-T2 -> H5-T3`: Huntboard source context should come from real Wire row actions
- `H5-T3 -> H7-T1`: the `Promote` flow depends on Huntboard having a stable contextual hunt record
- `H6-T3 -> H7-T3`: citation and validation affordances depend on proof deep links
- `H3/H5/H6/H7 -> H8`: final test coverage only makes sense after the core surfaces exist

## 6. Wave Plan

| Wave | Lanes | Goal | Advance Gate |
| --- | --- | --- | --- |
| `wave0` | `ORCH` | freeze topology, seed metadata, and protect shared files | docs and swarm metadata committed |
| `wave1` | `H1`, `H2` | shell/design foundation plus domain contract | both lanes reviewed; no shared-file edits leaked |
| `wave2` | `H3`, `H4` | first Wire surface plus transport projections | typed Wire renders from fixtures; adapters compile cleanly |
| `wave3` | `H5`, `H6` | Huntboard and proof surfaces | contextual Huntboard path and live receipt verification both work |
| `wave4` | `H7` | durable memory and trust layer | Promote/Profile/Watch flows are wired without breaking core surfaces |
| `wave5` | `H8` | final verification and bug sweep | test/build/typecheck and Tauri smoke pass |

## 7. Why This Graph Is Valid

The dependency graph has been shaped to remove the main conflict points in the current desktop app:

1. The monolithic shell wiring is serialized under `ORCH`, so no two worker lanes fight over
   `ShellApp.tsx`, `ShellLayout.tsx`, `registry.tsx`, or `styles.css`.
2. `H2` lands the object model before any lane depends on it for rendering, projection, or proof
   linkage.
3. `H3` and `H4` can run in parallel because one owns the Wire surface and the other owns the
   transport projections.
4. `H5` and `H6` can run in parallel because Huntboard and Vault own different feature trees and
   meet through the stable contracts defined by `H2` and `H4`.
5. `H7` waits until Promote, proof links, and hunt context are real, which prevents the trust layer
   from being built on placeholders.
6. `H8` is last because integration tests are the place where cross-surface assumptions should be
   proven, not guessed at early.

## 8. Launch Sequence

Seed worktrees:

```bash
scripts/codex-swarm/setup-worktrees.sh orch h1 h2 h3 h4 h5 h6 h7 h8
scripts/codex-swarm/bootstrap-lane.sh h1 h2 h3 h4 h5 h6 h7 h8
```

Launch waves deliberately:

```bash
scripts/codex-swarm/launch-wave.sh wave0 \
  --note "Keep Huntronomer shared shell wiring and swarm metadata under ORCH ownership."

scripts/codex-swarm/launch-wave.sh wave1 \
  --note "Land the shell foundation and Spec 16 domain contract without touching shared shell files."
```

Then continue with `wave2` through `wave5`, only after review and merge gates pass.

## 9. Lane Handoff Rules

- Every worker lane leaves a handoff with changed files, commands run, and unresolved items.
- Worker lanes do not edit orchestrator-owned shared files.
- If a worker absolutely must change a shared file to validate locally, it should leave that change
  unstaged or document the exact patch for `ORCH` to apply.
- `ORCH` runs the merge-review pass before advancing a wave.
