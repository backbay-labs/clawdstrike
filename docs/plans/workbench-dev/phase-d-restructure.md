# Phase D: Directory Restructure

> Week 7-8 — Feature-based organization, move 106 top-level files + 3 subdirectories (216 total files) from lib/workbench/ to features/

## Prerequisites

- Phase B complete (all stores are Zustand — files are ready to move)
- Phase C complete (pane + bottom-pane features already in `features/`)

---

## Current State

`apps/workbench/src/lib/workbench/` contains **106 top-level files** plus 3
subdirectories:

- `__tests__/` — 73 test files
- `detection-workflow/` — 30 files (adapters, stores, hooks, types for the detection
  workflow pipeline)
- `redteam/` — 7 files (red-team scenario generation, grading, risk scoring)

Total: **216 files** across the directory tree.

```
lib/workbench/
├── multi-policy-store.tsx      (store)
├── policy-store.tsx            (store)
├── swarm-board-store.tsx       (store)
├── sentinel-store.tsx          (store)
├── finding-store.tsx           (store)
├── intel-store.tsx             (store)
├── signal-store.tsx            (store)
├── mission-store.tsx           (store)
├── operator-store.tsx          (store)
├── reputation-store.tsx        (store)
├── project-store.tsx           (store)
├── swarm-store.tsx             (store)
├── swarm-feed-store.tsx        (store)
├── sentinel-manager.ts         (engine)
├── sentinel-types.ts           (types)
├── finding-engine.ts           (engine)
├── finding-constants.ts        (constants)
├── hunt-engine.ts              (engine)
├── hunt-types.ts               (types)
├── intel-forge.ts              (engine)
├── fleet-client.ts             (api)
├── fleet-url-policy.ts         (util)
├── force-graph-engine.ts       (engine)
├── hierarchy-engine.ts         (engine)
├── mission-control.ts          (engine)
├── mission-runtime.ts          (engine)
├── mission-manager.ts          (engine)
├── mission-types.ts            (types)
├── yaml-utils.ts               (util)
├── yaml-schema.ts              (util)
├── sigma-schema.ts             (util)
├── sigma-types.ts              (types)
├── sigma-templates.ts          (data)
├── use-auto-save.ts            (hook)
├── use-fleet-connection.ts     (hook)
├── use-general-settings.ts     (hook)
├── use-hint-settings.ts        (hook)
├── use-mcp-status.ts           (hook)
├── use-motion-config.ts        (hook)
├── use-native-validation.ts    (hook)
├── yara-language.ts            (language def)
├── yara-templates.ts           (data)
├── detection-workflow/          (30 files — pipeline adapters, stores, hooks)
├── redteam/                     (7 files — scenario gen, grading, risk scoring)
├── __tests__/                   (73 test files)
├── ... 60+ more files
```

Finding related files requires knowing the naming convention. No co-location of
stores with their consumers, types with their engines, or hooks with their features.

---

## Target Structure

Notes on naming: Store files that are currently `.tsx` (because they use React hooks
or JSX) keep their `.tsx` extension. The Phase B Zustand migration may convert some to
`.ts`, but this mapping uses the current extension. Files listed under `stores/` that
do not currently exist (marked with `# Phase B decomposition target`) will be created
during Phase B when `multi-policy-store.tsx` is decomposed.

```
src/features/
├── policy/                          # Policy editing (from multi-policy-store decomposition)
│   ├── stores/
│   │   ├── multi-policy-store.tsx   # existing — primary store until Phase B decomposition
│   │   ├── policy-store.tsx         # existing
│   │   ├── policy-tabs-store.ts     # Phase B decomposition target (does not exist yet)
│   │   ├── policy-edit-store.ts     # Phase B decomposition target (does not exist yet)
│   │   └── workbench-ui-store.ts    # Phase B decomposition target (does not exist yet)
│   ├── types.ts                     # WorkbenchPolicy, PolicyTab, etc.
│   ├── yaml-utils.ts
│   ├── yaml-schema.ts
│   ├── policy-catalog.ts
│   ├── builtin-rulesets.ts
│   ├── use-auto-version.ts
│   ├── use-auto-save.ts
│   └── use-native-validation.ts
│
├── detection/                       # Detection file types (Sigma, YARA, OCSF)
│   ├── file-type-registry.ts
│   ├── sigma-schema.ts
│   ├── sigma-types.ts
│   ├── sigma-templates.ts
│   ├── ocsf-schema.ts
│   ├── suite-parser.ts
│   ├── yara-language.ts
│   ├── yara-templates.ts
│   ├── stores/
│   │   ├── test-store.tsx
│   │   └── test-history-store.ts
│   ├── native-simulation.ts
│   └── observe-synth-engine.ts
│
├── detection-workflow/              # Detection workflow pipeline (existing subdir)
│   ├── adapters.ts
│   ├── coverage-gap-engine.ts
│   ├── coverage-projection.ts
│   ├── document-identity-store.ts
│   ├── draft-generator.ts
│   ├── draft-mappers.ts
│   ├── evidence-pack-store.ts
│   ├── evidence-redaction.ts
│   ├── execution-types.ts
│   ├── explainability.ts
│   ├── index.ts
│   ├── lab-run-store.ts
│   ├── ocsf-adapter.ts
│   ├── policy-adapter.ts
│   ├── publication-provenance.ts
│   ├── publication-store.ts
│   ├── shared-types.ts
│   ├── sigma-adapter.ts
│   ├── sigma-conversion.ts
│   ├── swarm-detection-nodes.ts
│   ├── swarm-receipt-linking.ts
│   ├── swarm-session-templates.ts
│   ├── use-coverage-gaps.ts
│   ├── use-draft-detection.ts
│   ├── use-evidence-packs.ts
│   ├── use-lab-execution.ts
│   ├── use-publication.ts
│   ├── use-published-coverage.ts
│   ├── use-swarm-launch.ts
│   └── yara-adapter.ts
│
├── redteam/                         # Red-team scenarios (existing subdir)
│   ├── coverage-bridge.ts
│   ├── framework-mappings.ts
│   ├── grading.ts
│   ├── plugin-registry.ts
│   ├── risk-scoring.ts
│   ├── scenario-generator.ts
│   └── types.ts
│
├── sentinels/                       # Sentinel management
│   ├── stores/sentinel-store.tsx
│   ├── sentinel-manager.ts
│   ├── sentinel-types.ts
│   └── signal-pipeline.ts
│
├── findings/                        # Findings & intel
│   ├── stores/
│   │   ├── finding-store.tsx
│   │   ├── signal-store.tsx
│   │   └── intel-store.tsx
│   ├── finding-engine.ts
│   ├── finding-constants.ts
│   ├── intel-forge.ts
│   └── cross-reference.ts
│
├── fleet/                           # Fleet connection & management
│   ├── stores/
│   │   └── fleet-connection-store.ts  # Phase B decomposition target (does not exist yet)
│   ├── fleet-client.ts
│   ├── fleet-url-policy.ts
│   ├── http-transport.ts
│   ├── idp-federation.ts
│   └── use-fleet-connection.ts
│
├── swarm/                           # Swarm board & orchestration
│   ├── stores/
│   │   ├── swarm-store.tsx
│   │   ├── swarm-board-store.tsx
│   │   ├── swarm-feed-store.tsx
│   │   └── sdk-script-store.ts
│   ├── swarm-coordinator.ts
│   ├── swarm-protocol.ts
│   ├── swarm-sync.ts
│   ├── swarm-trust-policy.ts
│   ├── swarm-blob-client.ts
│   ├── swarm-board-types.ts
│   └── script-dry-runner.ts
│
├── missions/                        # Mission control
│   ├── stores/mission-store.tsx
│   ├── mission-control.ts
│   ├── mission-manager.ts
│   ├── mission-runtime.ts
│   └── mission-types.ts
│
├── hunt/                            # Hunt engine
│   ├── hunt-engine.ts
│   ├── hunt-types.ts
│   ├── threat-matrix-data.ts
│   └── mitre-attack-data.ts
│
├── topology/                        # Topology & delegation
│   ├── force-graph-engine.ts
│   ├── hierarchy-engine.ts
│   ├── hierarchy-types.ts
│   ├── delegation-types.ts
│   ├── delegation-demo-data.ts
│   └── scenario-graph-engine.ts
│
├── compliance/                      # Compliance dashboard
│   ├── compliance-requirements.ts
│   ├── coverage-analyzer.ts
│   └── report-generator.ts
│
├── approvals/                       # Approval workflows
│   ├── approval-types.ts
│   └── approval-demo-data.ts
│
├── operator/                        # Operator identity & crypto
│   ├── stores/
│   │   ├── operator-store.tsx
│   │   └── reputation-store.tsx
│   ├── operator-crypto.ts
│   ├── operator-types.ts
│   └── reputation-tracker.ts
│
├── settings/                        # Settings & preferences
│   ├── stores/
│   │   ├── general-settings-store.ts  # Phase B decomposition target (does not exist yet)
│   │   └── hint-settings-store.ts     # Phase B decomposition target (does not exist yet)
│   ├── use-general-settings.ts
│   ├── use-hint-settings.ts
│   ├── use-motion-config.ts
│   └── secure-store.ts
│
├── project/                         # Detection project management
│   ├── stores/project-store.tsx
│   ├── catalog-deps.ts
│   ├── detection-mcp-tools.ts
│   └── use-mcp-status.ts
│
├── origin/                          # Origin enclaves
│   ├── origin-options.ts
│   └── origin-profile-utils.ts
│
├── receipts/                        # Receipt persistence
│   └── use-persisted-receipts.ts
│
├── panes/                           # (Created in Phase C)
│   └── ...
│
├── bottom-pane/                     # (Created in Phase C)
│   └── ...
│
├── terminal/                        # Terminal service
│   ├── terminal-service.ts
│   └── use-terminal-sessions.ts
│
├── speakeasy/                       # Speakeasy bridge
│   └── speakeasy-bridge.ts
│
├── trustprint/                      # Trustprint screening
│   ├── trustprint-connection.ts
│   ├── trustprint-patterns.ts
│   └── trustprint-screening.ts
│
└── shared/                          # Truly shared utilities
    ├── format-utils.ts
    ├── storage-sanitizer.ts
    ├── version-store.ts
    ├── version-diff.ts
    ├── use-guard-order.ts
    ├── use-version-history.ts
    ├── guard-registry.ts
    ├── local-audit.ts
    ├── pre-built-scenarios.ts
    ├── scenario-generator.ts
    ├── simulation-engine.ts
    ├── signature-adapter.ts
    ├── hushd-event-simulator.ts
    ├── invitation-manager.ts
    └── traffic-replay.ts
```

### Cross-Feature Dependencies

Some features depend on types/functions from other features. These are not circular
and flow in one direction, but they mean import paths will cross feature boundaries:

- `findings/` imports from `hunt/` (hunt-types) and `sentinels/` (sentinel-types)
- `missions/` imports from `sentinels/` (sentinel-types, sentinel-manager)
- `missions/` imports from `hunt/` (hunt-types via mission-control)
- `swarm/` imports from `sentinels/` (sentinel-types)
- `speakeasy/` imports from `operator/` (operator-crypto, operator-types) and `sentinels/`
- `signal-store` (findings/) imports from `fleet/` (fleet-client) and `hunt/` (hunt-types)

None of these form cycles. The dependency direction is:
`hunt/`, `operator/` (leaf) <- `sentinels/` <- `findings/`, `missions/`, `swarm/`, `speakeasy/`

---

## Migration Strategy

### Step 1: Create Feature Directories

Create all `features/` directories with empty `index.ts` barrel files.

Barrel re-exports work with the current Vite build setup. The `vite.config.ts` already
uses `manualChunks` for vendor splitting and Vite's Rollup-based bundler handles
`export { X } from "./Y"` re-exports via tree-shaking. However, avoid deep barrel
chains (barrel importing from barrel) as they can defeat Vite's HMR granularity —
keep barrels shallow (one level).

### Step 2: Move Files with Barrel Re-exports

For each file moved, add a re-export in the old location:

```typescript
// lib/workbench/sentinel-store.tsx (old location, kept temporarily)
export { useSentinelStore } from "@/features/sentinels/stores/sentinel-store";
```

This ensures existing imports don't break during migration.

### Step 3: Batch Update Imports

Use a codemod or IDE refactoring to update all import paths from
`@/lib/workbench/X` to `@/features/domain/X`.

The `@/*` path alias in `tsconfig.json` maps to `./src/*`, and Vite's `resolve.alias`
in `vite.config.ts` maps `@` to `resolve(__dirname, "src")`. Both already support the
`@/features/` prefix with no configuration changes.

```bash
# Example: find and replace sentinel-store imports
find apps/workbench/src -name "*.tsx" -o -name "*.ts" | \
  xargs sed -i '' 's|@/lib/workbench/sentinel-store|@/features/sentinels/stores/sentinel-store|g'
```

Note: The `detection-workflow/` and `redteam/` subdirectories already have internal
relative imports. When moved to `features/detection-workflow/` and `features/redteam/`,
their internal imports remain valid — only external consumers need path updates.

### Step 4: Verify with TypeScript Compiler

```bash
cd apps/workbench && npx tsc --noEmit
```

### Step 5: Remove Old Re-exports

Once all imports point to the new locations, delete the re-export shims in
`lib/workbench/`.

### Step 6: Clean Up lib/workbench/

After migration, `lib/workbench/` should contain only:
- `types.ts` (if shared across features)
- Any files that genuinely don't belong to a feature

Target: **< 10 files** remaining in `lib/workbench/`.

---

## Component Directory Alignment

The `components/workbench/` directory should also be restructured to align with
`features/`. Currently it has 35+ subdirectories. The page-level components should
move to their corresponding feature:

```
// Before
components/workbench/sentinel-swarm-pages.tsx  → features/sentinels/pages/
components/workbench/fleet/fleet-dashboard.tsx  → features/fleet/pages/
components/workbench/compliance/                → features/compliance/pages/
```

This is a large rename and can be done incrementally after the `lib/workbench/` migration.

---

## Test File Migration

The `__tests__/` directory contains 73 test files. These should move alongside their
source files into co-located `__tests__/` directories within each feature:

```
features/sentinels/__tests__/sentinel-manager.test.ts
features/fleet/__tests__/fleet-client.test.ts
features/swarm/__tests__/swarm-board-store.test.tsx
... etc.
```

This is the largest single batch of moves and can be done as a final pass after all
source files are relocated.

---

## Deliverables Checklist

- [ ] Feature directories created with barrel exports
- [ ] All 106 top-level files moved from `lib/workbench/` to `features/`
- [ ] `detection-workflow/` and `redteam/` subdirectories moved to `features/`
- [ ] 73 test files relocated to co-located `__tests__/` in each feature
- [ ] Backward-compat re-exports in place during migration
- [ ] All import paths updated (no tsconfig/vite config changes needed)
- [ ] TypeScript compilation passes (`tsc --noEmit`)
- [ ] All tests pass
- [ ] Re-export shims removed
- [ ] `lib/workbench/` has < 10 files
- [ ] `components/workbench/` alignment started (stretch goal)
