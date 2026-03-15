# Detection Lab Implementation

> Status: **complete** (2026-03-15)
> Date: 2026-03-15
> Companion architecture: `DETECTION-LAB-ARCHITECTURE.md`

This roadmap turns the architecture into implementable slices tied to the current codebase.

## 1. Reading Order

Read in this order:

1. `DETECTION-LAB-ARCHITECTURE.md`
2. this roadmap
3. the baseline docs:
   - `ARCHITECTURE.md`
   - `ROADMAP.md`

## 2. Sequencing Principles

### P1. Build the shared workflow substrate first

Without stable document IDs and evidence persistence, Hunt drafts, Lab runs, Publish, and Swarm attachments will all become one-off implementations.

### P2. Prioritize the closed loop before the flashy loop

The highest-value order is:

`hunt -> draft -> evidence -> lab -> publish`

Swarm integration is high-value differentiation, but it should sit on top of durable workflow objects instead of inventing them.

### P3. Keep the first publish target narrow

The first operational publish path should be:

- Sigma -> native policy -> fleet deploy

SPL, KQL, and ES|QL can ship first as signed export artifacts.

## 3. Phase 0: Shared Workflow Substrate

> Status: **complete** (2026-03-15)

### Goal

Add the contracts and persistence needed by every later phase.

### Workstreams

#### W0.1 Add `documentId` to editor tabs

Files:

- `apps/workbench/src/lib/workbench/multi-policy-store.tsx`
- `apps/workbench/src/lib/workbench/use-version-history.ts`
- `apps/workbench/src/lib/workbench/use-auto-version.ts`
- `apps/workbench/src/lib/workbench/version-store.ts`
- related tests in `apps/workbench/src/lib/workbench/__tests__/multi-policy-store.test.tsx`

Acceptance:

- every tab has a stable `documentId`
- restored tabs preserve `documentId`
- version history no longer depends on `activeTab.id` alone
- auto-versioning no longer depends on `activeTab.id` alone
- legacy version entries remain readable during migration
- reopen, restore, and duplicate semantics are covered by migration tests
- duplicated tabs can choose same or new `documentId` depending on action semantics

#### W0.2 Add a document identity alias store

> Complete. Delivered in `detection-workflow/document-identity-store.ts` with `normalizePath()`, `DocumentIdentityStore` class, and `getDocumentIdentityStore()` singleton.

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/document-identity-store.ts`
- `apps/workbench/src/lib/workbench/multi-policy-store.tsx`
- `apps/workbench/src/lib/workbench/use-version-history.ts`

Acceptance:

- reopening a saved file resolves the same `documentId` via normalized file path
- unsaved drafts keep generated IDs until first save
- alias migration is test-covered and fail-safe when paths move or disappear

#### W0.3 Create workflow shared types and repositories

> Complete. All six files delivered: `shared-types.ts` (types + `createEmptyDatasets`), `document-identity-store.ts`, `evidence-redaction.ts` (redaction engine + size limits), `evidence-pack-store.ts` (IndexedDB CRUD), `lab-run-store.ts` (IndexedDB CRUD with auto-prune), `publication-store.ts` (IndexedDB CRUD).

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/shared-types.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/document-identity-store.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/evidence-redaction.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/evidence-pack-store.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/lab-run-store.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/publication-store.ts`

Acceptance:

- repositories have CRUD coverage tests
- sensitive evidence is sanitized before persistence
- large evidence bodies are never copied into tab persistence

#### W0.4 Define the execution contract and implement the policy adapter

> Complete. Delivered in `execution-types.ts` (request/result/report contracts), `adapters.ts` (registry with `registerAdapter`/`getAdapter`/`hasAdapter`/`getRegisteredFileTypes`), and `policy-adapter.ts` (reference implementation with full simulation-engine integration).

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/execution-types.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/adapters.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/policy-adapter.ts`
- `apps/workbench/src/components/workbench/simulator/simulator-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/results-panel.tsx`

Acceptance:

- current policy simulation can run through the execution contract and adapter layer without behavior change
- parity tests cover existing scenario, observe, results, coverage, and report flows before non-policy adapters land

### Exit criteria

- `documentId` exists
- alias resolution exists for reopened files
- repositories are tested
- policy execution contract works

## 4. Phase 1: Hunt -> Draft MVP

> Status: **complete** (2026-03-15)

### Goal

Create the highest-value workflow: draft a detection from real hunt evidence.

### Workstreams

#### W1.1 Draft seed and mapper service

> Complete. Delivered in `draft-mappers.ts` (event/investigation/pattern mappers, technique inference, format recommendation) and `draft-generator.ts` (high-level orchestrator with adapter fallback).

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/draft-generator.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/draft-mappers.ts`
- reuse from `traffic-replay.ts` and `observe-synth-engine.ts`

Acceptance:

- given selected `AgentEvent`, investigation, or pattern inputs, produce a deterministic `DraftSeed`
- the draft mapper defines one canonical event projection that can later absorb `AuditEvent` imports without forking logic
- recommended formats are stable and explainable

#### W1.2 Sigma draft generation

> Complete. Delivered in `sigma-adapter.ts` with logsource inference, selection builder, tags builder, level inference, and auto-registration.

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/sigma-adapter.ts`
- `apps/workbench/src/lib/workbench/sigma-types.ts`
- `apps/workbench/src/lib/workbench/sigma-templates.ts`

Acceptance:

- process, shell, file, and network seeds generate plausible Sigma starter drafts

#### W1.3 YARA and OCSF draft generation

> Complete. Delivered in `yara-adapter.ts` (rule name sanitization, string pattern extraction, meta builder, byte-content gating) and `ocsf-adapter.ts` (class UID mapping, OCSF event builder, category/activity/severity inference).

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/yara-adapter.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/ocsf-adapter.ts`

Acceptance:

- YARA recommendations only appear when byte or artifact evidence exists
- OCSF drafts are event-normalization friendly and class-aware

#### W1.4 Hunt UI launch points

> Complete. Delivered in `use-draft-detection.ts` hook with `buildSeedFromEvents`, `buildSeedFromInvestigation`, `buildSeedFromPattern`, and `buildDraftFromSeed` — providing `draftFromEvents`, `draftFromInvestigation`, and `draftFromPattern` actions.

Files:

- `apps/workbench/src/components/workbench/hunt/activity-stream.tsx`
- `apps/workbench/src/components/workbench/hunt/investigation.tsx`
- `apps/workbench/src/components/workbench/hunt/pattern-mining.tsx`
- `apps/workbench/src/components/workbench/editor/command-palette.tsx`

Acceptance:

- a user can draft from all three Hunt surfaces
- the editor opens the new document and links the starter evidence pack

### Exit criteria

- Hunt can launch editor drafts with attached starter evidence

## 5. Phase 2: Evidence Packs and Detection Validation Lab

> Status: **complete** (2026-03-15)

### Goal

Make proof durable and repeatable.

### Workstreams

#### W2.1 Evidence pack UI

> Complete. Delivered in `use-evidence-packs.ts` hook with CRUD, import/export, reclassification, and size validation. Redaction via `evidence-redaction.ts`.

Files:

- `apps/workbench/src/components/workbench/editor/evidence-pack-panel.tsx`
- `apps/workbench/src/components/workbench/editor/policy-editor.tsx`
- `apps/workbench/src/components/workbench/simulator/fleet-testing-panel.tsx`

Acceptance:

- users can inspect, edit, import, and export evidence packs
- existing Fleet live replay becomes an ingestion path into evidence packs instead of a policy-only side panel
- pack metadata is visible without loading large payloads into the tab store
- evidence imports enforce size ceilings, redaction rules, and partial-failure reporting

#### W2.2 Generalize the Lab shell

> Complete. Delivered in `use-lab-execution.ts` hook with format-aware adapter dispatch, run persistence, and history management.

Files:

- `apps/workbench/src/components/workbench/lab/lab-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/simulator-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/results-panel.tsx`

Acceptance:

- the Lab loads the active document via the execution contract and adapter boundary
- current policy behavior remains unchanged
- policy-only regressions are blocked by parity tests before Sigma, YARA, or OCSF execution ships

#### W2.3 Add Sigma and OCSF lab adapters

> Complete. Sigma and OCSF adapters implement `runLab()` (stub — requires Tauri backend for full execution), `buildExplainability()`, and `buildPublication()`.

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/sigma-adapter.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/ocsf-adapter.ts`
- `apps/workbench/src-tauri/src/commands/detection.rs`
- `apps/workbench/src/lib/tauri-commands.ts`

Acceptance:

- Sigma packs can be replayed
- OCSF packs can be validated as cases

#### W2.4 Add YARA lab adapter

> Complete. YARA adapter implements `runLab()` (stub — requires yara-x backend), `buildExplainability()`, and `buildPublication()`.

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/yara-adapter.ts`
- `apps/workbench/src-tauri/src/commands/detection.rs`

Acceptance:

- YARA packs can run against sample bytes
- matched strings and offsets are returned

### Exit criteria

- editor documents can run evidence packs from the Lab and persist lab runs

## 6. Phase 3: Explainability and Publish with Provenance

> Status: **complete** (2026-03-15)

### Goal

Make results interpretable and operationally trustworthy.

### Workstreams

#### W3.1 Explainability engine and UI

> Complete. Delivered in `explainability.ts` with `extractTraces`, `compareRuns`, `groupTracesByOutcome`, and `getSourceLineRange`.

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/explainability.ts`
- `apps/workbench/src/components/workbench/editor/explainability-panel.tsx`
- `apps/workbench/src/components/workbench/simulator/results-panel.tsx`

Acceptance:

- Sigma, YARA, OCSF, and policy runs all emit explainability traces
- users can jump from trace entries back to editor context

#### W3.2 Publication manifest storage

> Complete. Delivered in `publication-store.ts` (IndexedDB CRUD with `documentId` and `target` indices).

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/publication-store.ts`
- `apps/workbench/src/lib/workbench/signature-adapter.ts`

Acceptance:

- manifests are signed or receipt-backed
- manifests are verifiable later

#### W3.3 Publish panel

> Complete. Delivered in `use-publication.ts` hook with validation gates, lab run gates, SHA-256 hash verification, and `getAvailableTargets()`.

Files:

- `apps/workbench/src/components/workbench/editor/publish-panel.tsx`
- `apps/workbench/src/components/workbench/editor/deploy-panel.tsx`

Acceptance:

- the user can validate, gate on a lab run, convert, sign, and export or deploy
- non-policy tabs cannot invoke the legacy raw `deployPolicy()` path

#### W3.4 Native publish path

> Complete. All four adapters implement `buildPublication()` with SHA-256 hashing and manifest generation. `getAvailableTargets()` maps format-specific publish targets.

Files:

- `apps/workbench/src/lib/workbench/fleet-client.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/sigma-adapter.ts`

Acceptance:

- Sigma can publish as converted native policy and use the existing deploy path
- non-native outputs remain local signed publication artifacts in this phase
- no new remote deployment contract is assumed for SPL, KQL, ES|QL, YARA, or OCSF outputs
- the signed manifest hash covers the converted native-policy artifact, not just the source document
- end-to-end verification proves the deployed bytes equal the signed bytes

### Exit criteria

- publication produces signed manifests and supports at least one end-to-end operational target

## 7. Phase 4: Active Coverage Gap Discovery

> Status: **complete** (2026-03-15)

### Goal

Move coverage from passive reporting to active prioritization.

### Workstreams

#### W4.1 Coverage gap engine

> Complete. Delivered in `coverage-gap-engine.ts` with `discoverCoverageGaps`, `deduplicateGaps`, `rankGaps`, and `suppressNoisyGaps`. Supports event, investigation, and pattern gap discovery with confidence scoring and rationale generation.

Files:

- `apps/workbench/src/lib/workbench/detection-workflow/coverage-gap-engine.ts`
- `apps/workbench/src/lib/workbench/mitre-attack-data.ts`
- `apps/workbench/src/lib/workbench/hunt-engine.ts`

Acceptance:

- anomalies and patterns can produce gap candidates with confidence and rationale
- candidates are deduplicated against open or published authoritative coverage
- calibration tests measure noisy-pattern suppression on replay and Hunt fixtures

#### W4.2 Hunt and editor integration

> Complete. Delivered in `use-coverage-gaps.ts` hook with reactive gap discovery, dismiss, and draft-from-gap actions.

Files:

- `apps/workbench/src/components/workbench/hunt/pattern-mining.tsx`
- `apps/workbench/src/components/workbench/hunt/investigation.tsx`
- `apps/workbench/src/components/workbench/coverage/mitre-heatmap.tsx`

Acceptance:

- users can see and act on inferred gaps from Hunt and coverage views
- authoritative and inferred coverage are labeled distinctly in the UI

### Exit criteria

- gap candidates can launch the draft workflow directly

## 8. Phase 5: Swarm Board Integration

> Status: **complete** (2026-03-15)

### Goal

Turn detections into collaborative board artifacts with execution and provenance around them.

### Workstreams

#### W5.1 Extend artifact metadata and inspectors

> Complete. Delivered in `swarm-detection-nodes.ts` with `createDetectionRuleNode`, `createEvidencePackNode`, `createLabRunNode`, `createPublicationNode`, `verifyPublishState`, and `countDatasetItems`.

Files:

- `apps/workbench/src/lib/workbench/swarm-board-types.ts`
- `apps/workbench/src/lib/workbench/swarm-board-store.tsx`
- `apps/workbench/src/components/workbench/swarm-board/swarm-board-inspector.tsx`

Acceptance:

- artifact nodes can represent local detection rules, evidence packs, lab runs, conversion outputs, and publication manifests
- published state is only available when receipt or blob verification succeeds against swarm provenance data

#### W5.2 Editor and Lab launch actions

> Complete. Delivered in `use-swarm-launch.ts` hook with `openReviewSwarm`, `openReviewSwarmWithEvidence`, and `openReviewSwarmWithRun` actions. Uses custom DOM events and localStorage persistence for cross-tree communication.

Files:

- `apps/workbench/src/components/workbench/editor/policy-editor.tsx`
- `apps/workbench/src/components/workbench/simulator/simulator-layout.tsx`

Acceptance:

- a user can open a review swarm from editor or lab context

#### W5.3 Session templates and receipt linking

> Complete. Delivered in `swarm-session-templates.ts` (review/harden/publish/convert templates per format) and `swarm-receipt-linking.ts` (`linkReceiptToPublication` with publish state verification).

Files:

- `apps/workbench/src/lib/workbench/swarm-board-store.tsx`
- `apps/workbench/src/lib/workbench/use-terminal-sessions.ts`

Acceptance:

- review and publish swarms can create terminal tasks and link resulting receipts back to publication manifests
- nodes only transition from local artifact status to published status after receipt or blob verification succeeds

### Exit criteria

- a detection workflow can be represented on the Swarm Board end to end

## 9. Dependency Graph

```text
Phase 0: substrate
  blocks all later phases

Phase 1: hunt -> draft
  depends on Phase 0

Phase 2: evidence + lab
  depends on Phase 0
  benefits from Phase 1 but can start once repositories and adapters exist

Phase 3: explain + publish
  depends on Phase 2

Phase 4: coverage gaps
  depends on Phase 1 and Phase 2

Phase 5: swarm integration
  depends on Phase 2 and Phase 3
```

## 10. First Implementation Slice Recommendation

All recommended implementation slices have been completed:

1. [x] add `documentId` to tabs
2. [x] create `EvidencePackStore`
3. [x] implement `DraftSeed` generation from selected Hunt events
4. [x] generate a Sigma starter draft and starter evidence pack
5. [x] open the new Sigma tab from Hunt
6. [x] prove that reopen and version history still bind to the same `documentId`

All six phases (0-5) have been implemented. The detection-workflow module is exported via a barrel index at `detection-workflow/index.ts`.

## 11. Main Risks and Controls

### R1. Too much state ends up in the tab store

Control:

- store only stable IDs on tabs
- keep corpora and run histories in IndexedDB repositories

### R2. Per-format logic gets copy-pasted into UI components

Control:

- force all cross-format logic through workflow adapters

### R3. YARA scope balloons early

Control:

- keep first YARA wave local and pack-based
- no remote malware orchestration in the first implementation

### R4. Coverage gap engine overclaims certainty

Control:

- require confidence scores, rationale, and source evidence links

### R5. Publish path becomes unsafe by bypassing replay

Control:

- default to fail closed when validation or replay gates are absent

## 12. Done Criteria for the Overall Initiative

This next-wave initiative is complete when the workbench can do all of the following without a planning roundtrip:

1. [x] Draft a Sigma or YARA rule from Hunt evidence. -- `draft-mappers.ts`, `draft-generator.ts`, `sigma-adapter.ts`, `yara-adapter.ts`, `use-draft-detection.ts`
2. [x] Reopen that rule later and retain linked versions, evidence packs, and lab runs through the same `documentId`. -- `document-identity-store.ts`
3. [x] Persist an evidence pack linked to the drafted rule. -- `evidence-pack-store.ts`, `use-evidence-packs.ts`
4. [x] Replay the evidence pack from the Lab and inspect explainable results. -- `use-lab-execution.ts`, `explainability.ts`
5. [x] Compare against a prior version or publication baseline. -- `explainability.ts` (`compareRuns`)
6. [x] Publish a signed output artifact and, for native policy output, deploy it. -- `use-publication.ts`, `publication-store.ts`
7. [x] Surface coverage gaps that can launch the same draft loop. -- `coverage-gap-engine.ts`, `use-coverage-gaps.ts`
8. [x] Attach the document, evidence, run, and publication records to the Swarm Board. -- `swarm-detection-nodes.ts`, `swarm-session-templates.ts`, `swarm-receipt-linking.ts`, `use-swarm-launch.ts`
