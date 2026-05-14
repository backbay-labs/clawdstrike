# Detection Lab Architecture

> Status: draft  
> Date: 2026-03-15  
> Scope: integrate the current multi-format editor with Hunt, the Lab, Swarm Board, and publish/provenance workflows.

This document assumes the current workbench already has:

- typed multi-format tabs in `apps/workbench/src/lib/workbench/multi-policy-store.tsx`
- format-aware editor routing in `apps/workbench/src/components/workbench/editor/split-editor.tsx`
- native detection validation in `apps/workbench/src/lib/workbench/use-native-validation.ts` and `apps/workbench/src-tauri/src/commands/detection.rs`
- mounted command palette, explorer, problems, and ATT&CK coverage in `apps/workbench/src/components/workbench/editor/policy-editor.tsx`
- Hunt, Simulate, and Swarm Board surfaces in `apps/workbench/src/components/workbench/hunt/`, `apps/workbench/src/components/workbench/simulator/`, and `apps/workbench/src/components/workbench/swarm-board/`

The next architectural step is not another editor rewrite. It is to close the loop between:

`hunt -> draft -> replay -> explain -> publish -> coordinate`

## 1. Goals

### Primary goals

1. Turn live or retrospective hunt evidence into draft detections without retyping the context.
2. Make saved evidence packs and replayable regression sets first-class for Sigma, YARA, OCSF, and native policy.
3. Reuse the current simulation, receipt, version, and swarm infrastructure instead of building parallel systems.
4. Preserve the local-first security posture: validation and sensitive evidence stay local by default, and every publish path has provenance.

### Non-goals for the first wave

1. Real-time collaborative editing.
2. A generic remote deployment framework for every SIEM target.
3. Remote malware execution infrastructure for YARA.
4. Replacing the current editor route or tab model.

## 2. Current Code-Backed Substrate

The workbench already has most of the substrate needed for the next workflow wave.

### 2.1 Detection editing

Reusable code paths:

- `apps/workbench/src/lib/workbench/multi-policy-store.tsx`
- `apps/workbench/src/lib/workbench/file-type-registry.ts`
- `apps/workbench/src/components/workbench/editor/split-editor.tsx`
- `apps/workbench/src/components/workbench/editor/policy-editor.tsx`
- `apps/workbench/src/lib/workbench/use-native-validation.ts`
- `apps/workbench/src-tauri/src/commands/detection.rs`

What exists today:

- typed tabs for `clawdstrike_policy`, `sigma_rule`, `yara_rule`, and `ocsf_event`
- format-aware open/save/import/export
- dedicated visual editors for Sigma, YARA, and OCSF
- mounted problems, explorer, command palette, and ATT&CK heatmap
- per-tab persistence, dirty tracking, and native validation

Architectural implication:

- the editor shell is already strong enough; the next work should compose around it instead of refactoring it again

### 2.2 Hunt

Reusable code paths:

- `apps/workbench/src/components/workbench/hunt/hunt-layout.tsx`
- `apps/workbench/src/components/workbench/hunt/investigation.tsx`
- `apps/workbench/src/components/workbench/hunt/pattern-mining.tsx`
- `apps/workbench/src/lib/workbench/hunt-types.ts`
- `apps/workbench/src/lib/workbench/hunt-engine.ts`
- `apps/workbench/src/lib/workbench/traffic-replay.ts`
- `apps/workbench/src/lib/workbench/observe-synth-engine.ts`

What exists today:

- fleet audit ingestion
- anomaly scoring and baselines
- investigations with annotations and scoped event sets
- pattern discovery and promotion signals
- conversion of audit events to test scenarios
- synthesis of policies from observed event logs

Architectural implication:

- Hunt already produces the raw materials for rule drafting and replay packs; this is the highest-leverage integration point

### 2.3 Lab and simulation

Reusable code paths:

- `apps/workbench/src/components/workbench/lab/lab-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/simulator-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/fleet-testing-panel.tsx`
- `apps/workbench/src/components/workbench/simulator/observe-panel.tsx`
- `apps/workbench/src/components/workbench/simulator/results-panel.tsx`
- `apps/workbench/src/lib/workbench/scenario-generator.ts`
- `apps/workbench/src/lib/workbench/simulation-engine.ts`
- `apps/workbench/src/lib/workbench/native-simulation.ts`
- `apps/workbench/src-tauri/src/commands/workbench.rs`

What exists today:

- native and client-side policy simulation
- scenario generation
- posture tracking
- import and replay of production audit traffic against draft policy
- results, coverage, reports, and observation views

Architectural implication:

- the Lab route already has a proven interaction model for "load inputs -> run -> inspect results"; it should be generalized via adapters rather than forked

### 2.4 Swarm Board

Reusable code paths:

- `apps/workbench/src/components/workbench/swarm-board/swarm-board-page.tsx`
- `apps/workbench/src/lib/workbench/swarm-board-store.tsx`
- `apps/workbench/src/lib/workbench/swarm-board-types.ts`
- `apps/workbench/src/lib/workbench/terminal-service.ts`
- `apps/workbench/src/lib/workbench/use-terminal-sessions.ts`
- `apps/workbench/src-tauri/src/commands/worktree.rs`

What exists today:

- agent session nodes
- terminal task nodes
- artifact nodes
- diff nodes
- receipt nodes
- PTY-backed live sessions
- worktree management
- local persistence and inspectors

Architectural implication:

- the board already models collaborative work artifacts; detection workflows should extend artifact metadata instead of adding a parallel coordination system

### 2.5 Publish and provenance

Reusable code paths:

- `apps/workbench/src/components/workbench/editor/deploy-panel.tsx`
- `apps/workbench/src/lib/workbench/fleet-client.ts`
- `apps/workbench/src/components/workbench/receipts/receipt-inspector.tsx`
- `apps/workbench/src/components/workbench/receipts/chain-verification.tsx`
- `apps/workbench/src/lib/workbench/signature-adapter.ts`
- `apps/workbench/src/lib/workbench/version-store.ts`
- `apps/workbench/src/lib/workbench/use-version-history.ts`

What exists today:

- remote validate and deploy for native policy YAML
- local and remote receipt verification
- persistent and ephemeral signing
- IndexedDB-backed version history
- version diff and rollback

Architectural implication:

- publish provenance should extend the existing version and receipt model rather than inventing a second trust system

### 2.6 Coverage and explainability

Reusable code paths:

- `apps/workbench/src/components/workbench/coverage/mitre-heatmap.tsx`
- `apps/workbench/src/lib/workbench/mitre-attack-data.ts`
- `apps/workbench/src/lib/workbench/coverage-analyzer.ts`
- `apps/workbench/src/components/workbench/simulator/results-panel.tsx`
- `apps/workbench/src/components/workbench/editor/problems-panel.tsx`

What exists today:

- ATT&CK extraction from Sigma, YARA, and policy content
- heatmap and coverage summary
- guard coverage for policy scenarios
- verdict, evaluation-path, and diagnostic rendering

Architectural implication:

- coverage and explainability should become reusable artifacts produced by lab runs and publish gates, not one-off UI panels

## 3. Cross-Cutting Design Decisions

### D1. Keep the open-tab store thin

`multi-policy-store.tsx` should remain the source of truth for open documents, dirty state, source content, and native validation. It should not absorb:

- large corpora
- run histories
- publish manifests
- swarm attachments

Reason:

- the store is already heavily used and persisted
- large evidence payloads will slow hydration and increase corruption risk
- this avoids deepening the existing provider pyramid

### D2. Add a stable `documentId` to each tab

The next wave needs a stable key for evidence packs, lab runs, publication history, and swarm attachments.

Proposed addition in `multi-policy-store.tsx`:

```ts
interface PolicyTab {
  id: string;
  documentId: string;
  fileType: FileType;
  name: string;
  filePath: string | null;
  dirty: boolean;
  yaml: string;
  policy: WorkbenchPolicy;
  validation: ValidationResult;
  nativeValidation: NativeValidationState;
  activeEvidencePackId?: string | null;
}
```

Rules:

- create `documentId` once when a tab is created
- persist it with tab restore
- preserve it across save and rename
- generate a new `documentId` on "duplicate as new rule"

Because the current version history is keyed by `activeTab.id` in `policy-editor.tsx`,
`use-version-history.ts`, and `version-store.ts`, the next wave also needs a small
`DocumentIdentityStore`:

- unsaved drafts get a generated `documentId`
- saved documents register aliases from normalized `filePath -> documentId`
- reopening a saved file should resolve `documentId` through that alias index before creating a new one
- version, evidence, publication, and lab-run repositories key off `documentId`, never `tab.id`
- migration should read legacy tab-id-keyed versions opportunistically, then rekey them to `documentId`

This avoids breaking version history every time a tab is reopened and gives non-tab workflow
objects a durable document anchor.

### D3. Use repository + adapter patterns, not more root providers

New persistent workflow data should live behind repositories in `src/lib/workbench/detection-workflow/`.

Recommended pattern:

- repositories for persistence and query
- pure services for inference and orchestration
- one small route-scoped store only if cross-route transient state truly needs it

Avoid:

- another global context provider at `App.tsx` level
- embedding cross-format orchestration logic inside React components

### D4. Make per-format behavior pluggable

The editor already branches by `fileType`. The next wave should formalize that into adapters so Hunt, Lab, Publish, and Explainability can share the same per-format contract.

```ts
interface DetectionWorkflowAdapter {
  fileType: FileType;
  canDraftFrom(seed: DraftSeed): boolean;
  buildDraft(seed: DraftSeed): DraftBuildResult;
  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack;
  runLab(source: string, pack: EvidencePack): Promise<LabRun>;
  buildExplainability(run: LabRun): ExplainabilityTrace[];
  buildPublication(request: PublicationRequest): Promise<PublicationBuildResult>;
}
```

Adapter implementations:

- `policy-adapter.ts`
- `sigma-adapter.ts`
- `yara-adapter.ts`
- `ocsf-adapter.ts`

### D5. Treat evidence as first-class, immutable-enough inputs

Evidence packs should behave like test fixtures:

- explicit positive and negative datasets
- importable and exportable
- versionable by content hash
- reusable across versions of the same detection document

The main anti-pattern to avoid is storing only generated scenarios. For Sigma, YARA, and OCSF, the first-class object is the evidence corpus, not just a policy-style scenario list.

Storage boundary rules:

- pack records store metadata, expectations, provenance, and small inline bodies only
- large JSON corpora and byte samples spill into a blob store keyed by content hash
- inline size limits should be explicit from day one:
  - structured events: 64 KiB per item
  - byte samples: 256 KiB per item
  - larger bodies require blob-backed storage
- import, export, and quota failures must surface partial-failure detail instead of silently dropping evidence

### D6. Publish everything through signed manifests

Every publish/export/deploy action should produce a manifest before side effects occur.

The manifest is the stable provenance object. It records:

- source document hash
- validation snapshot
- evidence pack and run snapshot
- converter identity and version
- output hash
- signer identity
- receipt or signature reference
- deployment or export destination

First-wave scope boundary:

- remote deployment is only supported for native policy output using the existing `deployPolicy()` and `distributePolicy()` paths in `fleet-client.ts`
- Sigma, YARA, OCSF, SPL, KQL, and ES|QL outputs are local signed publication artifacts first, with remote publication deferred until the backend has a real API contract for them

### D7. Separate inferred coverage from authoritative coverage

Coverage gaps derived from Hunt are probabilistic. They should be labeled accordingly.

Required split:

- authoritative coverage: open or published rules that explicitly map to techniques or data sources
- inferred gaps: anomalies and patterns that suggest missing coverage

### D8. Default to secure local storage and redaction

Large or sensitive evidence should be stored locally first and redacted before:

- swarm publication
- export
- remote validation
- shareable manifests

Reuse:

- `storage-sanitizer.ts` as the storage-boundary pattern, not as the final evidence-redaction catalog
- existing fleet URL and secure-store policy in `fleet-client.ts`

The current sanitizer only strips a narrow set of policy fields. Evidence packs need their own
redaction registry and import/export failure reporting instead of assuming the existing policy
sanitizer is sufficient.

## 4. Shared Contracts

### 4.1 Document reference

```ts
interface DetectionDocumentRef {
  documentId: string;
  fileType: FileType;
  tabId?: string;
  filePath: string | null;
  name: string;
  sourceHash: string;
  versionId?: string | null;
}
```

### 4.2 Draft seed

```ts
type DraftSeedKind = "hunt_event" | "investigation" | "hunt_pattern" | "manual";

interface DraftSeed {
  id: string;
  kind: DraftSeedKind;
  sourceEventIds: string[];
  investigationId?: string;
  patternId?: string;
  preferredFormats: FileType[];
  techniqueHints: string[];
  dataSourceHints: string[];
  extractedFields: Record<string, unknown>;
  createdAt: string;
  confidence: number;
}
```

### 4.3 Evidence pack

```ts
type EvidenceDatasetKind = "positive" | "negative" | "regression" | "false_positive";

type EvidenceItem =
  | {
      id: string;
      kind: "structured_event";
      format: "json";
      payload: Record<string, unknown>;
      expected: "match" | "no_match";
      sourceEventId?: string;
    }
  | {
      id: string;
      kind: "bytes";
      encoding: "base64" | "hex" | "utf8";
      payload: string;
      expected: "match" | "no_match";
      sourceArtifactPath?: string;
    }
  | {
      id: string;
      kind: "ocsf_event";
      payload: Record<string, unknown>;
      expected: "valid" | "invalid";
      sourceEventId?: string;
    }
  | {
      id: string;
      kind: "policy_scenario";
      scenario: TestScenario;
      expected: Verdict;
    };

interface EvidencePack {
  id: string;
  documentId: string;
  fileType: FileType;
  title: string;
  createdAt: string;
  derivedFromSeedId?: string;
  datasets: Record<EvidenceDatasetKind, EvidenceItem[]>;
  notes?: string;
  redactionState: "clean" | "redacted" | "contains_sensitive_fields";
}
```

Implementation note:

- the logical contract above does not require every payload to be stored inline
- Phase 2 should separate evidence metadata from blob-backed payload bodies where size or sensitivity requires it

### 4.4 Lab run

```ts
interface LabRunSummary {
  totalCases: number;
  passed: number;
  failed: number;
  matched: number;
  missed: number;
  falsePositives: number;
  engine: "native" | "client" | "mixed";
}

interface LabCaseResult {
  caseId: string;
  dataset: EvidenceDatasetKind;
  status: "pass" | "fail";
  expected: string;
  actual: string;
  explanationRefIds: string[];
}

interface LabRun {
  id: string;
  documentId: string;
  evidencePackId: string;
  fileType: FileType;
  startedAt: string;
  completedAt: string;
  summary: LabRunSummary;
  results: LabCaseResult[];
  explainability: ExplainabilityTrace[];
  coverageDelta?: {
    techniquesAdded: string[];
    techniquesLost: string[];
  };
}
```

### 4.5 Publication manifest

```ts
type PublishTarget =
  | "native_policy"
  | "spl"
  | "kql"
  | "esql"
  | "json_export"
  | "fleet_deploy";

interface PublicationManifest {
  id: string;
  documentId: string;
  sourceFileType: FileType;
  target: PublishTarget;
  createdAt: string;
  sourceHash: string;
  outputHash: string;
  validationSnapshot: {
    valid: boolean;
    diagnosticCount: number;
  };
  runSnapshot: {
    evidencePackId: string;
    labRunId: string;
    passed: boolean;
  } | null;
  converter: {
    id: string;
    version: string;
  };
  signer: {
    publicKey: string;
    keyType: "persistent" | "ephemeral";
  } | null;
  receiptId?: string;
  exportPath?: string;
  deployResponse?: {
    success: boolean;
    hash?: string;
    destination?: string;
  };
}
```

### 4.6 Coverage gap candidate

```ts
interface CoverageGapCandidate {
  id: string;
  sourceKind: "event" | "investigation" | "pattern";
  sourceIds: string[];
  severity: "high" | "medium" | "low";
  confidence: number;
  suggestedFormats: FileType[];
  techniqueHints: string[];
  dataSourceHints: string[];
  rationale: string;
}
```

### 4.7 Explainability trace

```ts
type ExplainabilityTrace =
  | {
      id: string;
      kind: "sigma_match";
      caseId: string;
      matchedSelectors: Array<{ name: string; fields: string[] }>;
      matchedFields: Array<{ path: string; value: string }>;
      techniqueHints: string[];
      sourceLineHints: number[];
    }
  | {
      id: string;
      kind: "yara_match";
      caseId: string;
      matchedStrings: Array<{ name: string; offset: number; length: number }>;
      conditionSummary: string;
      sourceLineHints: number[];
    }
  | {
      id: string;
      kind: "ocsf_validation";
      caseId: string;
      classUid: number | null;
      missingFields: string[];
      invalidFields: string[];
      sourceLineHints: number[];
    }
  | {
      id: string;
      kind: "policy_evaluation";
      caseId: string;
      guardResults: GuardSimResult[];
      evaluationPath?: EvaluationPathStep[];
    };
```

## 5. Proposed Module Layout

### 5.1 Domain and persistence

Add a new module family:

```text
apps/workbench/src/lib/workbench/detection-workflow/
  shared-types.ts
  document-identity-store.ts
  execution-types.ts
  adapters.ts
  policy-adapter.ts
  sigma-adapter.ts
  yara-adapter.ts
  ocsf-adapter.ts
  draft-generator.ts
  draft-mappers.ts
  evidence-redaction.ts
  evidence-pack-store.ts
  lab-run-store.ts
  publication-store.ts
  coverage-gap-engine.ts
  explainability.ts
```

Implementation rules:

- repository modules follow the raw IndexedDB style used in `version-store.ts`
- adapter modules are pure orchestration layers over existing Tauri and client-side helpers
- React components should not directly compose cross-format inference logic

### 5.2 UI integration points

Add or extend:

```text
apps/workbench/src/components/workbench/
  hunt/
    activity-stream.tsx
    investigation.tsx
    pattern-mining.tsx
  simulator/
    simulator-layout.tsx
    results-panel.tsx
  editor/
    policy-editor.tsx
    publish-panel.tsx
    explainability-panel.tsx
    evidence-pack-panel.tsx
  swarm-board/
    swarm-board-inspector.tsx
    nodes/
```

### 5.3 Backend integration points

Extend:

- `apps/workbench/src-tauri/src/commands/detection.rs`
- `apps/workbench/src-tauri/src/main.rs`
- `apps/workbench/src/lib/tauri-commands.ts`

New command family:

- `test_sigma_rule`
- `scan_yara_rule`
- `normalize_ocsf_event`
- `convert_sigma_rule`

## 6. Initiative 1: Hunt -> Detection Draft

### Current reusable surfaces

- Hunt event and investigation models in `hunt-types.ts`
- escalation and scoped event behavior in `hunt-layout.tsx` and `investigation.tsx`
- pattern discovery in `pattern-mining.tsx`
- `auditEventsToScenarios()` in `traffic-replay.ts`
- `synthesizePolicy()` in `observe-synth-engine.ts`
- typed tab creation in `multi-policy-store.tsx`

### Target user outcome

From Hunt, a user should be able to:

1. select one or more events, or an investigation, or a discovered pattern
2. click `Draft Detection`
3. choose or accept a recommended format
4. land in the editor with:
   - a prefilled document
   - an attached starter evidence pack
   - starter ATT&CK hints
   - a direct path into the validation lab

### Recommended format mapping

| Hunt signal shape | Preferred format | Fallbacks | Notes |
|---|---|---|---|
| Structured process or shell telemetry | `sigma_rule` | `clawdstrike_policy`, `ocsf_event` | Best fit for process creation and field-based matching |
| File or network event with stable metadata | `sigma_rule` | `ocsf_event` | Use Sigma for matching, OCSF for normalized event capture |
| Binary, string-rich, or artifact-centric evidence | `yara_rule` | `sigma_rule` | Only recommend YARA when byte or artifact evidence exists |
| Event normalization or finding publication | `ocsf_event` | `sigma_rule` | OCSF is not a detection rule; use it where the user is shaping telemetry or findings |

### Architecture

1. Add a `DraftSeed` builder in `draft-generator.ts`.
2. Normalize Hunt and replay inputs into one seed shape:
   - selected `AgentEvent[]` from Hunt UI
   - `Investigation`
   - `HuntPattern`
   - later, imported `AuditEvent[]` from fleet replay when users draft from lab-side evidence
3. Use adapter-specific `buildDraft()` to produce source text and format metadata.
4. Use adapter-specific `buildStarterEvidence()` to create the first `EvidencePack`.
5. Open a typed tab with `multiDispatch({ type: "NEW_TAB", fileType, yaml })`.
6. Persist the seed and evidence pack immediately so the Lab and Swarm Board can reference them by ID.

The first mapper should not depend on UI-only event shapes. Create one canonical event projection
for draft generation so `ActivityStream`, `InvestigationWorkbench`, and future fleet replay entry
points all feed the same drafting service.

### UI changes

Add `Draft Detection` affordances to:

- `activity-stream.tsx` for selected events
- `investigation.tsx` for a case or selected session slice
- `pattern-mining.tsx` for promoted or draft patterns

Also add:

- a command palette action for drafting from current hunt context
- navigation handoff from Hunt to `/editor` and `/lab`

### File changes

Primary files:

- `apps/workbench/src/components/workbench/hunt/activity-stream.tsx`
- `apps/workbench/src/components/workbench/hunt/investigation.tsx`
- `apps/workbench/src/components/workbench/hunt/pattern-mining.tsx`
- `apps/workbench/src/lib/workbench/detection-workflow/draft-generator.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/sigma-adapter.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/yara-adapter.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/ocsf-adapter.ts`
- `apps/workbench/src/lib/workbench/multi-policy-store.tsx`

### Security requirements

- strip or redact secrets from event content before pre-populating a draft
- cap per-seed payload sizes
- never auto-generate YARA from arbitrary large remote blobs without explicit user confirmation

## 7. Initiative 2: Evidence Replay and Regression Packs

### Current reusable surfaces

- `version-store.ts` raw IndexedDB wrapper pattern
- `traffic-replay.ts` event-to-scenario conversion
- `scenario-generator.ts` deterministic policy scenario generation

### Problem to solve

Today, non-policy documents can be validated, but they do not have a durable proof loop comparable to:

- "this evidence should match"
- "this evidence should not match"
- "this behavior regressed compared to the previous version"

### Architecture

1. Add `documentId` to tabs.
2. Implement `evidence-pack-store.ts` using raw IndexedDB, keyed by `documentId`.
3. Store only pack IDs on the tab, never full datasets.
4. Allow multiple packs per document:
   - starter pack from Hunt
   - manually curated regression pack
   - false-positive suppression pack
5. Add optional content hashing so identical evidence packs deduplicate naturally.

Storage rules:

- sanitize and redact evidence before persistence using the same storage boundary principles as `version-store.ts`
- retain provenance fields that point back to source events or artifacts without copying unnecessary remote metadata
- keep pack metadata queryable without loading the full payload body into the editor shell

### Why a dedicated store instead of only `TestScenario[]`

`TestScenario` is policy-centric and action-based. It is correct for policy simulation, but it is the wrong center of gravity for:

- YARA byte samples
- Sigma raw event corpora
- OCSF conformance packs

Design rule:

- the policy adapter may project evidence items into `TestScenario`
- Sigma, YARA, and OCSF should keep native evidence representations

### UI changes

Add an `Evidence` panel in the editor that can:

- show linked packs for the active document
- import and export a pack
- reclassify examples between positive and negative datasets
- mark a case as `regression`

### File changes

Primary files:

- `apps/workbench/src/lib/workbench/multi-policy-store.tsx`
- `apps/workbench/src/lib/workbench/detection-workflow/evidence-pack-store.ts`
- `apps/workbench/src/components/workbench/editor/evidence-pack-panel.tsx`
- `apps/workbench/src/components/workbench/editor/policy-editor.tsx`

## 8. Initiative 3: Turn Simulate into a Detection Validation Lab

### Current reusable surfaces

- `lab-layout.tsx`
- `simulator-layout.tsx`
- `results-panel.tsx`
- `use-native-validation.ts`
- `workbench.rs` native simulation
- `detection.rs` validation

### Architectural direction

Keep `/lab?tab=simulate`, but evolve `SimulatorLayout` into a format-aware validation lab.

Recommended migration:

1. preserve current policy behavior as the `policy` adapter
2. add an adapter registry
3. load the active editor tab or explicit document ID when the Lab opens
4. render format-specific case inputs and results using the same shell

Important constraint from the current code:

- `SimulatorLayout`, `FleetTestingPanel`, and `ResultsPanel` are still policy-centric around `state.activePolicy`, `TestScenario[]`, and policy simulation results
- do not route non-policy formats directly through those components
- add an intermediate execution contract first, then migrate the existing policy flow onto it without behavior change

Recommended execution contract:

```ts
interface DetectionExecutionRequest {
  document: DetectionDocumentRef;
  evidencePack: EvidencePack;
  adapterRunConfig?: Record<string, unknown>;
}

interface DetectionExecutionResult {
  run: LabRun;
  coverage?: CoverageReport | null;
  reportArtifacts: Array<{ id: string; kind: string; title: string }>;
}
```

Only after policy runs use this contract cleanly should Sigma, YARA, or OCSF adapters plug into the Lab shell.

### Adapter behavior

#### Policy adapter

Reuse current scenario builder and simulation engine.

#### Sigma adapter

Inputs:

- JSON event corpora from evidence packs

Needed command surface:

- `test_sigma_rule(source, events_jsonl)`
- optional `convert_sigma_rule(source, target_format)`

Outputs:

- matched and missed events
- matched field paths
- ATT&CK tag suggestions or confirmations

#### YARA adapter

Inputs:

- bytes, hex, or UTF-8 sample corpora

Needed command surface:

- `scan_yara_rule(source, samples)`

Outputs:

- matched strings
- offsets and counts
- false-positive hits against negative datasets

#### OCSF adapter

Inputs:

- OCSF JSON events

Needed command surface:

- `normalize_ocsf_event(json)` or an equivalent schema/conformance runner

Outputs:

- valid vs invalid cases
- missing required fields
- class and category normalization details

### UI changes

Evolve the current Lab tabs into:

- `Cases`
- `Results`
- `Coverage`
- `Explain`
- `Publish Gate`

Keep the existing scenario builder and observation model only for the policy adapter until the unified panels are ready.

### File changes

Primary files:

- `apps/workbench/src/components/workbench/lab/lab-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/simulator-layout.tsx`
- `apps/workbench/src/components/workbench/simulator/results-panel.tsx`
- `apps/workbench/src/lib/workbench/detection-workflow/adapters.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/lab-run-store.ts`
- `apps/workbench/src-tauri/src/commands/detection.rs`
- `apps/workbench/src/lib/tauri-commands.ts`

## 9. Initiative 4: Put Detections on the Swarm Board

### Current reusable surfaces

- `swarm-board-types.ts`
- `swarm-board-store.tsx`
- artifact, diff, and receipt nodes
- PTY and worktree integration

### Design choice

Do not create a large new swarm taxonomy immediately.

Preferred first implementation:

- keep existing node types
- extend artifact metadata
- add detection-specific inspectors and creation helpers

### Proposed metadata additions

Extend `SwarmBoardNodeData` with:

```ts
interface SwarmBoardNodeData {
  artifactKind?:
    | "detection_rule"
    | "evidence_pack"
    | "lab_run"
    | "conversion_output"
    | "publication_manifest";
  documentId?: string;
  evidencePackId?: string;
  labRunId?: string;
  publicationId?: string;
  format?: FileType;
  publishState?: "draft" | "validated" | "published" | "deployed";
  coverageDelta?: { added: string[]; removed: string[] };
}
```

### User flow

From the editor or lab:

1. `Open Review Swarm`
2. create or focus a board
3. attach:
   - rule artifact node
   - evidence pack artifact node
   - lab run artifact node
   - diff node if comparing versions
   - receipt node after publish
4. spawn agent sessions and terminal tasks for review, hardening, or conversion

### Phase boundary

First phase is local board integration only.

Do not couple the first implementation to remote swarm feed publication. That can come later through `swarm-feed-store.tsx` and `swarm-protocol.ts`.

Also split artifact states explicitly:

- local board artifact: a node persisted in `swarm-board-store.tsx`
- published swarm artifact: a node that also has verified `swarm-protocol` blob or receipt backing

No board node should claim `published` or `deployed` status unless the underlying receipt or blob reference verifies successfully.

## 10. Initiative 5: Publish Path with Provenance

### Current reusable surfaces

- `deploy-panel.tsx`
- `fleet-client.ts`
- `receipt-inspector.tsx`
- `version-store.ts`
- `use-version-history.ts`
- `signature-adapter.ts`

### Architecture

Split the current concept of "deploy" into a broader "publish" pipeline:

1. validate
2. run evidence gate
3. compare with current publication baseline
4. convert
5. sign manifest
6. export or deploy

### Design rule

Native policy deployment remains a special case of publish, not a parallel system.

That means:

- Sigma -> native policy -> deploy uses the same publication manifest flow
- native policy tabs can still use the existing deploy API under the hood
- SPL, KQL, and ES|QL exports stop at signed publication artifacts until connector-specific deployment exists

The current fleet and catalog APIs should be treated as policy-centric. Do not plan the first implementation around publishing arbitrary detection artifacts to them.

### Recommended UI split

- keep `DeployPanel` for backward-compatible policy deployment during migration
- add `PublishPanel` for format-aware publish/export/deploy
- once stable, fold `DeployPanel` into `PublishPanel`
- hard-gate `DeployPanel` and `deployPolicy()` so non-policy tabs can never invoke them directly

### Manifest contents

Minimum manifest fields:

- source file type
- document ID
- source hash
- source version reference
- validation state
- evidence pack ID
- lab run ID
- output hash
- target type
- converter ID and version
- signature or receipt reference
- export path or deploy response

### File changes

Primary files:

- `apps/workbench/src/components/workbench/editor/deploy-panel.tsx`
- `apps/workbench/src/components/workbench/editor/publish-panel.tsx`
- `apps/workbench/src/lib/workbench/detection-workflow/publication-store.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/sigma-adapter.ts`
- `apps/workbench/src/lib/workbench/detection-workflow/policy-adapter.ts`
- `apps/workbench/src/lib/workbench/fleet-client.ts`
- `apps/workbench/src/lib/workbench/signature-adapter.ts`

### Security requirements

- publish must fail closed if validation is invalid
- fleet deploy should require a passing lab run for converted outputs unless explicitly overridden
- signatures should cover the manifest and output hash, not just the source text
- for Sigma -> native policy deployment, the signed manifest hash must cover the converted native-policy artifact that is actually sent to fleet
- publish verification should prove the deployed bytes equal the signed bytes before the workflow records a deployed state

## 11. Initiative 6: Active Coverage Gap Discovery

### Current reusable surfaces

- `hunt-engine.ts`
- `traffic-replay.ts`
- `mitre-attack-data.ts`
- `mitre-heatmap.tsx`
- `coverage-analyzer.ts`

### Problem to solve

The current ATT&CK coverage is passive and document-centric. Users must already have rules open. The next step is to let Hunt say:

- observed behavior suggests missing detection coverage

### Architecture

Add `coverage-gap-engine.ts` that consumes:

- `AgentEvent[]`
- `Investigation[]`
- `HuntPattern[]`
- open document coverage
- optionally published document coverage later

Outputs:

- `CoverageGapCandidate[]`

Required conflict handling:

- de-duplicate against open editor documents and known publication manifests
- keep authoritative coverage separate from inferred coverage
- suppress repeated low-confidence candidates from the same underlying pattern or replay fixture

### Important modeling note

ATT&CK alone is not enough. The engine also needs a small telemetry or data-source vocabulary.

Suggested first-wave data-source families:

- process
- file
- network
- command
- tool
- prompt
- normalized finding

These can be inferred from `AgentEvent.actionType` first, then refined later.

### UI surfaces

Add gap views to:

- Hunt `Patterns`
- Hunt `Investigate`
- editor coverage panel
- command palette search results

Each gap card should offer:

- rationale
- confidence
- linked evidence
- `Draft Detection` action

The first implementation should calibrate on known Hunt and replay fixtures before surfacing high-confidence gap suggestions broadly.

## 12. Initiative 7: Delight Through Explainability

### Current reusable surfaces

- `results-panel.tsx`
- `problems-panel.tsx`
- `version-history-panel.tsx`
- `evaluation-path.tsx`

### Target outcome

Users should be able to answer:

- why did this match?
- why did this fail?
- what changed from the last version?
- what technique or evidence does this correspond to?

### Architecture

Make explainability an explicit output of every lab run.

Per-format expectations:

#### Sigma

- matched selections
- matched field paths and values
- modifier semantics used
- technique hints
- source line hints

#### YARA

- matched strings
- offsets and lengths
- condition summary
- source line hints

#### OCSF

- required vs missing fields
- invalid fields
- class and category interpretation
- source line hints

#### Policy

- existing guard results and evaluation path

### Version-aware explainability

For the same evidence pack, the user should be able to compare:

- current run
- previous saved version
- last published version

This should produce a delta summary such as:

- cases that flipped from pass to fail
- new matches
- new false positives
- ATT&CK techniques added or lost

### UI changes

Add:

- `Explain` tab or panel in the Lab
- inline links from explainability traces back to editor lines or visual sections
- publish preflight summary showing what changed since the last publication

## 13. Architecture Summary

The next wave should be implemented as a workflow layer around the current editor, not as another editor rewrite.

The three most important structural moves are:

1. add `documentId` and keep large workflow data outside `multi-policy-store.tsx`
2. formalize format-specific behavior behind workflow adapters
3. make evidence packs, lab runs, and publication manifests the durable objects that connect Hunt, Lab, Swarm, and Publish

If those three are done cleanly, the seven initiatives can be implemented incrementally without destabilizing the current editor foundation.
