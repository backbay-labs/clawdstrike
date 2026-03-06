# Detection and Rule Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the fleet detection model, the supported rule
> families, and how Sigma, YARA, and Clawdstrike-native policy syntax fit
> together.

## 1. Objective

Clawdstrike already has pieces of a detection stack:

- current alert configuration and dispatch in `control-api`
- SIGMA-inspired hunt correlation rules in `hunt-correlate`
- OCSF export for SIEM pipelines
- guard-based and custom-policy detections in the canonical policy model
- an existing YARA integration design under `docs/plans/threat-intel/`

What is still missing is one coherent rule model that explains:

- what a detection rule is in the fleet platform
- which authoring formats are supported
- how those formats compile or execute
- how a detection becomes a durable finding tied to evidence and response

## 2. Existing Anchors

- Current alert CRUD:
  `crates/services/control-api/src/routes/alerts.rs`
- Current alert dispatch service:
  `crates/services/control-api/src/services/alerter.rs`
- SIGMA-inspired correlation schema:
  `crates/libs/hunt-correlate/src/rules.rs`
- OCSF implementation:
  `crates/libs/clawdstrike-ocsf`
- Policy event OCSF export:
  `crates/libs/clawdstrike-policy-event/src/ocsf.rs`
- Threat-intel custom guard model:
  `docs/src/guides/threat-intel.md`
- Existing YARA design reference:
  `docs/plans/threat-intel/yara-integration.md`

## 3. Design Invariants

- the platform has one canonical detection finding model
- rule authoring formats may vary, but execution should converge on a small set
  of engines
- OCSF is the interchange and export schema, not the sole authoring model
- Sigma support should be real, but preferably compile into native execution
  paths
- YARA support should be first-class for content matching, not awkwardly forced
  into a correlation DSL
- the Clawdstrike policy schema remains first-class for control and guard-based
  detections

## 4. Detection Planes

The fleet detection system should support four complementary planes:

| Plane | Primary purpose | Example engine |
|---|---|---|
| Correlation | multi-event temporal detection | native correlation rules |
| Content | file/code/payload pattern matching | YARA |
| Policy/Guard | inline preventive and detective checks | canonical policy schema + custom guards |
| Threshold/Baseline | counters, drift, anomaly thresholds | native threshold engine |

These are not competing. They are separate detection planes that produce the
same downstream finding model.

## 5. Canonical Detection Rule Record

Recommended durable rule record:

```typescript
export interface DetectionRule {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  enabled: boolean;
  severity: "low" | "medium" | "high" | "critical";
  sourceFormat:
    | "native_correlation"
    | "sigma"
    | "yara"
    | "clawdstrike_policy"
    | "threshold";
  engineKind: "correlation" | "content" | "policy_guard" | "threshold";
  executionMode: "streaming" | "batch" | "inline" | "scheduled";
  tags: string[];
  mitreAttack?: string[];
  author?: string;
  sourceText?: string;
  sourceObject?: Record<string, unknown>;
  compiledArtifact?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}
```

This keeps source authoring format distinct from runtime engine kind.

## 6. Canonical Detection Finding Record

Every detection engine should emit the same finding shape.

```typescript
export interface DetectionFinding {
  detectionId: string;
  tenantId: string;
  ruleId: string;
  ruleName: string;
  sourceFormat: DetectionRule["sourceFormat"];
  severity: DetectionRule["severity"];
  status: "open" | "suppressed" | "resolved" | "false_positive";
  title: string;
  summary: string;
  principalId?: string;
  sessionId?: string;
  grantId?: string;
  responseActionIds?: string[];
  evidenceRefs: string[];
  firstSeenAt: string;
  lastSeenAt: string;
  metadata?: Record<string, unknown>;
}
```

This is the canonical finding record that can then be projected into:

- console views
- response triggers
- OCSF Detection Finding exports
- case and evidence bundles

## 7. Native Correlation Rules

Clawdstrike already has a native correlation schema in `hunt-correlate`:

- schema: `clawdstrike.hunt.correlation.v1`
- YAML authoring
- sequence-based conditions
- bind references and evidence lists
- duration windows

That native correlation rule format should remain the primary runtime rule model
for multi-event temporal detections.

Recommended position:

- native correlation is the canonical correlation IR
- Sigma imports should compile to this model when possible

## 8. Sigma Support

Sigma should be supported as an authoring and import format, but not by making
the engine execute arbitrary Sigma YAML directly in every hot path.

Recommended approach:

1. accept Sigma YAML as an import format
2. parse and validate it
3. compile supported constructs into native correlation or threshold rules
4. preserve original Sigma source for provenance
5. record unsupported constructs explicitly during import

Phase 1 target:

- field filters
- simple selections
- severity and metadata
- timeframe / window
- sequential correlations that map cleanly to native rules

Design rule:

Sigma is a compatibility surface and ecosystem bridge. The native correlation
model remains the primary execution target.

## 9. YARA Support

YARA should be a first-class content detection plane.

Recommended scope:

- file writes
- patches and generated code
- artifact uploads
- offline or asynchronous file/content scans

Recommended rule behavior:

- preserve original YARA source
- compile with caching
- record rule name, tags, matched strings, offsets, and severity
- support blocking and non-blocking modes depending on the calling context

YARA findings should still emit the same `DetectionFinding` shape, with richer
content-specific metadata attached.

The existing YARA design under
`docs/plans/threat-intel/yara-integration.md` is a strong implementation anchor
and should be treated as complementary to this fleet rule model.

## 10. Clawdstrike Policy and Custom Guard Support

The canonical policy schema remains a first-class rule surface, especially for:

- inline preventive controls
- posture-sensitive enforcement
- custom guards
- threat-intel integrations

Important distinction:

- policy rules are the control DSL
- detection rules are the fleet finding DSL

But the two should integrate cleanly.

Examples:

- a custom threat-intel guard emits a high-severity detection finding
- repeated guard denies contribute to a threshold or correlation rule
- a policy violation may also be exported as OCSF Detection Finding

This means the platform should not force every detection into Sigma or YARA.

## 11. Threshold and Baseline Rules

Not every useful detection is sequence-based or content-based.

The fleet model should support native threshold rules for:

- repeated denials
- repeated session posture degradation
- stale-heartbeat bursts
- unusual grant issuance volume
- tool or egress spikes

These should compile into a simple native threshold engine rather than abusing
the correlation DSL for counter semantics.

## 12. Rule Packaging and Distribution

Recommended rule packaging model:

- store original authoring source
- store compiled artifact
- support tenant-local and packaged/shared rules
- support versioning, enable/disable, and test mode

Future-friendly source origins:

- built-in
- imported Sigma
- imported YARA
- packaged Clawdstrike detection pack
- tenant-authored custom rule

## 13. OCSF Role in the Detection Model

OCSF should be the standard export and interchange layer for findings and
activity, especially for SIEM integration.

Recommended stance:

- internal normalized fleet events feed detection engines
- detection findings map to OCSF Detection Finding
- process and network activity map through the existing OCSF converters
- OCSF does not replace the internal rule representation

This is already credible because the repo includes:

- `crates/libs/clawdstrike-ocsf`
- `crates/libs/clawdstrike-policy-event/src/ocsf.rs`
- `crates/libs/hunt-query/src/ocsf.rs`

## 14. API Surface

Recommended rule endpoints:

```text
GET    /api/v1/detections/rules
POST   /api/v1/detections/rules
GET    /api/v1/detections/rules/{id}
PATCH  /api/v1/detections/rules/{id}
DELETE /api/v1/detections/rules/{id}
POST   /api/v1/detections/rules/{id}/test
POST   /api/v1/detections/rules/import/sigma
POST   /api/v1/detections/rules/import/yara
```

Recommended finding endpoints:

```text
GET    /api/v1/detections/findings
GET    /api/v1/detections/findings/{id}
POST   /api/v1/detections/findings/{id}/suppress
POST   /api/v1/detections/findings/{id}/resolve
POST   /api/v1/detections/findings/{id}/respond
```

## 15. Relationship to Current Alerts

The current `/alerts` routes are config and dispatch surfaces, not a full
detection model.

Target relationship:

- detections produce findings
- findings may trigger alerts
- alerts remain notification outputs

This is a clearer architecture than trying to stretch alert configs into a
detection engine.

## 16. Open Questions

- How much Sigma coverage should be guaranteed in Phase 1 before falling back to
  import warnings?
- Should YARA execute inline in the endpoint hot path, in async scan workers, or
  both depending on content size and action type?
- Which policy-guard outcomes should be promoted automatically to durable
  detection findings versus left as raw events?

## 17. Implementation Notes

This spec is meant to pair with:

- [Normalized Fleet Event Envelope Spec](normalized-fleet-event-envelope.md)
- [Hunt Backend API and Data Model Spec](hunt-backend.md)
- [Response Execution Pipeline Spec](response-execution-pipeline.md)
- [Suppression and Tuning Model Spec](suppression-tuning-model.md)
- [Case and Evidence Bundle Model Spec](case-evidence-bundle-model.md)
- [Rule Packaging and Distribution Model Spec](rule-packaging-distribution.md)
- [Detection API Contract Spec](detection-api-contract.md)
- [Detection Storage Model Spec](detection-storage-model.md)
- [Fleet Console Read Model Spec](fleet-console-read-model.md)
