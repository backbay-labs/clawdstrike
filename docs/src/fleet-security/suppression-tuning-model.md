# Suppression and Tuning Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines how detections are suppressed, tuned, scoped, and
> reviewed without erasing the underlying evidence trail.

## 1. Objective

Once detections are durable and operator-visible, the next problem is noise.
The platform needs a suppression and tuning model that reduces false positives
without destroying:

- rule provenance
- evidence integrity
- future retrospective investigations
- trust in alert volume metrics

This spec defines that model.

## 2. Existing Anchors

- Detection finding model:
  `docs/src/fleet-security/detection-rule-model.md`
- Existing alert configuration baseline:
  `crates/services/control-api/src/routes/alerts.rs`
- Existing alert dispatch service:
  `crates/services/control-api/src/services/alerter.rs`
- Hunt query and correlation engine:
  `crates/libs/hunt-query`
  `crates/libs/hunt-correlate`

## 3. Design Invariants

- suppression never deletes the underlying event or finding
- tuning and suppression are distinct concepts
- all suppression artifacts are tenant-scoped and auditable
- suppression should support time bounds and scope bounds
- rule edits should be versioned separately from per-tenant suppression state
- operators must be able to distinguish suppressed findings from missing
  findings

## 4. Definitions

### 4.1 Suppression

A post-detection decision that a finding matching certain criteria should not
surface as an active operator alert for some period or scope.

### 4.2 Tuning

A change to rule thresholds, windows, filters, severity, or execution parameters
that changes future detection behavior.

### 4.3 False positive disposition

An operator resolution applied to a specific finding instance or recurring
pattern, not necessarily a permanent suppression.

## 5. Suppression Levels

The platform should support suppression at four levels:

| Level | Example |
|---|---|
| finding instance | suppress one noisy detection occurrence |
| rule + scope | suppress a rule for one project or principal group |
| evidence pattern | suppress repeated matches on a known benign target |
| scheduled silence | suppress matching findings for a time window |

## 6. Canonical Suppression Record

```typescript
export interface DetectionSuppression {
  id: string;
  tenantId: string;
  ruleId?: string;
  findingId?: string;
  scope: {
    principalIds?: string[];
    swarmIds?: string[];
    projectIds?: string[];
    capabilityGroupIds?: string[];
  };
  match?: {
    targetPattern?: string;
    processPattern?: string;
    actionType?: string;
    source?: string;
    metadataSelectors?: Record<string, string>;
  };
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt?: string;
  status: "active" | "expired" | "revoked";
}
```

## 7. Canonical Tuning Record

```typescript
export interface DetectionTuningChange {
  id: string;
  tenantId: string;
  ruleId: string;
  kind:
    | "severity_override"
    | "window_override"
    | "threshold_override"
    | "scope_narrowing"
    | "scope_expansion"
    | "metadata_filter";
  patch: Record<string, unknown>;
  reason: string;
  createdBy: string;
  createdAt: string;
}
```

Design rule:

- suppressions filter surfaced findings
- tuning changes the rule’s future execution behavior

## 8. Evaluation Order

Recommended order:

1. execute rule on normalized events
2. create raw finding candidate
3. apply instance or scoped suppressions
4. assign surfaced state
5. route surfaced findings to alerts, response automation, and console queues

This order ensures the platform still records that a finding would have fired,
even if it is later suppressed.

## 9. Finding States

Recommended finding lifecycle:

| State | Meaning |
|---|---|
| `open` | surfaced and actionable |
| `suppressed` | matched but hidden by active suppression |
| `resolved` | operator resolved |
| `false_positive` | operator marked as false positive |
| `expired` | no longer active after time-based rule/finding semantics |

## 10. Audit Requirements

Every suppression or tuning change should emit:

- actor
- target rule or finding
- scope
- reason
- previous and new values
- expiry if present

These changes must also be queryable in hunt and case timelines.

## 11. Review and Expiry

Suppressions should not live forever by default.

Recommended behavior:

- allow explicit expiry dates
- surface “expiring soon” suppressions in the console
- support periodic review workflows
- distinguish expired suppressions from manually revoked suppressions

## 12. API Surface

Recommended endpoints:

```text
GET    /api/v1/detections/suppressions
POST   /api/v1/detections/suppressions
GET    /api/v1/detections/suppressions/{id}
POST   /api/v1/detections/suppressions/{id}/revoke
GET    /api/v1/detections/tuning
POST   /api/v1/detections/tuning
GET    /api/v1/detections/tuning/{id}
POST   /api/v1/detections/tuning/{id}/revert
POST   /api/v1/detections/findings/{id}/suppress
POST   /api/v1/detections/findings/{id}/false-positive
```

## 13. Implementation Notes

This spec is meant to pair with:

- [Detection and Rule Model Spec](detection-rule-model.md)
- [Detection API Contract Spec](detection-api-contract.md)
- [Detection Storage Model Spec](detection-storage-model.md)
- [Case and Evidence Bundle Model Spec](case-evidence-bundle-model.md)
