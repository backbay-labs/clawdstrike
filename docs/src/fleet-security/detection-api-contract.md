# Detection API Contract Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification turns the detection model into a concrete API surface for
> rules, findings, suppressions, cases, packs, and test flows.

## 1. Objective

The detection rule model defines what the platform should support. This spec
defines how operators, services, and the console should interact with it over
HTTP.

## 2. Existing Anchors

- Detection rule model:
  `docs/src/fleet-security/detection-rule-model.md`
- Current alert CRUD:
  `crates/services/control-api/src/routes/alerts.rs`
- Current alert dispatch service:
  `crates/services/control-api/src/services/alerter.rs`

## 3. Design Invariants

- all endpoints are tenant-scoped
- rule CRUD and finding workflow are separate concerns
- finding state transitions are auditable
- pack install/activate is distinct from rule CRUD
- the API should support console use without excessive client-side joins

## 4. Rule Endpoints

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

Create rule request:

```typescript
export interface CreateDetectionRuleRequest {
  name: string;
  description?: string;
  severity: "low" | "medium" | "high" | "critical";
  sourceFormat: "native_correlation" | "sigma" | "yara" | "clawdstrike_policy" | "threshold";
  executionMode: "streaming" | "batch" | "inline" | "scheduled";
  sourceText?: string;
  sourceObject?: Record<string, unknown>;
  tags?: string[];
  enabled?: boolean;
}
```

## 5. Finding Endpoints

```text
GET  /api/v1/detections/findings
GET  /api/v1/detections/findings/{id}
POST /api/v1/detections/findings/{id}/suppress
POST /api/v1/detections/findings/{id}/resolve
POST /api/v1/detections/findings/{id}/false-positive
POST /api/v1/detections/findings/{id}/respond
```

Finding filters should include:

- `status`
- `severity`
- `rule_id`
- `principal_id`
- `session_id`
- `grant_id`
- date range
- text query

## 6. Suppression and Tuning Endpoints

```text
GET    /api/v1/detections/suppressions
POST   /api/v1/detections/suppressions
GET    /api/v1/detections/suppressions/{id}
POST   /api/v1/detections/suppressions/{id}/revoke
GET    /api/v1/detections/tuning
POST   /api/v1/detections/tuning
POST   /api/v1/detections/tuning/{id}/revert
```

## 7. Case and Evidence Endpoints

```text
GET    /api/v1/cases
POST   /api/v1/cases
GET    /api/v1/cases/{id}
PATCH  /api/v1/cases/{id}
POST   /api/v1/cases/{id}/artifacts
GET    /api/v1/cases/{id}/timeline
POST   /api/v1/cases/{id}/evidence/export
GET    /api/v1/evidence-bundles/{export_id}
GET    /api/v1/evidence-bundles/{export_id}/download
```

## 8. Detection Pack Endpoints

```text
GET  /api/v1/detections/packs
POST /api/v1/detections/packs/install
GET  /api/v1/detections/packs/{name}/{version}
POST /api/v1/detections/packs/{name}/{version}/activate
POST /api/v1/detections/packs/{name}/{version}/deactivate
GET  /api/v1/detections/packs/{name}/{version}/rules
```

## 9. Test and Validation Endpoints

Operators will need rule testing before activation.

```text
POST /api/v1/detections/rules/{id}/test
POST /api/v1/detections/rules/validate
POST /api/v1/detections/rules/import/sigma
POST /api/v1/detections/rules/import/yara
```

Recommended test response:

```typescript
export interface DetectionRuleTestResponse {
  ruleId?: string;
  valid: boolean;
  findings: Array<{
    title: string;
    severity: string;
    evidenceRefs: string[];
  }>;
  warnings: string[];
  errors: string[];
}
```

## 10. Authorization Model

Recommended Phase 1 policy:

| Role | Read | Mutate rules/findings |
|---|---|---|
| `viewer` | yes | no |
| `member` | yes | limited finding actions only if explicitly granted later |
| `admin` | yes | yes |
| `owner` | yes | yes |

## 11. Compatibility Notes

The existing `/alerts` endpoints should remain as alert-notification config
surfaces, but they should no longer be mistaken for the detection engine API.

## 12. Implementation Notes

This spec is meant to pair with:

- [Detection Storage Model Spec](detection-storage-model.md)
- [Suppression and Tuning Model Spec](suppression-tuning-model.md)
- [Case and Evidence Bundle Model Spec](case-evidence-bundle-model.md)
- [Rule Packaging and Distribution Model Spec](rule-packaging-distribution.md)
