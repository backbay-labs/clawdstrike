# Detection Storage Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification turns the detection model into a concrete storage schema
> for rules, findings, suppressions, cases, bundles, and pack activation.

## 1. Objective

The detection API needs a durable backend model. This spec defines the first
Postgres-oriented schema slices that fit the current `control-api` baseline.

## 2. Existing Anchors

- Existing `alert_configs` table:
  `crates/services/control-api/migrations/001_init.sql`
- Existing `approvals` and `tenant_active_policies` tables:
  `crates/services/control-api/migrations/002_adaptive_sdr_schema.sql`
  `crates/services/control-api/migrations/004_adaptive_sdr_active_policy.sql`
- Detection rule model:
  `docs/src/fleet-security/detection-rule-model.md`

## 3. Design Invariants

- additive migrations first
- detection tables are tenant-scoped
- findings reference evidence rather than duplicating raw evidence payloads
- suppression records never delete findings
- package install state remains separate from the registry source of truth

## 4. Core Tables

Recommended initial tables:

- `detection_rules`
- `detection_findings`
- `detection_finding_evidence`
- `detection_suppressions`
- `detection_tuning_changes`
- `cases`
- `case_artifacts`
- `evidence_bundles`
- `installed_detection_packs`

## 5. Suggested Schema

```sql
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    severity TEXT NOT NULL,
    source_format TEXT NOT NULL,
    engine_kind TEXT NOT NULL,
    execution_mode TEXT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_text TEXT,
    source_object JSONB,
    compiled_artifact JSONB,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE detection_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    principal_id UUID,
    session_id TEXT,
    grant_id UUID,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE detection_finding_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES detection_findings(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE detection_suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID,
    finding_id UUID,
    scope JSONB NOT NULL DEFAULT '{}'::jsonb,
    match_criteria JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE detection_tuning_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    patch JSONB NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE case_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    added_by TEXT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    file_path TEXT,
    sha256 TEXT,
    size_bytes BIGINT,
    manifest_ref TEXT,
    expires_at TIMESTAMPTZ
);

CREATE TABLE installed_detection_packs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    installed_by TEXT NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (tenant_id, package_name, version)
);
```

## 6. Indexes

Recommended initial indexes:

```sql
CREATE INDEX idx_detection_rules_tenant_enabled
ON detection_rules(tenant_id, enabled, updated_at DESC);

CREATE INDEX idx_detection_findings_tenant_status
ON detection_findings(tenant_id, status, last_seen_at DESC);

CREATE INDEX idx_detection_findings_tenant_rule
ON detection_findings(tenant_id, rule_id, last_seen_at DESC);

CREATE INDEX idx_detection_findings_tenant_principal
ON detection_findings(tenant_id, principal_id, last_seen_at DESC);

CREATE INDEX idx_detection_suppressions_tenant_status
ON detection_suppressions(tenant_id, status, created_at DESC);

CREATE INDEX idx_cases_tenant_status
ON cases(tenant_id, status, updated_at DESC);
```

## 7. Migration Sequencing

Recommended slices:

1. `011_detection_core.sql`
2. `012_detection_cases_and_bundles.sql`
3. `013_detection_pack_install_state.sql`

This keeps detection storage additive and independently reviewable.

## 8. Relationship to Existing Alert Tables

`alert_configs` should remain in place, but it should be treated as downstream
notification config rather than the durable source of detection truth.

Future join:

- findings may trigger alert delivery
- alert config does not replace `detection_rules`

## 9. Implementation Notes

This spec is meant to pair with:

- [Detection API Contract Spec](detection-api-contract.md)
- [Detection and Rule Model Spec](detection-rule-model.md)
- [Suppression and Tuning Model Spec](suppression-tuning-model.md)
- [Case and Evidence Bundle Model Spec](case-evidence-bundle-model.md)
- [Rule Packaging and Distribution Model Spec](rule-packaging-distribution.md)
