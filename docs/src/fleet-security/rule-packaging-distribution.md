# Rule Packaging and Distribution Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines how detection rules and detection packs are
> packaged, published, verified, installed, and activated.

## 1. Objective

Clawdstrike already has a package manager and registry model for guards,
policy-packs, adapters, engines, templates, and bundles. Detection rules should
land inside that ecosystem rather than creating a second distribution path.

This spec defines how rule packs should fit into the existing package manager.

## 2. Existing Anchors

- Package manager overview:
  `docs/src/package-manager/index.md`
- Package types:
  `docs/src/package-manager/package-types.md`
- Registry architecture:
  `docs/src/package-manager/registry-architecture.md`
- Trust and verification:
  `docs/src/package-manager/trust-verification.md`
- RFC-0001 package manager:
  `docs/src/rfcs/0001-package-manager.md`

## 3. Design Invariants

- rule distribution should reuse existing package-manager trust and attestation
- rules remain content artifacts, not embedded only in database rows
- installed rule packs should be versioned and auditable
- source authoring format must be preserved
- package install should not automatically enable all rules without tenant
  control
- rule packs should support Sigma, YARA, and native rule assets

## 4. Recommended Packaging Strategy

Phase 1 recommendation:

- reuse `policy-pack` as the initial package type for detection content
- model “detection pack” as a typed subclass of `policy-pack` in package
  metadata

Why:

- the package manager already supports packaged policy/ruleset content
- it avoids introducing a new registry primitive before the execution model is
  stable
- it keeps trust, install, and mirror behavior aligned with the current system

## 5. Detection Pack Manifest Extensions

Recommended package metadata extension:

```toml
[package]
name = "@acme/detection-pack-cloud"
version = "1.0.0"
pkg_type = "policy-pack"

[clawdstrike.detection_pack]
format_version = "1"
contains = ["native_correlation", "sigma", "yara"]
min_clawdstrike_version = "0.1.0"
min_policy_schema = "1.2.0"
default_enable = false
```

## 6. Pack Contents

Recommended pack layout:

```text
clawdstrike-pkg.toml
rules/
  native/
    suspicious-delegation.yaml
  sigma/
    lateral-movement.yml
  yara/
    malicious-script.yar
metadata/
  tags.json
  mappings.json
  mitre.json
tests/
  fixtures/
  expected-findings.json
README.md
```

## 7. Supported Rule Assets

Detection packs should support:

- native correlation YAML
- Sigma YAML
- YARA rules
- optional supporting metadata such as MITRE mappings or tuning defaults

Compilation model:

- native correlation ships directly
- Sigma may ship as source plus compiled native artifact
- YARA ships as source and compiles at install or activation time

## 8. Trust and Verification

Rule packs should inherit the existing package trust model:

- `signed`
- `verified`
- `certified`

This is important because detection content is operationally sensitive. A rule
pack can create fleet-wide noise or suppress visibility if tampered with.

## 9. Installation vs Activation

The platform should distinguish:

- installation: package is downloaded and verified
- activation: one or more rules from the package are enabled for a tenant

Recommended flow:

1. install pack
2. inspect pack contents
3. activate selected rules or default set
4. optionally apply tenant tuning or suppressions

## 10. Activation Record

```typescript
export interface InstalledDetectionPack {
  packageName: string;
  version: string;
  trustLevel: "unverified" | "signed" | "verified" | "certified";
  installedAt: string;
  installedBy: string;
  activatedRules: string[];
}
```

## 11. API Surface

Recommended endpoints:

```text
GET  /api/v1/detections/packs
POST /api/v1/detections/packs/install
GET  /api/v1/detections/packs/{name}/{version}
POST /api/v1/detections/packs/{name}/{version}/activate
POST /api/v1/detections/packs/{name}/{version}/deactivate
GET  /api/v1/detections/packs/{name}/{version}/rules
```

CLI alignment:

```text
clawdstrike pkg install @acme/detection-pack-cloud
clawdstrike detections pack activate @acme/detection-pack-cloud --rule suspicious-delegation
```

## 12. Mirror and Offline Operation

Detection packs should work with:

- mirrored registries
- offline installs from signed `.cpkg` archives
- reproducible pack activation in regulated environments

This is a major reason to keep rule distribution inside the package-manager
system.

## 13. Versioning and Compatibility

Detection packs should declare:

- supported Clawdstrike version
- supported policy schema version where relevant
- required detection engine capabilities
- optional OCSF mapping expectations

Sigma and YARA support may also evolve by capability level rather than just
semantic version.

## 14. Implementation Notes

This spec is meant to pair with:

- [Detection and Rule Model Spec](detection-rule-model.md)
- [Detection API Contract Spec](detection-api-contract.md)
- [Detection Storage Model Spec](detection-storage-model.md)
- [Suppression and Tuning Model Spec](suppression-tuning-model.md)
