# Policy Versioning and Compatibility for Clawdstrike

## Problem Statement

Policy versioning in Clawdstrike currently lacks formal semantics, leading to:

### Current Challenges

1. **No Compatibility Guarantees**: Unknown if a policy works with a given SDK version
2. **Silent Breaking Changes**: Policy schema changes may break existing policies
3. **Version Confusion**: Today `version` is a strict schema boundary, but we have no separate “policy content version”
4. **No Deprecation Path**: No way to sunset old policy features gracefully
5. **Upgrade Anxiety**: Teams hesitate to upgrade SDK due to policy compatibility fears

### Real-World Issues

| Issue | Root Cause | Impact |
|-------|------------|--------|
| Policy fails after SDK upgrade | Schema changed incompatibly | Production outage |
| New guard not recognized | SDK too old for policy | Silent security gap |
| Deprecated feature removed | No migration warning | Policy load failure |
| Test failures after upgrade | Behavior changed | CI/CD blocked |

---

## Repo Reality (Current Implementation)

This document is partly aspirational (a more complete semantic versioning + compatibility system), but the *current* behavior in this repo is:

- In **v1**, the top-level `version` field is the **policy schema version** (not a user-defined policy content version).
- Runtimes currently support **exactly** `version: "1.1.0"` and **fail closed** on any other version.
- Policies also fail closed on **unknown fields** (`serde(deny_unknown_fields)` in Rust).
- Legacy inputs (`version: "1.0.0"` and OpenClaw-shaped “clawdstrike-v1.0” policies) are intended to be handled via migration/translation tooling (see `hush policy migrate` and the TS legacy translator).

### Schema `1.1.0` highlights (implemented)

- `custom_guards[]`: policy-driven custom guard instances (`id`, `enabled`, `config`).
- `guards.forbidden_path.exceptions[]`: allowlisted path globs that bypass forbidden patterns.
- `guards.forbidden_path.additional_patterns[]` / `guards.forbidden_path.remove_patterns[]`: extend-time pattern add/remove helpers.

## Proposed Solution: Semantic Policy Versioning

### Version Model

```
+------------------------------------------------------------------+
|                    Policy Version Model                            |
+------------------------------------------------------------------+
|                                                                   |
|   Policy Version: X.Y.Z                                          |
|                   | | |                                          |
|                   | | +-- Patch: Bug fixes, documentation        |
|                   | +---- Minor: New features, backward compat   |
|                   +------ Major: Breaking changes                 |
|                                                                   |
|   SDK Version: A.B.C                                              |
|   Policy Schema Version: N.M.P                                    |
|                                                                   |
|   Compatibility Matrix:                                           |
|   +----------------+-------------------+------------------------+ |
|   | Policy Schema  | SDK Min Version   | SDK Max Version        | |
|   +----------------+-------------------+------------------------+ |
|   | 1.0.x          | 1.0.0             | 2.x.x                  | |
|   | 1.1.x          | 1.2.0             | 2.x.x                  | |
|   | 2.0.x          | 2.0.0             | 3.x.x                  | |
|   +----------------+-------------------+------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Version Fields

```yaml
# v1 policy.yaml (as implemented today)
version: "1.1.0"              # Policy schema version (Clawdstrike-defined, strict)

name: "Production Policy"
description: "Security policy for production AI agents"

custom_guards:
  - id: "acme-threat-intel"
    enabled: true
    config:
      api_key: "${ACME_THREAT_INTEL_API_KEY}"

guards:
  # ... guard configuration
```

> Future direction: add an explicit policy content version and compatibility metadata; see the remainder of this document.

---

## Schema Versioning

### Schema Version Semantics

```
MAJOR.MINOR.PATCH

MAJOR: Breaking schema changes
  - Removed fields
  - Changed field types
  - Changed semantics of existing fields
  - Renamed required fields

MINOR: Backward-compatible additions
  - New optional fields
  - New guards
  - New enum values
  - New features (opt-in)

PATCH: Bug fixes and clarifications
  - Documentation updates
  - Validation improvements
  - Default value changes (if safe)
```

### Schema Evolution Example

```yaml
# Schema 1.0.0 (Initial)
guards:
  forbidden_path:
    patterns: [string]

# Schema 1.1.0 (Added exceptions + custom_guards - MINOR)
custom_guards:
  - id: string
    enabled: boolean
    config: object

guards:
  forbidden_path:
    patterns: [string]
    exceptions: [string]  # NEW optional field

# Schema 1.2.0 (Added severity - MINOR)
guards:
  forbidden_path:
    patterns: [string]
    exceptions: [string]
    severity: string       # NEW optional field (default: "high")

# Schema 2.0.0 (Restructured - MAJOR)
guards:
  filesystem:              # RENAMED from forbidden_path
    deny_patterns: [string] # RENAMED from patterns
    allow_patterns: [string] # RENAMED from exceptions
    severity: string
```

---

## Compatibility Checking

### CLI Interface

```bash
# Check policy compatibility with current SDK
hush policy version policy.yaml

# Check compatibility with specific SDK version
hush policy version policy.yaml --sdk-version 2.0.0

# Check if policy can be upgraded
hush policy version policy.yaml --check-upgrade

# List required features
hush policy version policy.yaml --features

# Show deprecation warnings
hush policy version policy.yaml --deprecations
```

### Output Examples

```
$ hush policy version policy.yaml

Policy Version Information
==========================

Policy Version:     1.2.0
Schema Version:     1.1.0
Current SDK:        1.5.0

Compatibility:      OK
  SDK Min Required: 1.0.0
  SDK Max Allowed:  2.x.x

Features Used:
  - forbidden_path guard
  - egress_allowlist guard
  - secret_leak guard

Deprecation Warnings:
  - None

Upgrade Available:
  - Schema 1.1.0 available (run: hush policy migrate)
```

```
$ hush policy version policy.yaml --sdk-version 0.9.0

Policy Version Information
==========================

Policy Version:     1.2.0
Schema Version:     1.1.0
Target SDK:         0.9.0

Compatibility:      INCOMPATIBLE

Errors:
  - Policy requires SDK >= 1.0.0, but target is 0.9.0
  - Feature 'egress_allowlist' requires SDK >= 1.0.0

Recommendation:
  - Upgrade SDK to 1.0.0 or later
  - Or remove egress_allowlist guard from policy
```

---

## Deprecation Management

### Deprecation Lifecycle

```
+------------------------------------------------------------------+
|                    Deprecation Lifecycle                          |
+------------------------------------------------------------------+
|                                                                   |
|   Phase 1: ACTIVE                                                |
|   +----------------------------------------------------------+  |
|   | Feature is actively used and supported                    |  |
|   | No warnings shown                                         |  |
|   +----------------------------------------------------------+  |
|                        |                                         |
|                        v                                         |
|   Phase 2: DEPRECATED (minimum 2 minor versions)                |
|   +----------------------------------------------------------+  |
|   | Feature still works                                       |  |
|   | Warning shown on policy load                              |  |
|   | Documentation updated with migration guide                |  |
|   +----------------------------------------------------------+  |
|                        |                                         |
|                        v                                         |
|   Phase 3: REMOVED (major version)                              |
|   +----------------------------------------------------------+  |
|   | Feature no longer available                               |  |
|   | Policy fails to load with clear error                     |  |
|   | Migration tool available                                  |  |
|   +----------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

### Deprecation Registry

```yaml
# internal: deprecations.yaml
deprecations:
  - feature: "guards.forbidden_path"
    deprecated_in: "1.5.0"
    removed_in: "2.0.0"
    replacement: "guards.filesystem"
    migration_guide: |
      Replace `guards.forbidden_path` with `guards.filesystem`:

      Before:
        guards:
          forbidden_path:
            patterns: ["**/.ssh/**"]

      After:
        guards:
          filesystem:
            deny_patterns: ["**/.ssh/**"]

  - feature: "settings.timeout"
    deprecated_in: "1.3.0"
    removed_in: "2.0.0"
    replacement: "settings.session_timeout_secs"
    auto_migrate: true
    migration_transform: |
      .settings.session_timeout_secs = .settings.timeout
      | del(.settings.timeout)
```

### Deprecation Warnings

```
$ hush policy lint policy.yaml

Policy Validation: policy.yaml
==============================

Warnings:
  - DEPRECATED: guards.forbidden_path is deprecated since v1.5.0
    Will be removed in: v2.0.0
    Replacement: guards.filesystem
    Run: hush policy migrate --to 1.5.0 policy.yaml

  - DEPRECATED: settings.timeout is deprecated since v1.3.0
    Will be removed in: v2.0.0
    Replacement: settings.session_timeout_secs
    Auto-migration available

Policy is valid with 2 deprecation warnings.
```

---

## Feature Flags

### Feature Detection

```yaml
# policy.yaml
compatibility:
  features_required:
    - rego_evaluation        # Requires OPA/Rego support
    - rate_limiting          # Requires rate limiting guard
    - time_based_rules       # Requires time condition support
```

### Feature Registry

```yaml
# internal: features.yaml
features:
  - name: rego_evaluation
    since_sdk: "1.5.0"
    description: "OPA/Rego policy evaluation"
    detection: |
      .rego != null

  - name: rate_limiting
    since_sdk: "1.3.0"
    description: "Rate limiting guards"
    detection: |
      .guards.rate_limit != null

  - name: time_based_rules
    since_sdk: "1.4.0"
    description: "Time-based policy conditions"
    detection: |
      .. | .time_condition? | select(. != null)

  - name: multi_tenant
    since_sdk: "2.0.0"
    description: "Multi-tenant policy isolation"
    detection: |
      .tenant_id != null
```

### Feature Compatibility Check

```bash
$ hush policy version policy.yaml --features

Features Analysis
=================

Features Required by Policy:
  - rego_evaluation (since SDK 1.5.0)      [OK - SDK 1.6.0]
  - rate_limiting (since SDK 1.3.0)        [OK - SDK 1.6.0]
  - time_based_rules (since SDK 1.4.0)     [OK - SDK 1.6.0]

Features Available (not used):
  - multi_tenant (since SDK 2.0.0)         [SDK too old]
  - custom_guards (since SDK 1.7.0)        [OK - not used]

SDK Feature Coverage: 100% (3/3 required features supported)
```

---

## Version Bumping

### CLI Commands

```bash
# Show current version
hush policy version policy.yaml

# Bump patch version (1.2.0 -> 1.2.1)
hush policy version --bump patch policy.yaml

# Bump minor version (1.2.1 -> 1.3.0)
hush policy version --bump minor policy.yaml

# Bump major version (1.3.0 -> 2.0.0)
hush policy version --bump major policy.yaml

# Set specific version
hush policy version --set 2.0.0-beta.1 policy.yaml

# Bump with automatic changelog
hush policy version --bump minor --changelog policy.yaml
```

### Version Bump Rules

```yaml
# Auto-bump recommendations based on diff analysis
version_bump_rules:
  major:
    - removed_guard
    - renamed_required_field
    - changed_default_action_restrictive
    - removed_pattern_from_allowlist

  minor:
    - added_guard
    - added_optional_field
    - added_pattern_to_allowlist
    - removed_pattern_from_denylist

  patch:
    - documentation_change
    - description_update
    - reordered_patterns
```

### Automatic Version Suggestion

```bash
$ hush policy version --suggest-bump policy.yaml

Analyzing changes from last committed version...

Changes detected:
  + guards.egress_allowlist.allow[]: "*.newdomain.com"
  ~ guards.patch_integrity.max_additions: 500 -> 600

Recommendation: PATCH bump (1.2.0 -> 1.2.1)
Reason: Changes are backward-compatible relaxations

Apply? [y/N]
```

---

## Compatibility Matrix

### Matrix Definition

```yaml
# internal: compatibility_matrix.yaml
sdk_versions:
  - version: "1.0.0"
    release_date: "2024-01-01"
    schema_versions: ["1.0.0"]
    features: []
    deprecated: []

  - version: "1.1.0"
    release_date: "2024-02-01"
    schema_versions: ["1.0.0"]
    features: ["egress_allowlist"]
    deprecated: []

  - version: "1.2.0"
    release_date: "2024-03-01"
    schema_versions: ["1.0.0", "1.1.0"]
    features: ["egress_allowlist", "mcp_tool"]
    deprecated: []

  - version: "1.5.0"
    release_date: "2024-06-01"
    schema_versions: ["1.0.0", "1.1.0"]
    features: ["egress_allowlist", "mcp_tool", "rego_evaluation"]
    deprecated: ["guards.forbidden_path"]

  - version: "2.0.0"
    release_date: "2025-01-01"
    schema_versions: ["2.0.0"]
    features: ["filesystem", "network", "rego_evaluation", "multi_tenant"]
    removed: ["guards.forbidden_path", "settings.timeout"]
```

### Matrix Visualization

```
$ hush policy version --matrix

Clawdstrike Compatibility Matrix
================================

Schema    | SDK 1.0 | SDK 1.1 | SDK 1.2 | SDK 1.5 | SDK 2.0
----------|---------|---------|---------|---------|--------
1.0.0     |   OK    |   OK    |   OK    |   OK    | MIGRATE
1.1.0     |    -    |    -    |   OK    |   OK    | MIGRATE
2.0.0     |    -    |    -    |    -    |    -    |   OK

Legend:
  OK      = Fully compatible
  MIGRATE = Migration required (schema upgrade)
  -       = Not supported

Current: SDK 1.5.0, Schema 1.1.0
```

---

## Programmatic API

### TypeScript API

```typescript
import {
  PolicyVersion,
  CompatibilityChecker,
  VersionBumper,
  DeprecationChecker
} from '@clawdstrike/openclaw';

// Parse version from policy
const policy = await loadPolicy('policy.yaml');
const version = PolicyVersion.parse(policy);

console.log(`Policy version: ${version.policy}`);
console.log(`Schema version: ${version.schema}`);

// Check compatibility
const checker = new CompatibilityChecker();
const result = checker.check(policy, {
  sdkVersion: '2.0.0'
});

if (!result.compatible) {
  console.log('Incompatibility reasons:');
  for (const reason of result.reasons) {
    console.log(`  - ${reason}`);
  }
}

// Check deprecations
const deprecations = new DeprecationChecker();
const warnings = deprecations.check(policy);

for (const warning of warnings) {
  console.log(`DEPRECATED: ${warning.feature}`);
  console.log(`  Removed in: ${warning.removedIn}`);
  console.log(`  Migration: ${warning.migrationGuide}`);
}

// Bump version
const bumper = new VersionBumper();
const suggestion = await bumper.suggest(policy, {
  basedOnDiff: true,
  gitRef: 'HEAD~1'
});

console.log(`Suggested bump: ${suggestion.type}`);
console.log(`New version: ${suggestion.newVersion}`);

if (suggestion.approved) {
  const updated = bumper.apply(policy, suggestion);
  await writePolicy('policy.yaml', updated);
}
```

### Rust API

```rust
use clawdstrike::version::{
    PolicyVersion, CompatibilityChecker, VersionBumper, BumpType
};

// Parse version
let policy = Policy::from_yaml_file("policy.yaml")?;
let version = PolicyVersion::from_policy(&policy)?;

println!("Policy version: {}", version.policy);
println!("Schema version: {}", version.schema);

// Check compatibility
let checker = CompatibilityChecker::new()?;
let result = checker.check(&policy, SdkVersion::parse("2.0.0")?)?;

match result {
    CompatibilityResult::Compatible => println!("Compatible"),
    CompatibilityResult::Incompatible { reasons } => {
        for reason in reasons {
            eprintln!("Incompatible: {}", reason);
        }
    }
    CompatibilityResult::NeedsMigration { from, to } => {
        println!("Migration needed: {} -> {}", from, to);
    }
}

// Bump version
let bumper = VersionBumper::new();
let new_version = bumper.bump(&policy, BumpType::Minor)?;

println!("New version: {}", new_version);

// Save updated policy
policy.set_version(new_version);
policy.to_yaml_file("policy.yaml")?;
```

---

## CI/CD Integration

### Version Enforcement

```yaml
# .github/workflows/version-check.yml
name: Policy Version Check

on:
  pull_request:
    paths:
      - 'policy.yaml'

jobs:
  version-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Clawdstrike
        uses: clawdstrike/setup-action@v1

      - name: Check Version Bump
        run: |
          # Get versions
          OLD_VERSION=$(git show HEAD~1:policy.yaml | hush policy version --format json | jq -r '.policy')
          NEW_VERSION=$(hush policy version policy.yaml --format json | jq -r '.policy')

          if [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
            echo "::error::Policy changed but version not bumped"
            echo "Run: hush policy version --bump <patch|minor|major> policy.yaml"
            exit 1
          fi

      - name: Verify Compatibility
        run: |
          hush policy version policy.yaml --check-upgrade
          if [ $? -ne 0 ]; then
            echo "::error::Policy has compatibility issues"
            exit 1
          fi

      - name: Check Deprecations
        run: |
          DEPRECATIONS=$(hush policy version policy.yaml --deprecations --format json | jq '.count')
          if [ "$DEPRECATIONS" -gt 0 ]; then
            echo "::warning::Policy uses $DEPRECATIONS deprecated features"
            hush policy version policy.yaml --deprecations
          fi
```

### Changelog Generation

```yaml
# .github/workflows/release.yml
name: Policy Release

on:
  push:
    tags:
      - 'policy-v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Generate Changelog
        run: |
          VERSION=$(echo ${{ github.ref_name }} | sed 's/policy-v//')
          hush policy changelog --from policy-v$(echo $VERSION | awk -F. '{print $1"."$2-1".0"}') --to ${{ github.ref_name }} > CHANGELOG.md

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          body_path: CHANGELOG.md
          files: policy.yaml
```

### GitLab CI

```yaml
# .gitlab-ci.yml
policy-version-check:
  stage: validate
  image: clawdstrike/cli:latest
  script:
    - |
      # Check version was bumped
      OLD_VERSION=$(git show HEAD~1:policy.yaml | hush policy version --format json | jq -r '.policy')
      NEW_VERSION=$(hush policy version policy.yaml --format json | jq -r '.policy')

      if [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
        echo "ERROR: Policy changed but version not bumped"
        exit 1
      fi
    - |
      # Check compatibility
      hush policy version policy.yaml --check-upgrade
    - |
      # Check deprecations
      DEPRECATIONS=$(hush policy version policy.yaml --deprecations --format json | jq '.count')
      if [ "$DEPRECATIONS" -gt 0 ]; then
        echo "WARNING: Policy uses $DEPRECATIONS deprecated features"
        hush policy version policy.yaml --deprecations
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - policy.yaml

policy-release:
  stage: deploy
  image: clawdstrike/cli:latest
  script:
    - |
      VERSION=$(echo $CI_COMMIT_TAG | sed 's/policy-v//')
      hush policy changelog \
        --from policy-v$(echo $VERSION | awk -F. '{print $1"."$2-1".0"}') \
        --to $CI_COMMIT_TAG > CHANGELOG.md
    - |
      # Upload artifacts or publish to registry
      echo "Publishing policy version $VERSION"
  artifacts:
    paths:
      - CHANGELOG.md
      - policy.yaml
  rules:
    - if: $CI_COMMIT_TAG =~ /^policy-v/
```

---

## Best Practices

### Version Control

```
DO:
  - Commit policy.yaml to version control
  - Tag releases with policy-vX.Y.Z
  - Use meaningful commit messages
  - Review policy changes like code changes

DON'T:
  - Edit production policies directly
  - Skip version bumps for "small" changes
  - Ignore deprecation warnings
  - Deploy without compatibility checks
```

### Version Numbering

```
DO:
  - Start at 1.0.0 for production policies
  - Use pre-release versions for testing (1.0.0-beta.1)
  - Bump major version for breaking changes
  - Document changes in commit messages

DON'T:
  - Use 0.x.x for production policies
  - Skip version numbers
  - Reset to 1.0.0 after reaching high numbers
```

### Upgrade Process

```
1. Check compatibility: hush policy version --check-upgrade
2. Review deprecations: hush policy version --deprecations
3. Run migration: hush policy migrate --dry-run
4. Update tests: hush policy test
5. Apply migration: hush policy migrate
6. Bump version: hush policy version --bump minor
7. Commit and deploy
```

---

## Implementation Phases

### Phase 1: Core Versioning (2 weeks)
- [ ] Schema version validation
- [ ] Policy version field
- [ ] Basic compatibility checking
- [ ] CLI commands

### Phase 2: Deprecation System (2 weeks)
- [ ] Deprecation registry
- [ ] Warning system
- [ ] Migration guides
- [ ] Auto-migration

### Phase 3: Feature Flags (2 weeks)
- [ ] Feature registry
- [ ] Feature detection
- [ ] Compatibility matrix
- [ ] SDK version checking

### Phase 4: Tooling (2 weeks)
- [ ] Version bumping
- [ ] Changelog generation
- [ ] CI/CD integration
- [ ] Documentation

---

## Appendix: Schema Version History

### Version 1.0.0 (Initial)

```yaml
version: "1.0.0"
guards:
  forbidden_path:
    patterns: [string]
  egress_allowlist:
    allow: [string]
    block: [string]
    default_action: "allow" | "block"
  secret_leak:
    patterns:
      - name: string
        pattern: string
        severity: "low" | "medium" | "high" | "critical"
  patch_integrity:
    max_additions: number
    max_deletions: number
    forbidden_patterns: [string]
settings:
  fail_fast: boolean
  verbose_logging: boolean
  session_timeout_secs: number
```

### Version 1.1.0

```yaml
# Added fields in 1.1.0:
guards:
  forbidden_path:
    exceptions: [string]     # NEW
  mcp_tool:                  # NEW guard
    allow: [string]
    block: [string]
    require_confirmation: [string]
    default_action: "allow" | "block"
    max_args_size: number
```

### Version 2.0.0 (Planned)

```yaml
# Breaking changes in 2.0.0:
schema_version: "2.0.0"      # NEW required field

guards:
  filesystem:                # RENAMED from forbidden_path
    deny_patterns: [string]  # RENAMED from patterns
    allow_patterns: [string] # RENAMED from exceptions
    enabled: boolean         # NEW required field

  network:                   # RENAMED from egress_allowlist
    allow_domains: [string]  # RENAMED from allow
    deny_domains: [string]   # RENAMED from block
    default_action: "allow" | "deny"  # "block" -> "deny"

metadata:                    # NEW required section
  name: string
  description: string
  author: string

compatibility:               # NEW optional section
  sdk_min_version: string
  features_required: [string]
```
