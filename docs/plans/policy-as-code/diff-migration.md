# Policy Diff and Migration Tooling for Clawdstrike

## Problem Statement

Policy changes in production environments are inherently risky. Without proper tooling:

### Current Challenges

1. **Blind Deployments**: No visibility into what actually changes between policy versions
2. **Breaking Changes**: Policy updates may inadvertently tighten rules, breaking workflows
3. **Rollback Complexity**: No easy way to revert to a previous policy state
4. **Schema Migrations**: Upgrading policy schema versions requires manual intervention
5. **Audit Requirements**: Compliance requires documenting all policy changes

### Real-World Scenarios

| Scenario | Risk | Impact |
|----------|------|--------|
| Add new forbidden path pattern | May block legitimate access | Developer productivity loss |
| Remove egress domain | API integrations silently fail | Service outages |
| Change severity level | Alerts may be missed | Security gaps |
| Upgrade schema version | Incompatible syntax | Policy fails to load |

---

## Proposed Solution

### Feature Overview

```
+------------------------------------------------------------------+
|                    Policy Diff & Migration System                  |
+------------------------------------------------------------------+
|                                                                    |
|   hush policy diff     - Compare two policy versions          |
|   hush policy impact   - Analyze impact of changes            |
|   hush policy migrate  - Upgrade policy schema                |
|   hush policy rollback - Revert to previous version           |
|   hush policy history  - View policy change history           |
|                                                                    |
+------------------------------------------------------------------+
```

### Architecture

```
+------------------------------------------------------------------+
|                     Diff & Migration Architecture                  |
+------------------------------------------------------------------+
|                                                                   |
|   +-----------+      +-----------+      +-----------+            |
|   | Policy A  |      | Policy B  |      | Schema    |            |
|   | (old)     |      | (new)     |      | Registry  |            |
|   +-----+-----+      +-----+-----+      +-----+-----+            |
|         |                  |                  |                   |
|         v                  v                  v                   |
|   +--------------------------------------------------+          |
|   |              Policy Analyzer                      |          |
|   |  +----------+  +----------+  +----------+        |          |
|   |  |  AST     |  |  Semantic|  |  Schema  |        |          |
|   |  |  Parser  |  |  Analyzer|  |  Checker |        |          |
|   |  +----+-----+  +----+-----+  +----+-----+        |          |
|   +--------------------------------------------------+          |
|                          |                                       |
|                          v                                       |
|   +--------------------------------------------------+          |
|   |              Change Detection Engine              |          |
|   |  +----------+  +----------+  +----------+        |          |
|   |  |Structural|  | Semantic |  | Breaking |        |          |
|   |  |  Diff    |  |  Diff    |  |  Change  |        |          |
|   |  +----+-----+  +----+-----+  +----+-----+        |          |
|   +--------------------------------------------------+          |
|                          |                                       |
|                          v                                       |
|   +--------------------------------------------------+          |
|   |              Output Formatters                    |          |
|   |  +----------+  +----------+  +----------+        |          |
|   |  |  Human   |  |   JSON   |  | Markdown |        |          |
|   |  | Readable |  |  Output  |  |  Report  |        |          |
|   |  +----------+  +----------+  +----------+        |          |
|   +--------------------------------------------------+          |
|                                                                   |
+------------------------------------------------------------------+
```

---

## CLI Interface

### Policy Diff

```bash
# Basic diff between two policy files
hush policy diff old.yaml new.yaml

# Diff with breaking change detection
hush policy diff --breaking old.yaml new.yaml

# Diff between git commits
hush policy diff HEAD~1:policy.yaml HEAD:policy.yaml

# Diff against built-in ruleset
hush policy diff clawdstrike:strict ./my-policy.yaml

# Output formats
hush policy diff old.yaml new.yaml --format unified
hush policy diff old.yaml new.yaml --format json
hush policy diff old.yaml new.yaml --format markdown > diff.md

# Ignore specific sections
hush policy diff old.yaml new.yaml --ignore version,description

# Focus on specific guards
hush policy diff old.yaml new.yaml --guards forbidden_path,egress_allowlist
```

### Impact Analysis

```bash
# Analyze impact of policy change
hush policy impact old.yaml new.yaml

# Impact against audit log (what would have changed?)
hush policy impact old.yaml new.yaml --replay audit.json

# Impact summary
hush policy impact old.yaml new.yaml --summary

# CI-friendly impact check
hush policy impact old.yaml new.yaml --fail-on-breaking
```

### Migration

```bash
# Check if migration is needed
hush policy migrate --check policy.yaml

# Migrate to latest schema version
hush policy migrate policy.yaml

# Migrate to specific version
hush policy migrate --to 2.0.0 policy.yaml

# Dry-run migration
hush policy migrate --dry-run policy.yaml

# Generate migration script
hush policy migrate --script policy.yaml > migrate.sh
```

### History and Rollback

```bash
# View policy change history (requires git)
hush policy history policy.yaml

# Show specific historical version
hush policy history policy.yaml --revision abc123

# Rollback to previous version
hush policy rollback policy.yaml --to HEAD~1

# Create rollback commit
hush policy rollback policy.yaml --to HEAD~1 --commit
```

---

## Diff Output Format

### Human-Readable Output

```
Policy Diff: old.yaml -> new.yaml
================================

Summary:
  - 3 additions
  - 1 removal
  - 2 modifications
  - 1 BREAKING CHANGE detected

Guards:
  forbidden_path:
    patterns:
      + "**/secrets/**"        # NEW: Block secrets directory
      + "**/credentials/**"    # NEW: Block credentials directory
      - "**/.vault/**"         # REMOVED: No longer blocking vault

  egress_allowlist:
    allow:
      ~ "*.github.com" -> "api.github.com"  # MODIFIED: More restrictive
                                            # BREAKING: May block github.com subdomain access

    default_action:
      ~ "allow" -> "block"     # MODIFIED
                               # BREAKING: Default behavior changed

Settings:
  fail_fast:
    ~ false -> true            # MODIFIED: Will now fail on first violation

Breaking Changes (1):
  1. egress_allowlist.default_action changed from 'allow' to 'block'
     Impact: All network requests not explicitly allowed will be blocked
     Affected: Any egress to domains not in allow list
```

### JSON Output

```json
{
  "summary": {
    "additions": 3,
    "removals": 1,
    "modifications": 2,
    "breaking_changes": 1
  },
  "changes": [
    {
      "path": "guards.forbidden_path.patterns",
      "type": "addition",
      "value": "**/secrets/**",
      "breaking": false,
      "impact": "Blocks access to paths matching **/secrets/**"
    },
    {
      "path": "guards.egress_allowlist.default_action",
      "type": "modification",
      "old_value": "allow",
      "new_value": "block",
      "breaking": true,
      "impact": "All network requests not explicitly allowed will be blocked",
      "affected_events": ["network_egress"]
    }
  ],
  "breaking_changes": [
    {
      "path": "guards.egress_allowlist.default_action",
      "description": "Default action changed from permissive to restrictive",
      "mitigation": "Add required domains to egress_allowlist.allow before deploying"
    }
  ]
}
```

### Markdown Report

```markdown
# Policy Change Report

**Generated:** 2024-01-15T10:30:00Z
**Old Policy:** old.yaml (v1.0.0)
**New Policy:** new.yaml (v1.1.0)

## Summary

| Metric | Count |
|--------|-------|
| Additions | 3 |
| Removals | 1 |
| Modifications | 2 |
| Breaking Changes | 1 |

## Changes

### Guards

#### forbidden_path

**Patterns Added:**
- `**/secrets/**` - Block secrets directory
- `**/credentials/**` - Block credentials directory

**Patterns Removed:**
- `**/.vault/**` - No longer blocking vault

#### egress_allowlist

**Modified:**
- `*.github.com` -> `api.github.com` (more restrictive)
- `default_action`: `allow` -> `block` **BREAKING**

## Breaking Changes

### 1. Egress Default Action

**Change:** `egress_allowlist.default_action` changed from `allow` to `block`

**Impact:** All network requests not explicitly allowed will be blocked.

**Affected Events:** `network_egress`

**Mitigation:**
1. Review all egress destinations in your application
2. Add required domains to `egress_allowlist.allow`
3. Test with `hush policy simulate` before deploying

## Recommendations

1. Run impact analysis: `hush policy impact old.yaml new.yaml --replay audit.json`
2. Update tests to cover new patterns
3. Notify teams of egress behavior change
```

---

## Breaking Change Detection

### What Constitutes a Breaking Change

```
+------------------------------------------------------------------+
|                  Breaking Change Classification                    |
+------------------------------------------------------------------+
|                                                                   |
|  ALWAYS BREAKING:                                                 |
|  +------------------------------------------------------------+  |
|  | - Adding forbidden path patterns (blocks more paths)        |  |
|  | - Removing egress allow domains (blocks more egress)        |  |
|  | - Changing default_action from 'allow' to 'block'          |  |
|  | - Lowering numeric limits (max_additions, timeout, etc.)   |  |
|  | - Raising severity levels (warn -> deny)                    |  |
|  | - Adding to tool deny list                                  |  |
|  | - Removing from tool allow list                             |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  POTENTIALLY BREAKING:                                            |
|  +------------------------------------------------------------+  |
|  | - Modifying regex patterns (may match more or less)         |  |
|  | - Changing glob patterns (wildcards are tricky)             |  |
|  | - Updating extends reference (inherits different base)      |  |
|  | - Modifying merge_strategy                                  |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  NOT BREAKING:                                                    |
|  +------------------------------------------------------------+  |
|  | - Removing forbidden path patterns (allows more)            |  |
|  | - Adding egress allow domains (allows more)                 |  |
|  | - Changing default_action from 'block' to 'allow'          |  |
|  | - Raising numeric limits                                    |  |
|  | - Lowering severity levels (deny -> warn)                   |  |
|  | - Adding to tool allow list                                 |  |
|  | - Removing from tool deny list                              |  |
|  | - Changing name, description, version                       |  |
|  +------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

### Breaking Change Rules

```yaml
# internal: breaking_change_rules.yaml
rules:
  # Pattern list additions are breaking for deny-lists
  - path_pattern: "guards.*.patterns"
    guard_type: deny
    change_type: addition
    breaking: true
    message: "Adding patterns to deny list blocks more operations"

  # Pattern list removals are breaking for allow-lists
  - path_pattern: "guards.*.allow"
    change_type: removal
    breaking: true
    message: "Removing from allow list blocks more operations"

  # Default action changes
  - path_pattern: "guards.*.default_action"
    old_value: "allow"
    new_value: "block"
    breaking: true
    message: "Changing default to block affects all unmatched operations"

  # Numeric limit decreases
  - path_pattern: "guards.patch_integrity.max_*"
    change_type: decrease
    breaking: true
    message: "Lowering limits may block previously allowed operations"

  # Severity increases
  - path_pattern: "guards.*.severity"
    change_direction: increase
    breaking: true
    message: "Raising severity may cause operations to be blocked instead of warned"
```

---

## Impact Analysis

### Replay-Based Analysis

```bash
# Analyze what would change with new policy
hush policy impact old.yaml new.yaml --replay audit.json
```

Output:

```
Impact Analysis Report
======================

Audit Period: 2024-01-01 to 2024-01-15
Events Analyzed: 10,847

Decision Changes:
  - Total changed: 156 (1.4%)
  - Newly denied: 89
  - Newly allowed: 12
  - Severity changed: 55

Newly Denied Events (Top 10):
  1. network_egress to cdn.example.com (45 occurrences)
     Change: default_action now 'block'
     Mitigation: Add cdn.example.com to egress_allowlist.allow

  2. file_read /app/secrets/config.yaml (23 occurrences)
     Change: New pattern **/secrets/**
     Mitigation: Review if these accesses are legitimate

  3. tool_call: shell_exec (21 occurrences)
     Change: Added to mcp_tool.block
     Mitigation: Use safer alternatives or add exception

Recommendation:
  Before deploying, address the 89 newly denied events
  Run: hush policy simulate new.yaml --events audit.json
```

### Statistical Summary

```json
{
  "analysis": {
    "period": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-15T23:59:59Z"
    },
    "total_events": 10847,
    "decision_changes": {
      "total": 156,
      "percentage": 1.44,
      "breakdown": {
        "allow_to_deny": 89,
        "deny_to_allow": 12,
        "allow_to_warn": 45,
        "warn_to_deny": 10
      }
    },
    "by_guard": {
      "egress_allowlist": {
        "changes": 67,
        "new_denials": 45
      },
      "forbidden_path": {
        "changes": 34,
        "new_denials": 23
      },
      "mcp_tool": {
        "changes": 55,
        "new_denials": 21
      }
    },
    "high_impact_changes": [
      {
        "event_type": "network_egress",
        "target": "cdn.example.com",
        "occurrences": 45,
        "old_decision": "allow",
        "new_decision": "deny"
      }
    ]
  }
}
```

---

## Schema Migration

### Version Upgrade Path

```
+------------------------------------------------------------------+
|                    Schema Version Timeline                         |
+------------------------------------------------------------------+
|                                                                   |
|  v1.0.0 -----> v1.1.0 -----> v2.0.0 -----> v2.1.0               |
|    |             |             |             |                    |
|    |             |             |             +-- Minor changes     |
|    |             |             |                                  |
|    |             |             +-- Major: New guard structure     |
|    |             |                                                |
|    |             +-- Minor: Added mcp_tool guard                  |
|    |                                                              |
|    +-- Initial release                                            |
|                                                                   |
+------------------------------------------------------------------+
```

### Migration Transformations

```yaml
# migrations/v1_to_v2.yaml
from_version: "1.0.0"
to_version: "2.0.0"

transformations:
  # Rename field
  - type: rename
    from: "guards.forbidden_path.patterns"
    to: "guards.filesystem.deny_patterns"

  # Split field
  - type: split
    from: "guards.egress_allowlist"
    to:
      - path: "guards.network.allow_domains"
        selector: ".allow"
      - path: "guards.network.deny_domains"
        selector: ".block"

  # Add required field with default
  - type: add
    path: "guards.filesystem.enabled"
    default: true
    condition: "has(.guards.forbidden_path)"

  # Remove deprecated field
  - type: remove
    path: "guards.deprecated_guard"
    warning: "deprecated_guard has been removed in v2.0.0"

  # Transform value
  - type: transform
    path: "settings.session_timeout_secs"
    transform: |
      if . > 3600 then 3600 else . end  # Cap at 1 hour

  # Add new required section
  - type: add
    path: "metadata"
    default:
      schema_version: "2.0.0"
      migrated_from: "1.0.0"
      migration_date: "${now}"
```

### Migration CLI

```bash
# Check current version and migration path
$ hush policy migrate --check policy.yaml
Current version: 1.0.0
Latest version: 2.0.0
Migration path: 1.0.0 -> 1.1.0 -> 2.0.0

# Preview migration
$ hush policy migrate --dry-run policy.yaml
Migrating policy.yaml from v1.0.0 to v2.0.0

Changes:
  - Rename: guards.forbidden_path.patterns -> guards.filesystem.deny_patterns
  - Split: guards.egress_allowlist -> guards.network.{allow,deny}_domains
  - Add: guards.filesystem.enabled = true
  - Add: metadata section

Run without --dry-run to apply changes

# Apply migration
$ hush policy migrate policy.yaml
Migrating policy.yaml from v1.0.0 to v2.0.0...
Backup created: policy.yaml.bak
Migration complete.
Validating migrated policy...
Policy is valid.

# Migrate with backup disabled (CI)
$ hush policy migrate --no-backup policy.yaml
```

---

## Git Integration

### Policy History

```bash
$ hush policy history policy.yaml

Policy History: policy.yaml
===========================

commit abc123 (HEAD -> main)
Author: Alice <alice@example.com>
Date:   2024-01-15

    Add rate limiting guards

    Changes:
      + guards.mcp_tool.max_args_size
      + guards.patch_integrity.max_additions

---

commit def456
Author: Bob <bob@example.com>
Date:   2024-01-10

    Tighten egress policy

    Changes:
      ~ guards.egress_allowlist.default_action: allow -> block
      + guards.egress_allowlist.allow[]: "*.anthropic.com"

    BREAKING: Default egress behavior changed

---

commit 789ghi
Author: Alice <alice@example.com>
Date:   2024-01-05

    Initial policy configuration
```

### Compare Across Commits

```bash
# Diff between commits
$ hush policy diff HEAD~2:policy.yaml HEAD:policy.yaml

# Diff between branches
$ hush policy diff main:policy.yaml feature/new-guards:policy.yaml

# Diff between tags
$ hush policy diff v1.0.0:policy.yaml v2.0.0:policy.yaml
```

### Rollback

```bash
# View available rollback targets
$ hush policy rollback --list policy.yaml
Available rollback targets:
  HEAD~1 (def456): Tighten egress policy
  HEAD~2 (789ghi): Initial policy configuration

# Preview rollback
$ hush policy rollback --dry-run policy.yaml --to HEAD~1
Rolling back to def456
Changes:
  - guards.mcp_tool.max_args_size (removing)
  - guards.patch_integrity.max_additions (removing)

# Perform rollback
$ hush policy rollback policy.yaml --to HEAD~1
Rolled back to def456
Run 'git commit' to save or 'git checkout policy.yaml' to undo
```

---

## Programmatic API

### TypeScript API

```typescript
import {
  PolicyDiff,
  PolicyMigrator,
  BreakingChangeDetector,
  ImpactAnalyzer
} from '@clawdstrike/openclaw';

// Diff two policies
const oldPolicy = await loadPolicy('old.yaml');
const newPolicy = await loadPolicy('new.yaml');

const diff = PolicyDiff.compare(oldPolicy, newPolicy);

console.log(`Changes: ${diff.changes.length}`);
console.log(`Breaking: ${diff.breakingChanges.length}`);

for (const change of diff.changes) {
  console.log(`${change.type}: ${change.path}`);
  if (change.breaking) {
    console.log(`  BREAKING: ${change.impact}`);
  }
}

// Detect breaking changes
const detector = new BreakingChangeDetector();
const breaking = detector.detect(oldPolicy, newPolicy);

if (breaking.length > 0) {
  throw new Error(`${breaking.length} breaking changes detected`);
}

// Impact analysis with audit log
const analyzer = new ImpactAnalyzer();
const impact = await analyzer.analyze({
  oldPolicy,
  newPolicy,
  auditLog: 'audit.json'
});

console.log(`Events affected: ${impact.changedDecisions.length}`);
console.log(`New denials: ${impact.newDenials.length}`);

// Migrate policy
const migrator = new PolicyMigrator();
const migrated = await migrator.migrate(oldPolicy, {
  targetVersion: '2.0.0',
  dryRun: false
});

await writePolicy('policy.yaml', migrated);
```

### Rust API

```rust
use clawdstrike::diff::{PolicyDiff, DiffOptions, BreakingChangeLevel};
use clawdstrike::migrate::{Migrator, MigrationOptions};

// Diff policies
let old_policy = Policy::from_yaml_file("old.yaml")?;
let new_policy = Policy::from_yaml_file("new.yaml")?;

let diff = PolicyDiff::compare(&old_policy, &new_policy, DiffOptions::default());

for change in &diff.changes {
    println!("{}: {} -> {}", change.path, change.old_value, change.new_value);
}

// Check for breaking changes
let breaking = diff.breaking_changes();
if !breaking.is_empty() {
    for bc in breaking {
        eprintln!("BREAKING: {} - {}", bc.path, bc.description);
    }
    return Err(Error::BreakingChanges(breaking));
}

// Migrate policy
let migrator = Migrator::new()?;
let options = MigrationOptions {
    target_version: "2.0.0".to_string(),
    dry_run: true,
    backup: true,
};

let result = migrator.migrate(&old_policy, options)?;

if result.dry_run {
    println!("Migration preview:");
    for step in &result.steps {
        println!("  {}: {}", step.operation, step.description);
    }
} else {
    result.migrated_policy.to_yaml_file("policy.yaml")?;
}
```

---

## CI/CD Integration

### GitHub Actions for Change Review

```yaml
# .github/workflows/policy-review.yml
name: Policy Change Review

on:
  pull_request:
    paths:
      - 'policy.yaml'
      - 'policies/**'

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for diff

      - name: Setup Clawdstrike
        uses: clawdstrike/setup-action@v1

      - name: Generate Diff Report
        run: |
          hush policy diff \
            origin/main:policy.yaml \
            HEAD:policy.yaml \
            --format markdown > diff-report.md

      - name: Check Breaking Changes
        id: breaking
        run: |
          if hush policy diff --breaking --fail-on-breaking \
            origin/main:policy.yaml HEAD:policy.yaml; then
            echo "breaking=false" >> $GITHUB_OUTPUT
          else
            echo "breaking=true" >> $GITHUB_OUTPUT
          fi

      - name: Comment on PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const diff = fs.readFileSync('diff-report.md', 'utf8');
            const breaking = '${{ steps.breaking.outputs.breaking }}' === 'true';

            const header = breaking
              ? '## :warning: Policy Change Contains Breaking Changes\n\n'
              : '## Policy Change Report\n\n';

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: header + diff
            });

      - name: Require Approval for Breaking Changes
        if: steps.breaking.outputs.breaking == 'true'
        run: |
          gh pr edit ${{ github.event.pull_request.number }} \
            --add-label "breaking-change" \
            --add-label "requires-security-review"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### GitLab CI

```yaml
# .gitlab-ci.yml
policy-diff:
  stage: review
  image: clawdstrike/cli:latest
  script:
    - |
      hush policy diff \
        $CI_MERGE_REQUEST_DIFF_BASE_SHA:policy.yaml \
        HEAD:policy.yaml \
        --format json > diff.json
    - |
      if hush policy diff --breaking --fail-on-breaking \
        $CI_MERGE_REQUEST_DIFF_BASE_SHA:policy.yaml HEAD:policy.yaml; then
        echo "No breaking changes"
      else
        echo "BREAKING CHANGES DETECTED"
        exit 1
      fi
  artifacts:
    reports:
      dotenv: diff.env
    paths:
      - diff.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - policy.yaml
```

---

## Implementation Phases

### Phase 1: Basic Diff (2 weeks)
- [ ] Structural diff between YAML policies
- [ ] Human-readable output format
- [ ] JSON output format
- [ ] CLI commands

### Phase 2: Breaking Change Detection (2 weeks)
- [ ] Breaking change rules engine
- [ ] Configurable rule set
- [ ] CI integration (--fail-on-breaking)

### Phase 3: Impact Analysis (3 weeks)
- [ ] Audit log replay
- [ ] Statistical analysis
- [ ] Impact report generation

### Phase 4: Migration Tools (3 weeks)
- [ ] Migration transformation engine
- [ ] Version upgrade path
- [ ] Backup and rollback
- [ ] Git integration

### Phase 5: Polish (2 weeks)
- [ ] Markdown report generation
- [ ] IDE integration
- [ ] Documentation
- [ ] Migration guides for each version

---

## Appendix: Diff Algorithm

### Structural Diff Algorithm

```
1. Parse both policies into AST (Abstract Syntax Tree)
2. Normalize paths (resolve extends, apply merge strategy)
3. Walk both ASTs in parallel:
   a. For each node in old policy:
      - If present in new: mark as "unchanged" or "modified"
      - If absent in new: mark as "removed"
   b. For each node in new policy:
      - If absent in old: mark as "added"
4. For modified nodes:
   a. Compare values
   b. Determine change type (value change, type change, etc.)
5. Apply breaking change rules to each change
6. Generate output
```

### Semantic Diff for Patterns

```
For pattern lists (glob, regex):
1. Compare set membership
2. Analyze pattern overlap:
   - Does new pattern subsume old?
   - Does old pattern subsume new?
3. Detect broadening vs narrowing:
   - "*.github.com" -> "api.github.com" = narrowing
   - "api.github.com" -> "*.github.com" = broadening
4. Flag as breaking if narrowing in allow-list or broadening in deny-list
```
