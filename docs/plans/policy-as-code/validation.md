# Advanced Policy Validation and Linting for Clawdstrike

## Problem Statement

Current policy validation in Clawdstrike is limited to basic schema checks, missing many semantic and security issues:

### Current Limitations

1. **Schema-Only Validation**: Only checks field types, not semantic correctness
2. **No Security Analysis**: Doesn't detect overly permissive or conflicting rules
3. **No Best Practice Enforcement**: No warnings for suboptimal configurations
4. **Limited Error Messages**: Errors don't explain how to fix issues
5. **No Custom Rules**: Cannot add organization-specific validation rules

### Types of Bugs That Slip Through

| Bug Type | Example | Impact |
|----------|---------|--------|
| Overlapping patterns | `*.github.com` and `api.github.com` both in allow | Confusion, maintenance burden |
| Regex DoS | `(a+)+$` pattern | Performance degradation |
| Ineffective patterns | `test/**` (missing leading `**`) | False sense of security |
| Conflicting rules | Same domain in allow and block | Undefined behavior |
| Unreachable rules | Broader pattern shadows specific | Dead code |

---

## Proposed Solution: Multi-Layer Validation

### Validation Architecture

```
+------------------------------------------------------------------+
|                    Validation Pipeline                             |
+------------------------------------------------------------------+
|                                                                   |
|   +----------+     +----------+     +----------+                  |
|   |  Policy  |     |  Custom  |     | Rulesets |                  |
|   |  File    |     |  Rules   |     |          |                  |
|   +----+-----+     +----+-----+     +----+-----+                  |
|        |               |                 |                        |
|        v               v                 v                        |
|   +--------------------------------------------------+           |
|   |              Validation Engine                    |           |
|   |                                                   |           |
|   |  Layer 1: Syntax Validation                      |           |
|   |  +--------------------------------------------+  |           |
|   |  | - YAML parsing                              |  |           |
|   |  | - JSON Schema validation                    |  |           |
|   |  | - Required field checks                     |  |           |
|   |  +--------------------------------------------+  |           |
|   |                      |                            |           |
|   |                      v                            |           |
|   |  Layer 2: Semantic Validation                    |           |
|   |  +--------------------------------------------+  |           |
|   |  | - Regex/glob compilation                    |  |           |
|   |  | - Reference resolution (extends)            |  |           |
|   |  | - Type coercion checks                      |  |           |
|   |  +--------------------------------------------+  |           |
|   |                      |                            |           |
|   |                      v                            |           |
|   |  Layer 3: Security Analysis                      |           |
|   |  +--------------------------------------------+  |           |
|   |  | - Overly permissive patterns                |  |           |
|   |  | - Conflicting rules                         |  |           |
|   |  | - Regex complexity                          |  |           |
|   |  +--------------------------------------------+  |           |
|   |                      |                            |           |
|   |                      v                            |           |
|   |  Layer 4: Best Practice Checks                   |           |
|   |  +--------------------------------------------+  |           |
|   |  | - Coverage analysis                         |  |           |
|   |  | - Redundancy detection                      |  |           |
|   |  | - Style consistency                         |  |           |
|   |  +--------------------------------------------+  |           |
|   |                      |                            |           |
|   |                      v                            |           |
|   |  Layer 5: Custom Rules                           |           |
|   |  +--------------------------------------------+  |           |
|   |  | - Organization-specific checks              |  |           |
|   |  | - Compliance requirements                   |  |           |
|   |  | - Project conventions                       |  |           |
|   |  +--------------------------------------------+  |           |
|   +--------------------------------------------------+           |
|                          |                                        |
|                          v                                        |
|   +--------------------------------------------------+           |
|   |              Validation Results                   |           |
|   |  +----------+  +----------+  +----------+        |           |
|   |  |  Errors  |  | Warnings |  |  Hints   |        |           |
|   |  +----------+  +----------+  +----------+        |           |
|   +--------------------------------------------------+           |
|                                                                   |
+------------------------------------------------------------------+
```

---

## CLI Interface

### Basic Linting

```bash
# Lint single policy
hush policy lint policy.yaml

# Lint with strict mode (warnings are errors)
hush policy lint --strict policy.yaml

# Lint multiple policies
hush policy lint *.yaml

# Lint with specific ruleset
hush policy lint --rules security policy.yaml

# Lint with custom rules
hush policy lint --config .clawdstrike-lint.yaml policy.yaml

# Output formats
hush policy lint --format pretty policy.yaml
hush policy lint --format json policy.yaml
hush policy lint --format sarif policy.yaml  # GitHub Code Scanning

# Fix auto-fixable issues
hush policy lint --fix policy.yaml
```

### Rule Management

```bash
# List available rules
hush policy lint --list-rules

# Show rule details
hush policy lint --explain SEC001

# Enable/disable specific rules
hush policy lint --enable SEC001,SEC002 --disable STYLE001 policy.yaml

# Generate default config
hush policy lint --init > .clawdstrike-lint.yaml
```

---

## Validation Rules

### Error Level Rules (Must Fix)

#### Syntax Errors (SYN)

```yaml
SYN001:
  name: "Invalid YAML syntax"
  level: error
  example: |
    guards:
      forbidden_path
        patterns:  # Missing colon after forbidden_path
          - "**/.ssh/**"

SYN002:
  name: "Invalid field type"
  level: error
  example: |
    guards:
      forbidden_path:
        patterns: "**/.ssh/**"  # Should be array

SYN003:
  name: "Unknown field"
  level: error
  example: |
    guards:
      forbidden_path:
        paterns: []  # Typo: should be 'patterns'
```

#### Semantic Errors (SEM)

```yaml
SEM001:
  name: "Invalid regex pattern"
  level: error
  example: |
    guards:
      secret_leak:
        patterns:
          - name: bad_regex
            pattern: "("  # Unclosed group

SEM002:
  name: "Invalid glob pattern"
  level: error
  example: |
    guards:
      forbidden_path:
        patterns:
          - "foo[bar"  # Unclosed bracket

SEM003:
  name: "Circular extends reference"
  level: error
  example: |
    # policy-a.yaml
    extends: policy-b.yaml

    # policy-b.yaml
    extends: policy-a.yaml  # Circular!

SEM004:
  name: "Unknown extends reference"
  level: error
  example: |
    extends: nonexistent-policy.yaml  # File doesn't exist

SEM005:
  name: "Unsupported schema version"
  level: error
  example: |
    version: "99.0.0"  # Unknown version
```

### Warning Level Rules (Should Fix)

#### Security Warnings (SEC)

```yaml
SEC001:
  name: "Overly permissive pattern"
  level: warning
  description: "Pattern matches too broadly, may create security gaps"
  example: |
    guards:
      egress_allowlist:
        allow:
          - "*"  # Allows all domains!
  suggestion: "Use specific domain patterns instead of wildcards"

SEC002:
  name: "Conflicting rules"
  level: warning
  description: "Same target appears in both allow and block lists"
  example: |
    guards:
      egress_allowlist:
        allow:
          - "api.github.com"
        block:
          - "*.github.com"  # Conflicts with allow
  suggestion: "Remove from one list or use more specific patterns"

SEC003:
  name: "Regex ReDoS vulnerability"
  level: warning
  description: "Pattern may cause exponential backtracking"
  example: |
    guards:
      secret_leak:
        patterns:
          - name: dangerous
            pattern: "(a+)+"  # Catastrophic backtracking
  suggestion: "Use possessive quantifiers or atomic groups"

SEC004:
  name: "Missing common sensitive paths"
  level: warning
  description: "Policy doesn't block commonly sensitive paths"
  example: |
    guards:
      forbidden_path:
        patterns:
          - "**/.ssh/**"
          # Missing .aws, .env, etc.
  suggestion: "Consider extending 'clawdstrike:default' for comprehensive coverage"

SEC005:
  name: "Permissive default action"
  level: warning
  description: "Default action allows unknown operations"
  example: |
    guards:
      egress_allowlist:
        default_action: allow  # Should be 'block' for security
  suggestion: "Use 'block' as default_action and explicitly allow required domains"
```

#### Pattern Warnings (PAT)

```yaml
PAT001:
  name: "Redundant pattern"
  level: warning
  description: "Pattern is already covered by a broader pattern"
  example: |
    guards:
      forbidden_path:
        patterns:
          - "**/.ssh/**"
          - "**/.ssh/id_rsa"  # Redundant: covered by above
  suggestion: "Remove the more specific pattern"

PAT002:
  name: "Shadowed pattern"
  level: warning
  description: "Pattern will never match due to earlier pattern"
  example: |
    guards:
      egress_allowlist:
        allow:
          - "*.github.com"
          - "api.github.com"  # Shadowed: first pattern matches

PAT003:
  name: "Ineffective pattern"
  level: warning
  description: "Pattern may not match as intended"
  example: |
    guards:
      forbidden_path:
        patterns:
          - ".ssh/**"  # Missing leading **, only matches .ssh at root
  suggestion: "Use '**/.ssh/**' to match at any depth"

PAT004:
  name: "Case sensitivity mismatch"
  level: warning
  description: "Pattern may miss case variants"
  example: |
    guards:
      forbidden_path:
        patterns:
          - "**/.ENV"  # Won't match .env on case-sensitive systems
```

### Hint Level Rules (Nice to Have)

#### Style Hints (STYLE)

```yaml
STYLE001:
  name: "Inconsistent pattern style"
  level: hint
  description: "Patterns use mixed styles"
  example: |
    guards:
      forbidden_path:
        patterns:
          - "**/.ssh/**"
          - ".aws/**"  # Inconsistent: missing leading **
  suggestion: "Use consistent ** prefix for all recursive patterns"

STYLE002:
  name: "Unsorted patterns"
  level: hint
  description: "Patterns are not in alphabetical order"
  auto_fix: true
  suggestion: "Sort patterns alphabetically for readability"

STYLE003:
  name: "Missing description"
  level: hint
  description: "Policy lacks description field"
  example: |
    version: "1.0.0"
    name: "Production"
    # Missing: description
  suggestion: "Add 'description' field documenting policy purpose"

STYLE004:
  name: "Inline comment recommended"
  level: hint
  description: "Complex pattern should have explanatory comment"
  example: |
    guards:
      secret_leak:
        patterns:
          - name: complex
            pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*[A-Za-z0-9]{32,}"
            # Missing comment explaining what this matches
```

---

## Lint Configuration

### Configuration File

```yaml
# .clawdstrike-lint.yaml
version: "1.0"

# Severity overrides
rules:
  # Upgrade warning to error
  SEC001:
    level: error

  # Downgrade to hint
  STYLE002:
    level: hint

  # Disable rule
  STYLE001:
    enabled: false

# Global settings
settings:
  # Fail on warnings in CI
  strict: false

  # Maximum issues before failure
  max_errors: 0
  max_warnings: 10

  # Auto-fix settings
  auto_fix:
    enabled: true
    rules: [STYLE002, STYLE003]

# Custom rules
custom_rules:
  - id: ORG001
    name: "Require production approval domain"
    level: error
    description: "All policies must allow our approval service"
    check: |
      .guards.egress_allowlist.allow | contains(["approval.internal.company.com"])
    message: "Policy must allow 'approval.internal.company.com' for production approval workflow"

  - id: ORG002
    name: "No localhost egress in production"
    level: error
    description: "Production policies must not allow localhost"
    condition:
      path_contains: "production"
    check: |
      (.guards.egress_allowlist.allow // []) | any(. == "localhost" or . == "127.0.0.1") | not
    message: "Production policies must not allow localhost egress"

# File patterns
include:
  - "**/*.yaml"
  - "**/*.yml"

exclude:
  - "node_modules/**"
  - "vendor/**"
  - "**/test/**"
```

### Rule Configuration Options

```yaml
rules:
  SEC001:
    level: error | warning | hint | off
    enabled: true | false
    options:
      # Rule-specific options
      threshold: 0.9
      allowed_wildcards: ["*.example.com"]
```

---

## Validation Output

### Pretty Output (Default)

```
$ hush policy lint policy.yaml

Linting: policy.yaml
====================

ERROR   [SEM001] Invalid regex pattern
        Line 15: guards.secret_leak.patterns[2].pattern
        Pattern "(" has unclosed group

        Fix: Close the regex group or escape the parenthesis

WARNING [SEC002] Conflicting rules
        Lines 8, 12
        Domain "api.github.com" appears in both allow and block lists

        The domain matches:
          - Allow: api.github.com (line 8)
          - Block: *.github.com (line 12)

        Fix: Remove from one list or use more specific patterns

WARNING [PAT001] Redundant pattern
        Line 20: guards.forbidden_path.patterns[5]
        Pattern "**/.ssh/id_rsa" is covered by "**/.ssh/**" (line 18)

        Fix: Remove the redundant pattern

HINT    [STYLE002] Unsorted patterns
        Lines 18-25: guards.forbidden_path.patterns
        Patterns are not in alphabetical order

        Run with --fix to auto-sort

Summary
-------
Errors:   1
Warnings: 2
Hints:    1

Policy is INVALID (1 error)
```

### JSON Output

```json
{
  "file": "policy.yaml",
  "valid": false,
  "issues": [
    {
      "rule": "SEM001",
      "level": "error",
      "message": "Invalid regex pattern",
      "location": {
        "line": 15,
        "column": 13,
        "path": "guards.secret_leak.patterns[2].pattern"
      },
      "context": {
        "pattern": "(",
        "error": "unclosed group"
      },
      "suggestion": "Close the regex group or escape the parenthesis"
    },
    {
      "rule": "SEC002",
      "level": "warning",
      "message": "Conflicting rules",
      "location": {
        "lines": [8, 12],
        "paths": [
          "guards.egress_allowlist.allow[0]",
          "guards.egress_allowlist.block[2]"
        ]
      },
      "context": {
        "domain": "api.github.com",
        "allow_pattern": "api.github.com",
        "block_pattern": "*.github.com"
      },
      "suggestion": "Remove from one list or use more specific patterns"
    }
  ],
  "summary": {
    "errors": 1,
    "warnings": 2,
    "hints": 1
  }
}
```

### SARIF Output (GitHub Code Scanning)

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "clawdstrike-lint",
          "version": "1.0.0",
          "rules": [
            {
              "id": "SEM001",
              "name": "InvalidRegexPattern",
              "shortDescription": {
                "text": "Invalid regex pattern"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SEM001",
          "level": "error",
          "message": {
            "text": "Pattern \"(\" has unclosed group"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "policy.yaml"
                },
                "region": {
                  "startLine": 15,
                  "startColumn": 13
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Security Analysis Details

### Regex Complexity Analysis

```
+------------------------------------------------------------------+
|                    Regex Complexity Checker                        |
+------------------------------------------------------------------+
|                                                                   |
|  Checks for ReDoS vulnerabilities:                               |
|                                                                   |
|  1. Nested quantifiers: (a+)+, (a*)+, (a+)*                      |
|  2. Overlapping alternatives: (a|a)+                              |
|  3. Catastrophic backtracking patterns                            |
|                                                                   |
|  Complexity scoring:                                              |
|    - Low (0-3): Simple literals, character classes               |
|    - Medium (4-6): Bounded quantifiers, alternations             |
|    - High (7-9): Unbounded quantifiers, lookahead                |
|    - Critical (10+): Nested quantifiers, complex alternations    |
|                                                                   |
+------------------------------------------------------------------+
```

### Pattern Coverage Analysis

```
$ hush policy lint --coverage policy.yaml

Pattern Coverage Analysis
=========================

Event Types:
  file_read:      [##########] 100%  (5/5 sensitive paths covered)
  file_write:     [########--]  80%  (4/5 sensitive paths covered)
  network_egress: [######----]  60%  (missing common API domains)
  tool_call:      [##########] 100%

Missing Coverage:
  - file_write: No protection for /etc/passwd (common attack vector)
  - network_egress: Missing *.anthropic.com (AI API)
  - network_egress: Missing *.openai.com (AI API)

Recommendations:
  1. Add "/etc/passwd" to forbidden_path patterns
  2. Add AI API domains to egress allow list
  3. Run: hush policy lint --suggest-patterns
```

### Conflict Detection

```
$ hush policy lint --conflicts policy.yaml

Conflict Analysis
=================

Detected Conflicts:

1. Egress: Allow vs Block conflict
   +-- Allow: api.github.com
   +-- Block: *.github.com
   Resolution: Block wins (more specific first)
   Recommendation: Remove from block or use allow: *.github.com

2. Forbidden Path: Pattern overlap
   +-- "**/.ssh/**" (matches all)
   +-- "**/.ssh/id_rsa" (redundant)
   Resolution: First pattern handles all cases
   Recommendation: Remove redundant pattern

3. Tool Allow/Block: Implicit conflict
   +-- Allow: [bash, python]
   +-- Block: [shell_exec] (bash is a shell)
   Resolution: Explicit allow overrides implicit block
   Recommendation: Consider blocking bash if shell_exec should be blocked

No critical conflicts found.
```

---

## Auto-Fix Capabilities

### Fixable Rules

```yaml
# Auto-fixable rules
auto_fixable:
  - STYLE002  # Sort patterns alphabetically
  - STYLE003  # Add missing description
  - PAT001    # Remove redundant patterns
  - SYN002    # Convert string to array

# Manual fix required
manual_fix:
  - SEM001    # Invalid regex (needs human judgment)
  - SEC001    # Overly permissive (needs review)
  - SEC002    # Conflicting rules (needs decision)
```

### Fix Preview

```bash
$ hush policy lint --fix --dry-run policy.yaml

Auto-fix Preview
================

STYLE002: Sort patterns alphabetically
  Before:
    patterns:
      - "**/.env"
      - "**/.aws/**"
      - "**/.ssh/**"

  After:
    patterns:
      - "**/.aws/**"
      - "**/.env"
      - "**/.ssh/**"

PAT001: Remove redundant pattern
  Remove: "**/.ssh/id_rsa" (covered by "**/.ssh/**")

Apply these fixes? [y/N]
```

---

## Programmatic API

### TypeScript API

```typescript
import {
  PolicyLinter,
  LintConfig,
  LintResult,
  LintRule,
  Severity
} from '@clawdstrike/openclaw';

// Create linter with custom config
const linter = new PolicyLinter({
  rules: {
    SEC001: { level: 'error' },
    STYLE001: { enabled: false }
  },
  customRules: [
    {
      id: 'ORG001',
      name: 'Require company domain',
      level: 'error',
      check: (policy) => {
        const allowed = policy.guards?.egress_allowlist?.allow || [];
        return allowed.includes('*.company.com')
          ? { valid: true }
          : { valid: false, message: 'Must allow *.company.com' };
      }
    }
  ]
});

// Lint policy
const result = await linter.lint('policy.yaml');

console.log(`Valid: ${result.valid}`);
console.log(`Errors: ${result.errors.length}`);
console.log(`Warnings: ${result.warnings.length}`);

for (const issue of result.issues) {
  console.log(`[${issue.rule}] ${issue.message}`);
  console.log(`  Location: ${issue.location.path}`);
  if (issue.suggestion) {
    console.log(`  Fix: ${issue.suggestion}`);
  }
}

// Auto-fix
if (result.fixable.length > 0) {
  const fixed = await linter.fix('policy.yaml', {
    rules: ['STYLE002', 'PAT001'],
    dryRun: false
  });
  console.log(`Fixed ${fixed.appliedFixes.length} issues`);
}

// Get rule info
const rule = linter.getRule('SEC001');
console.log(`Rule: ${rule.name}`);
console.log(`Description: ${rule.description}`);
```

### Rust API

```rust
use clawdstrike::lint::{Linter, LintConfig, LintResult, Severity};

// Create linter
let config = LintConfig {
    rules: vec![
        ("SEC001".into(), Severity::Error),
        ("STYLE001".into(), Severity::Off),
    ].into_iter().collect(),
    ..Default::default()
};

let linter = Linter::with_config(config)?;

// Lint policy
let result = linter.lint_file("policy.yaml")?;

if !result.is_valid() {
    for issue in result.errors() {
        eprintln!("[{}] {}", issue.rule, issue.message);
        eprintln!("  at {}", issue.location);
    }
    std::process::exit(1);
}

// Check specific rules
let conflicts = linter.check_conflicts(&policy)?;
let regex_issues = linter.check_regex_safety(&policy)?;

// Auto-fix
let fixes = linter.suggest_fixes(&result)?;
for fix in fixes {
    if fix.is_safe() {
        fix.apply(&mut policy)?;
    }
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/lint.yml
name: Policy Lint

on:
  push:
    paths:
      - '**/*.yaml'
  pull_request:
    paths:
      - '**/*.yaml'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Clawdstrike
        uses: clawdstrike/setup-action@v1

      - name: Lint Policies
        run: |
          hush policy lint \
            --format sarif \
            --output results.sarif \
            **/*.yaml

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
policy-lint:
  stage: validate
  image: clawdstrike/cli:latest
  script:
    - |
      hush policy lint \
        --format json \
        --output lint-results.json \
        policy.yaml
    - |
      # Strict mode for production branches
      if [ "$CI_COMMIT_BRANCH" = "$CI_DEFAULT_BRANCH" ]; then
        hush policy lint --strict policy.yaml
      fi
  artifacts:
    paths:
      - lint-results.json
    reports:
      codequality: lint-results.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - policy.yaml
        - policies/**
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: clawdstrike-lint
        name: Lint Clawdstrike Policies
        entry: hush policy lint --strict
        language: system
        files: 'policy\.ya?ml$'
        pass_filenames: true
```

### Editor Integration

```json
// .vscode/settings.json
{
  "yaml.schemas": {
    "https://clawdstrike.dev/schemas/policy-v1.json": "policy.yaml"
  },
  "clawdstrike.lint.enable": true,
  "clawdstrike.lint.rules": {
    "SEC001": "error",
    "STYLE001": "hint"
  }
}
```

---

## Implementation Phases

### Phase 1: Core Validation (3 weeks)
- [ ] Syntax validation (SYN rules)
- [ ] Semantic validation (SEM rules)
- [ ] Basic CLI interface
- [ ] JSON output format

### Phase 2: Security Analysis (3 weeks)
- [ ] Security warnings (SEC rules)
- [ ] Pattern analysis (PAT rules)
- [ ] Regex complexity checker
- [ ] Conflict detection

### Phase 3: Developer Experience (2 weeks)
- [ ] Style hints (STYLE rules)
- [ ] Auto-fix capabilities
- [ ] Pretty output with suggestions
- [ ] Configuration file support

### Phase 4: Integration (2 weeks)
- [ ] Custom rule support
- [ ] SARIF output
- [ ] IDE integration (LSP)
- [ ] CI/CD examples

---

## Appendix: Complete Rule Reference

| Rule ID | Name | Level | Auto-Fix |
|---------|------|-------|----------|
| SYN001 | Invalid YAML syntax | error | no |
| SYN002 | Invalid field type | error | yes |
| SYN003 | Unknown field | error | no |
| SEM001 | Invalid regex pattern | error | no |
| SEM002 | Invalid glob pattern | error | no |
| SEM003 | Circular extends reference | error | no |
| SEM004 | Unknown extends reference | error | no |
| SEM005 | Unsupported schema version | error | no |
| SEC001 | Overly permissive pattern | warning | no |
| SEC002 | Conflicting rules | warning | no |
| SEC003 | Regex ReDoS vulnerability | warning | no |
| SEC004 | Missing common sensitive paths | warning | no |
| SEC005 | Permissive default action | warning | no |
| PAT001 | Redundant pattern | warning | yes |
| PAT002 | Shadowed pattern | warning | no |
| PAT003 | Ineffective pattern | warning | no |
| PAT004 | Case sensitivity mismatch | warning | no |
| STYLE001 | Inconsistent pattern style | hint | no |
| STYLE002 | Unsorted patterns | hint | yes |
| STYLE003 | Missing description | hint | yes |
| STYLE004 | Inline comment recommended | hint | no |
