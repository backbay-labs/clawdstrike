---
description: "Run a comprehensive security audit on a ClawdStrike policy"
---

# Security Audit

## Audit Stages

### Stage 1: Policy Validation

Call `workbench_validate_policy` with the policy YAML. Check for:
- **Errors** — Schema violations, invalid regex patterns, version mismatches
- **Warnings** — Empty names, short timeouts, suboptimal configurations

### Stage 2: Guard Coverage Analysis

Call `workbench_list_guards` to get the full registry of 13 guards, then compare against the policy. Identify:
- **Active guards** — Enabled and properly configured
- **Inactive guards** — Disabled or missing from the policy
- **Coverage gaps** — Action types with no guard protection

The 13 guards cover 6 categories:
| Category | Guards |
|----------|--------|
| Filesystem | ForbiddenPath, PathAllowlist |
| Network | EgressAllowlist |
| Content | SecretLeak, PatchIntegrity |
| Tools | ShellCommand, McpTool |
| Detection | PromptInjection, Jailbreak, SpiderSense |
| Computer Use | ComputerUse, RemoteDesktopSideChannel, InputInjection |

### Stage 3: Compliance Scoring

Call `workbench_compliance_check` against all three frameworks:

- **HIPAA** (10 requirements) — Healthcare data protection
- **SOC 2** (8 requirements) — Service organization trust criteria
- **PCI-DSS** (7 requirements) — Payment card industry standards

For each framework, note:
- Overall score (percentage of requirements met)
- Specific gaps with citations
- Required guards and settings to close gaps

### Stage 4: Scenario Testing

1. Call `workbench_suggest_scenarios` to generate guard-specific test cases.
2. Combine suggested scenarios with the 20 built-in scenarios (available via the `workbench://scenarios/builtin` resource).
3. Call `workbench_run_all_scenarios` with the combined scenario set.
4. Analyze results:
   - **False negatives** — Attacks that were allowed (critical findings)
   - **False positives** — Benign actions that were blocked (operational issues)
   - **Pass rate** — Overall scenario pass/fail percentage

### Stage 5: Policy Comparison

If comparing against a baseline (e.g., the strict ruleset):
1. Fetch the strict ruleset YAML from the `workbench://rulesets/builtin` resource.
2. Call `workbench_diff_policies` to identify gaps relative to the baseline.
3. Flag any areas where the policy is weaker than the baseline.

### Stage 6: Report Generation

Compile findings into a structured report:

```
## Security Audit Report

### Validation
- Status: [PASS/FAIL]
- Errors: [count]
- Warnings: [count]

### Guard Coverage
- Active: [X]/13 guards
- Gaps: [list uncovered categories]

### Compliance Scores
- HIPAA: [X]% ([Y]/10 requirements met)
- SOC 2: [X]% ([Y]/8 requirements met)
- PCI-DSS: [X]% ([Y]/7 requirements met)

### Test Results
- Scenarios: [X] total, [Y] passed, [Z] failed
- Pass rate: [X]%
- Critical failures: [list]

### Prioritized Recommendations
1. [CRITICAL] ...
2. [HIGH] ...
3. [MEDIUM] ...
```

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Attacks pass through with no guard evaluation; secrets can be exfiltrated |
| **High** | Guards enabled but misconfigured; compliance gaps in active frameworks |
| **Medium** | Non-critical guards missing; detection thresholds too permissive |
| **Low** | Informational; best practices not followed but no direct risk |

## Instructions

- Run all 6 stages in order
- Present findings organized by severity (critical first)
- Provide YAML remediation for each finding
- Include compliance citations where relevant
- End with a prioritized action list
