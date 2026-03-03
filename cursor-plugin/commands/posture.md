---
description: "Assess overall security posture with a letter grade"
---

# ClawdStrike Posture

Perform a comprehensive security posture assessment and produce a letter grade (A-F).

## Steps

1. **Get active policy**: Call `clawdstrike_policy_show` to retrieve the current policy and guard configuration
2. **Scan MCP configs**: Call `clawdstrike_scan` to check all MCP server configurations for issues
3. **Check recent denials**: Call `clawdstrike_query` with `verdict=deny` to find recent policy violations

## Scoring

Assess posture across these categories and assign a sub-grade (A-F) to each:

| Category | Weight | What to Check |
|----------|--------|---------------|
| **Policy Strength** | 25% | Ruleset level (strict > default > permissive), number of enabled guards |
| **MCP Config** | 25% | Scan findings -- critical/high issues lower the grade |
| **Violation Rate** | 25% | Frequency and severity of recent denials |
| **Coverage** | 25% | Guard coverage across action types (file, shell, egress, mcp_tool) |

### Grade Scale

| Grade | Score Range | Criteria |
|-------|-----------|----------|
| **A** | 90 - 100 | Strong security posture, strict policy, no critical findings |
| **B** | 80 - 89 | Good posture, minor gaps or medium findings |
| **C** | 70 - 79 | Moderate posture, some high findings or significant gaps |
| **D** | 60 - 69 | Weak posture, critical findings or major gaps in coverage |
| **F** | 0 - 59 | Minimal security, permissive policy with unaddressed critical issues |

### Scoring Examples

**Policy Strength** (25 points max):
- `strict` ruleset with all guards enabled: 25
- `default` ruleset with most guards enabled: 20
- `ai-agent` ruleset with standard config: 18
- `permissive` ruleset: 5
- No policy loaded: 0

**MCP Config** (25 points max):
- Zero findings across all servers: 25
- Low findings only: 20
- Medium findings present: 15
- High findings present: 8
- Critical findings present: 0

**Violation Rate** (25 points max):
- No denials in session: 25
- Occasional denials, no pattern: 20
- Repeated denials on same target (misconfiguration): 15
- Frequent denials with escalation patterns: 5
- Active exploit attempts detected: 0

**Coverage** (25 points max):
- All 4 action types covered (file, shell, egress, mcp_tool): 25
- 3 of 4 action types covered: 18
- 2 of 4 action types covered: 12
- 1 action type covered: 6
- No guard coverage: 0

## Output Format

```
Security Posture: [GRADE]

Policy Strength:  [grade] - [details]
MCP Config:       [grade] - [details]
Violation Rate:   [grade] - [details]
Guard Coverage:   [grade] - [details]

Recommendations:
1. [Most impactful improvement]
2. [Second priority]
3. [Third priority]
```
