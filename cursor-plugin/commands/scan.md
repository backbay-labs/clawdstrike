---
description: "Scan MCP server configurations for security issues"
---

# ClawdStrike Scan

Scan all configured MCP servers for security vulnerabilities and policy violations.

## Steps

1. Call the `clawdstrike_scan` MCP tool to analyze the current MCP server configurations
2. Group findings by severity level: Critical, High, Medium, Low
3. Present results in this format:

### Output Format

For each finding:
- **Severity**: Critical/High/Medium/Low
- **Guard**: Which guard detected the issue
- **Target**: The affected MCP server or configuration
- **Issue**: What was found
- **Remediation**: Specific steps to fix the issue

### Severity to Risk Mapping

| Severity | Risk Category | Examples |
|----------|--------------|---------|
| **Critical** | RCE / Arbitrary code execution | MCP server with unrestricted shell access, eval-based tool handlers, unsandboxed code interpreters |
| **High** | Auth bypass / Secret exposure | Missing authentication on MCP endpoints, credentials in server config, overprivileged tool permissions |
| **Medium** | Config drift / Overprivileged access | Egress allowlist too broad, file access beyond project scope, deprecated TLS versions |
| **Low** | Info disclosure / Best practice | Verbose error messages, missing rate limiting, no audit logging configured |

### Remediation Priority

Address findings in severity order:
1. **Critical**: Fix immediately. These represent active exploitation vectors. Block the affected MCP server until remediated.
2. **High**: Fix before next session. These could lead to credential compromise or unauthorized access.
3. **Medium**: Fix within the current work cycle. These represent security debt that increases risk over time.
4. **Low**: Track and fix opportunistically. These improve defense-in-depth but are not urgent.

### Summary

End with a summary line:
```
Scan complete: X critical, Y high, Z medium, W low findings across N MCP servers.
```

If no issues are found, confirm that all configurations pass policy checks.
