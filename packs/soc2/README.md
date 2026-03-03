# @clawdstrike/soc2

SOC2 Type II compliance policy pack with continuous evidence collection. Provides guard configurations aligned with SOC2 Trust Service Criteria (CC6, CC7, CC8).

## Policies

| Policy | Base | Use case |
|--------|------|----------|
| `soc2-strict.yaml` | `strict` | Production environments under audit |
| `soc2-default.yaml` | `default` | Development and staging environments |

## Usage

```yaml
extends: "@clawdstrike/soc2/policies/soc2-strict"
```

```bash
clawdstrike pkg install @clawdstrike/soc2
clawdstrike check --ruleset @clawdstrike/soc2/policies/soc2-strict --action-type file /path/to/check
```

## Guard Coverage

- **ForbiddenPathGuard** -- protects audit logs, evidence directories, Terraform state
- **SecretLeakGuard** -- detects API keys, tokens, credentials, database URLs, JWT secrets
- **EgressAllowlistGuard** -- no egress allowed (strict), limited egress (default)
- **ShellCommandGuard** -- blocks log tampering (truncate, shred), infrastructure mutation
- **McpToolGuard** -- restricts MCP tools to read-only operations (strict)
- **PromptInjectionGuard** -- enabled with strict thresholds
- **PatchIntegrityGuard** -- blocks patches that disable logging, audit, or monitoring

## SOC2 Mapping

| Criteria | Control | Guard |
|---|---|---|
| CC6.1 | Logical access security | ForbiddenPathGuard, McpToolGuard |
| CC6.3 | Restrict access based on need | EgressAllowlistGuard |
| CC7.1 | Detect unauthorized changes | PatchIntegrityGuard |
| CC7.2 | Monitor system components | SecretLeakGuard |
| CC7.3 | Evaluate security events | PromptInjectionGuard, JailbreakGuard |
| CC8.1 | Change management | PatchIntegrityGuard |

## Customization

Extend with your organization's approved services:

```yaml
extends: "@clawdstrike/soc2/policies/soc2-strict"

guards:
  egress_allowlist:
    allow:
      - "api.your-monitoring.com"
      - "logs.your-siem.com"
```
