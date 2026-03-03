# @clawdstrike/pci-dss

PCI-DSS v4.0 compliance policy pack for payment processing environments. Provides guard configurations that enforce access controls aligned with PCI-DSS Requirements 3, 4, 6, 7, and 10.

## Policies

| Policy | Base | Use case |
|--------|------|----------|
| `pci-strict.yaml` | `strict` | Production CDE (Cardholder Data Environment) |
| `pci-default.yaml` | `default` | Development and staging environments |

## Usage

```yaml
extends: "@clawdstrike/pci-dss/policies/pci-strict"
```

```bash
clawdstrike pkg install @clawdstrike/pci-dss
clawdstrike check --ruleset @clawdstrike/pci-dss/policies/pci-strict --action-type file /path/to/check
```

## Guard Coverage

- **ForbiddenPathGuard** -- blocks access to cardholder data, payment keys, HSM directories
- **SecretLeakGuard** -- detects PANs (Visa, MC, Amex), CVVs, track data, Stripe keys
- **EgressAllowlistGuard** -- restricts network to PCI-compliant payment processors
- **ShellCommandGuard** -- blocks database dumps, network sniffing, exfiltration tools
- **McpToolGuard** -- restricts MCP tools to read-only operations (strict)
- **PromptInjectionGuard** -- enabled with strict thresholds
- **PatchIntegrityGuard** -- blocks patches that disable encryption or PCI controls

## PCI-DSS Mapping

| Requirement | Control | Guard |
|---|---|---|
| 3.4 | Render PAN unreadable | SecretLeakGuard (PAN detection) |
| 3.5 | Protect stored account data | ForbiddenPathGuard |
| 4.2 | Protect CHD during transmission | EgressAllowlistGuard |
| 6.3 | Security vulnerabilities | PatchIntegrityGuard |
| 7.1 | Restrict access to system components | McpToolGuard |
| 10.2 | Audit trail | PatchIntegrityGuard (audit protection) |

## Customization

Add your payment processor endpoints:

```yaml
extends: "@clawdstrike/pci-dss/policies/pci-strict"

guards:
  egress_allowlist:
    allow:
      - "api.your-processor.com"
```
