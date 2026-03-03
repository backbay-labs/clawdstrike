# @clawdstrike/hipaa

HIPAA compliance policy pack for AI agent environments. Provides guard configurations that enforce access controls aligned with 45 CFR 164.312 (Technical Safeguards).

## Policies

| Policy | Base | Use case |
|--------|------|----------|
| `hipaa-strict.yaml` | `strict` | Production environments handling PHI |
| `hipaa-default.yaml` | `default` | Development and staging with PHI test data |

## Usage

```yaml
# In your clawdstrike policy file:
extends: "@clawdstrike/hipaa/policies/hipaa-strict"
```

Or install and reference directly:

```bash
clawdstrike pkg install @clawdstrike/hipaa
clawdstrike check --ruleset @clawdstrike/hipaa/policies/hipaa-strict --action-type file /path/to/check
```

## Guard Coverage

- **ForbiddenPathGuard** -- blocks access to PHI directories, patient data, EHR exports
- **SecretLeakGuard** -- detects SSNs, MRNs, DEA numbers, NPIs, health plan IDs
- **EgressAllowlistGuard** -- restricts network to HIPAA-compliant endpoints (HL7, FHIR)
- **ShellCommandGuard** -- blocks data exfiltration tools (curl, wget, scp)
- **McpToolGuard** -- restricts MCP tools to read-only operations (strict)
- **PromptInjectionGuard** -- enabled with strict thresholds
- **PatchIntegrityGuard** -- blocks patches that disable security or audit controls

## HIPAA Mapping

| HIPAA Section | Control | Guard |
|---|---|---|
| 164.312(a)(1) | Access Control | ForbiddenPathGuard, PathAllowlistGuard |
| 164.312(b) | Audit Controls | PatchIntegrityGuard (audit log protection) |
| 164.312(c)(1) | Integrity | SecretLeakGuard, PatchIntegrityGuard |
| 164.312(d) | Authentication | McpToolGuard (tool-level auth) |
| 164.312(e)(1) | Transmission Security | EgressAllowlistGuard |

## Customization

Add organization-specific FHIR endpoints to the egress allowlist:

```yaml
extends: "@clawdstrike/hipaa/policies/hipaa-strict"

guards:
  egress_allowlist:
    allow:
      - "fhir.your-ehr.com"
      - "api.your-health-system.org"
```
