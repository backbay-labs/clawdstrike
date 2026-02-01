# SecretLeakGuard

Detects secrets and credentials in outputs and patches.

## Overview

The SecretLeakGuard scans content for patterns that match known secret formats, preventing accidental exposure of API keys, tokens, and private keys.

## Detected Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| AWS Access Key | 20-char uppercase starting with AKIA | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 40-char base64 | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| GitHub Token | `ghp_`, `gho_`, `ghs_` prefix | `ghp_xxxxxxxxxxxx` |
| GitLab Token | `glpat-` prefix | `glpat-xxxxxxxxxxxx` |
| OpenAI Key | `sk-` prefix | `sk-xxxxxxxxxxxxxxxx` |
| Anthropic Key | `sk-ant-` prefix | `sk-ant-xxxxxxxxxxxx` |
| Private Key | PEM format | `-----BEGIN RSA PRIVATE KEY-----` |
| Generic API Key | Common patterns | `api_key=`, `apikey:` |

## Configuration

The guard is enabled by default with no configuration needed.

To customize patterns:

```yaml
secrets:
  # Additional patterns (regex)
  additional_patterns:
    - "my_company_token_[a-zA-Z0-9]{32}"
    - "internal_api_key=[a-zA-Z0-9]+"

  # Patterns to ignore (false positives)
  ignored_patterns:
    - "EXAMPLE_KEY"
    - "your-api-key-here"
```

## Example Violations

```
Event: PatchApply { content: "API_KEY=sk-abc123..." }
Decision: Deny
Guard: SecretLeakGuard
Severity: Critical
Reason: Detected OpenAI API key in patch content
```

```
Event: PatchApply { content: "-----BEGIN RSA PRIVATE KEY-----" }
Decision: Deny
Guard: SecretLeakGuard
Severity: Critical
Reason: Detected private key in patch content
```

## Entropy Detection

In addition to pattern matching, high-entropy strings are flagged:

```python
# High entropy (suspicious)
password = "xK9#mP2$vL5@nQ8"

# Low entropy (likely not a secret)
password = "password123"
```

## False Positive Handling

### In-code markers

Use markers to indicate intentional patterns:

```python
# hushclaw: ignore-next-line
API_KEY_PATTERN = "sk-[a-zA-Z0-9]+"  # Regex pattern, not actual key
```

### Policy exceptions

```yaml
secrets:
  ignored_patterns:
    - "sk-test_"          # Test keys
    - "EXAMPLE"           # Example values
    - "your-key-here"     # Placeholders
```

## What's Not Detected

- Encrypted secrets (intentionally)
- Base64-encoded secrets (unless matching known patterns)
- Custom proprietary formats (add via `additional_patterns`)

## Testing

```bash
# Test content for secrets
echo '{"event_type":"patch_apply","data":{"patch_content":"sk-abc123456789"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [PatchIntegrityGuard](./patch-integrity.md) - Dangerous code patterns
- [Policies](../../concepts/policies.md) - Configure secret detection
