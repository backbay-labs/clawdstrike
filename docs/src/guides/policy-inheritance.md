# Policy Inheritance

Policies can inherit from a base policy using `extends`. The base can be a built-in ruleset (embedded), a local file,
or a pinned remote reference when enabled via the remote-extends allowlist.

## Built-in rulesets

- `clawdstrike:default`
- `clawdstrike:ai-agent`
- `clawdstrike:strict`
- `clawdstrike:cicd`
- `clawdstrike:permissive`

List them via:

```bash
clawdstrike policy list
```

## Extend a ruleset

```yaml
version: "1.1.0"
name: My Policy
extends: clawdstrike:default
```

## Extend a file

```yaml
extends: ./base-policy.yaml
```

Paths are resolved relative to the policy file.

Remote `extends` is disabled by default and requires host allowlisting + `#sha256=<64-hex>` integrity pins. By default
only HTTPS is allowed and private IP resolution is blocked; see the [Policy Schema](../reference/policy-schema.md).

## Merge strategies

Child policies can choose a merge strategy:

```yaml
merge_strategy: deep_merge # default
```

- `deep_merge`: recursively merges nested fields (default)
- `merge`: shallow merge (top-level override)
- `replace`: ignore the base entirely

## Add/remove allowlist entries (egress)

In `deep_merge`, egress config supports additive edits:

```yaml
extends: clawdstrike:default

guards:
  egress_allowlist:
    additional_allow:
      - "api.mycompany.com"
    remove_allow:
      - "api.github.com"
```

## Add/remove forbidden paths

```yaml
extends: clawdstrike:default

guards:
  forbidden_path:
    additional_patterns:
      - "**/company-secrets/**"
    remove_patterns:
      - "**/.env.*"
```

## Inspect the merged result

```bash
clawdstrike policy validate --resolve ./policy.yaml
clawdstrike policy show --merged ./policy.yaml
```
