# Rulesets

Rulesets are built-in policy presets shipped with Clawdstrike.

In this repository, rulesets are defined as YAML files in `rulesets/` and embedded into the Rust binary at build time.

## Built-in rulesets

| ID | Purpose |
|----|---------|
| `default` | Balanced baseline |
| `ai-agent` | Tuned for AI coding assistants |
| `strict` | Deny-by-default baseline for sensitive environments |
| `cicd` | Tuned for CI jobs (registries allowed) |
| `permissive` | Dev-friendly (egress defaults to allow; verbose logging) |

## Use a ruleset

### CLI

```bash
hush check --action-type egress --ruleset default api.github.com:443
```

### As a base policy

```yaml
version: "1.1.0"
name: My Policy
extends: clawdstrike:default
```

### Inspect

```bash
hush policy show strict
```

## Customize a ruleset

Create a policy file that extends a ruleset and adds overrides:

```yaml
version: "1.1.0"
name: My CI Policy
extends: clawdstrike:cicd

guards:
  egress_allowlist:
    additional_allow:
      - "api.mycompany.com"
```

Note: `extends` supports built-in ruleset ids, local file paths (resolved relative to the policy file), and pinned remote `https://…#sha256=…` / `git+…#sha256=…` references when enabled via the remote-extends allowlist.

## Next steps

- [Default](./default.md)
- [AI Agent](./ai-agent.md)
- [Strict](./strict.md)
- [CI/CD](./cicd.md)
- [Permissive](./permissive.md)
