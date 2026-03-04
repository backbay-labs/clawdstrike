# Rulesets

Rulesets are built-in policy presets shipped with Clawdstrike.

In this repository, rulesets are defined as YAML files in `rulesets/` and embedded into the Rust binary at build time.

## Built-in rulesets

| ID | Purpose |
|----|---------|
| `default` | Balanced baseline |
| `ai-agent` | Tuned for AI coding assistants |
| `ai-agent-posture` | Posture-aware progressive capabilities for AI agents |
| `strict` | Deny-by-default baseline for sensitive environments |
| `cicd` | Tuned for CI jobs (registries allowed) |
| `permissive` | Dev-friendly (egress defaults to allow; verbose logging) |
| `remote-desktop` | Base CUA security for remote desktop AI agents |
| `remote-desktop-permissive` | Dev-friendly CUA policy (all channels open, observe mode) |
| `remote-desktop-strict` | Maximum CUA security for high-security environments |
| `spider-sense` | Spider-Sense baseline with built-in S2Bench pattern DB + embedding-provider knobs |

## Use a ruleset

### CLI

```bash
clawdstrike check --action-type egress --ruleset default api.github.com:443
```

### As a base policy

```yaml
version: "1.3.0"
name: My Policy
extends: clawdstrike:default
```

### Inspect

```bash
clawdstrike policy show strict
```

## Customize a ruleset

Create a policy file that extends a ruleset and adds overrides:

```yaml
version: "1.3.0"
name: My CI Policy
extends: clawdstrike:cicd

guards:
  egress_allowlist:
    additional_allow:
      - "api.mycompany.com"
```

Note: `extends` supports built-in ruleset ids, local file paths (resolved relative to the policy file), and pinned remote references when enabled via the remote-extends allowlist.

Remote `extends` is hardened by default:

- requires `#sha256=<64-hex>` integrity pins
- HTTPS-only (HTTP requires explicit opt-in)
- blocks private/loopback/link-local IP resolution by default
- limits redirects and re-validates scheme/host allowlists on each hop

## Next steps

- [Default](./default.md)
- [AI Agent](./ai-agent.md)
- [AI Agent Posture](./ai-agent-posture.md)
- [Strict](./strict.md)
- [CI/CD](./cicd.md)
- [Permissive](./permissive.md)
- [Remote Desktop](./remote-desktop.md)
- [Remote Desktop Permissive](./remote-desktop-permissive.md)
- [Remote Desktop Strict](./remote-desktop-strict.md)
- [Spider-Sense](./spider-sense.md)
