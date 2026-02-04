# Claude Code Integration (conceptual)

Clawdstrike does not currently ship a `hush run` process wrapper that can transparently sandbox Claude Code.

To enforce Clawdstrike decisions, you need to integrate at the **tool boundary** (the layer that performs file/network/tool operations on behalf of the model).

## Practical workflow today

1. Pick a ruleset baseline:

```bash
hush policy list
hush policy show ai-agent
```

2. Write a policy file that extends it (optional):

```yaml
version: "1.1.0"
name: My Claude Policy
extends: clawdstrike:ai-agent
```

3. Validate and resolve:

```bash
hush policy validate ./policy.yaml
hush policy validate --resolve ./policy.yaml
```

4. Use `hush check` to test the policy against representative actions:

```bash
hush check --action-type file --policy ./policy.yaml ~/.ssh/id_rsa
hush check --action-type egress --policy ./policy.yaml api.github.com:443
```

## Next

- If you use OpenClaw, see the experimental plugin under `packages/clawdstrike-openclaw`.
- Otherwise, build a small adapter in your Claude Code tool layer that calls `clawdstrike::HushEngine` before executing actions.
