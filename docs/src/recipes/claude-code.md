# Claude Code Integration (conceptual)

Clawdstrike ships a best-effort `clawdstrike run` process wrapper (audit log + optional proxy/sandbox). For Claude Code, you still get the strongest guarantees by integrating at the **tool boundary** (the layer that performs file/network/tool operations on behalf of the model).

To enforce Clawdstrike decisions, you need to integrate at the **tool boundary** (the layer that performs file/network/tool operations on behalf of the model).

## Practical workflow today

1. Pick a ruleset baseline:

```bash
clawdstrike policy list
clawdstrike policy show ai-agent
```

2. Write a policy file that extends it (optional):

```yaml
version: "1.1.0"
name: My Claude Policy
extends: clawdstrike:ai-agent
```

3. Validate and resolve:

```bash
clawdstrike policy validate ./policy.yaml
clawdstrike policy validate --resolve ./policy.yaml
```

4. Use `clawdstrike check` to test the policy against representative actions:

```bash
clawdstrike check --action-type file --policy ./policy.yaml ~/.ssh/id_rsa
clawdstrike check --action-type egress --policy ./policy.yaml api.github.com:443
```

## Next

- If you use OpenClaw, see the experimental plugin under `packages/clawdstrike-openclaw`.
- Otherwise, build a small adapter in your Claude Code tool layer that calls `clawdstrike::HushEngine` before executing actions.
