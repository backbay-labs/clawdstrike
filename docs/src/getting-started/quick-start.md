# Quick Start

Evaluate actions against policies in a few minutes.

## Step 1: Install

```bash
cargo install --path crates/hush-cli
```

## Step 2: Pick a ruleset

List the built-ins:

```bash
hush policy list
```

Inspect one:

```bash
hush policy show ai-agent
```

## Step 3: Run checks

### File access

```bash
# Allowed example (depends on your local paths)
hush check --action-type file --ruleset default ./README.md

# Blocked example
hush check --action-type file --ruleset strict ~/.ssh/id_rsa
```

### Network egress

```bash
# Allowed in default ruleset
hush check --action-type egress --ruleset default api.github.com:443

# Blocked in strict ruleset (strict defaults to deny)
hush check --action-type egress --ruleset strict api.github.com:443
```

## Step 4: Create a policy file

Policies configure built-in guards under `guards.*` and can inherit via `extends`.

Create `policy.yaml`:

```yaml
version: "1.0.0"
name: My Policy
extends: clawdstrike:ai-agent

guards:
  egress_allowlist:
    additional_allow:
      - "api.stripe.com"
```

Validate (and optionally resolve `extends`):

```bash
hush policy validate policy.yaml
hush policy validate --resolve policy.yaml
```

Run checks using the file:

```bash
hush check --action-type egress --policy policy.yaml api.stripe.com:443
```

## Notes

- `hush check` evaluates a single action; it does not sandbox or wrap a process.
- For integration into an agent runtime, call the Rust API (`clawdstrike::HushEngine`) before performing actions.

## Next Steps

- [Your First Policy](./first-policy.md)
- [Policy Schema](../reference/policy-schema.md)
- [CLI Reference](../reference/api/cli.md)
