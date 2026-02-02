# Permissive

**Ruleset ID:** `permissive` (also accepted as `hushclaw:permissive`)

**Source:** `rulesets/permissive.yaml`

Development-friendly policy that relaxes egress and patch-integrity constraints.

## What it does (high level)

- Sets egress `default_action: allow` (network is open by default)
- Relaxes patch integrity size limits
- Enables verbose logging (`settings.verbose_logging: true`)

Note: guards that are not explicitly configured by the ruleset still use their default configurations (e.g. forbidden path protections remain active unless you override them).

## View the exact policy

```bash
hush policy show permissive
```
