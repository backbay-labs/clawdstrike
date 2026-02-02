# CI/CD

**Ruleset ID:** `cicd` (also accepted as `clawdstrike:cicd`)

**Source:** `rulesets/cicd.yaml`

Policy tuned for CI pipelines (registries allowed; extra protection for CI secret locations).

## What it does (high level)

- Blocks access to common CI secret paths (GitHub/GitLab/CircleCI secret folders)
- Allows egress to package registries, container registries, and common CI build endpoints
- Uses higher patch size limits than `default` (CI-generated diffs can be large)
- Restricts MCP tools via an allowlist and defaults to block
- Enables verbose logging (`settings.verbose_logging: true`)

## View the exact policy

```bash
hush policy show cicd
```
