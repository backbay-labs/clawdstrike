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

## `fail_fast` behavior

Unlike most other rulesets, CI/CD sets `settings.fail_fast: true`. This means the engine stops evaluating guards after the first block decision. In CI pipelines, this is desirable because:

- Failed checks should fail the pipeline immediately rather than accumulating warnings
- It reduces evaluation time for clearly-blocked actions
- CI logs are cleaner with a single, actionable failure message

If you extend this ruleset and want all guards to run (e.g. to collect a full violation report), override `fail_fast`:

```yaml
version: "1.2.0"
name: CI Full Report
extends: clawdstrike:cicd

settings:
  fail_fast: false
```

## View the exact policy

```bash
clawdstrike policy show cicd
```
