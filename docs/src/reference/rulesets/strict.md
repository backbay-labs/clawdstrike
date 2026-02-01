# Strict Ruleset

Maximum security for production and sensitive work.

## Use Case

The strict ruleset is designed for:

- Production deployments
- Sensitive repositories
- Compliance requirements
- High-security environments

## Configuration

```yaml
# hushclaw:strict
version: "hushclaw-v1.0"
name: strict
extends: hushclaw:default
description: Maximum security for production

egress:
  mode: allowlist
  allowed_domains:
    # Only essential APIs
    - "api.anthropic.com"
    - "api.openai.com"
    - "api.github.com"
    # No package registries - use local cache

  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
    - "10.*"
    - "192.168.*"
    - "172.16.*"

filesystem:
  allowed_write_roots:
    - "${WORKSPACE}/src"
    - "${WORKSPACE}/tests"
    - "${TMPDIR}"

  forbidden_paths:
    # All from default, plus:
    - "~/.bashrc"
    - "~/.zshrc"
    - "~/.profile"
    - "${WORKSPACE}/.git"
    - "${WORKSPACE}/.env*"
    - "${WORKSPACE}/secrets/*"
    - "${WORKSPACE}/**/*.key"
    - "${WORKSPACE}/**/*.pem"

execution:
  mode: allowlist
  allowed_commands:
    - "git"
    - "python"
    - "python3"
    - "pytest"
    - "ruff"
    - "mypy"
    - "node"
    - "npm"
    - "npx"
    - "cargo"
    - "rustc"

  denied_patterns:
    # All from default, plus:
    - "git push --force"
    - "git reset --hard"
    - "npm publish"
    - "cargo publish"

tools:
  mode: allowlist
  allowed:
    - "read_file"
    - "write_file"
    - "list_directory"
    - "search_files"
    - "run_command"

guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: true
  mcp_tool: true

limits:
  max_execution_seconds: 120
  max_memory_mb: 2048
  max_output_bytes: 5242880
  max_file_size_bytes: 10485760

on_violation: isolate
```

## Differences from Default

| Feature | Default | Strict |
|---------|---------|--------|
| Package registries | Allowed | Blocked |
| Git operations | All allowed | Limited |
| Write locations | Workspace + tmp | src + tests only |
| Command mode | Denylist | Allowlist |
| Tool mode | Denylist | Allowlist |
| Max execution | 300s | 120s |
| On violation | Cancel | Isolate |

## What's Allowed

- Essential AI APIs only
- Writing to src/ and tests/
- Whitelisted commands only
- Whitelisted tools only

## What's Blocked

- Package registry access (use local cache)
- Force pushes and hard resets
- Publishing packages
- Git directory access
- Any non-whitelisted command

## Extending

For company-specific strict policy:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:strict

# Add internal services
egress:
  allowed_domains:
    - "*.internal.company.com"
    - "artifact-registry.company.com"

# Add approved commands
execution:
  allowed_commands:
    - "company-build-tool"
```

## CI/CD Variant

For even stricter CI/CD:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:strict

filesystem:
  allowed_write_roots:
    - "${CI_PROJECT_DIR}"
    - "/tmp/ci-workspace"

limits:
  max_execution_seconds: 1800  # 30 min for builds

on_violation: cancel  # Fail fast
```

## When to Use

- Production code deployments
- Security-sensitive repositories
- Compliance audits
- Any environment where security > convenience
