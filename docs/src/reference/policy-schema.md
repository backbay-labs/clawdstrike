# Policy Schema

Complete reference for policy YAML schema.

## Schema Version

```yaml
version: "hushclaw-v1.0"
```

Required. Must be a valid hushclaw schema version.

## Full Schema

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:default  # Optional base policy

# Network egress control
egress:
  mode: allowlist  # allowlist | denylist | open
  allowed_domains:
    - "api.github.com"
    - "*.anthropic.com"
  denied_domains:
    - "*.onion"
    - "localhost"
  allowed_cidrs:
    - "10.0.0.0/8"

# Filesystem access control
filesystem:
  allowed_write_roots:
    - "/workspace"
    - "${TMPDIR}"
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
    - "*.pem"

# Command execution control
execution:
  mode: denylist  # allowlist | denylist
  allowed_commands:
    - "git"
    - "python"
  denied_patterns:
    - "rm -rf /"
    - "curl.*|.*bash"

# Tool access control
tools:
  mode: denylist  # allowlist | denylist
  allowed:
    - "read_file"
    - "write_file"
  denied:
    - "shell_exec_raw"
  policies:
    write_file:
      max_size_bytes: 1048576

# Secret detection
secrets:
  additional_patterns:
    - "my_token_[a-zA-Z0-9]{32}"
  ignored_patterns:
    - "EXAMPLE_KEY"

# Guard toggles
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: true
  mcp_tool: true

# Resource limits
limits:
  max_execution_seconds: 300
  max_memory_mb: 4096
  max_output_bytes: 10485760
  max_file_size_bytes: 52428800
  max_processes: 100

# Violation handling
on_violation: cancel  # cancel | warn | isolate | escalate
```

## Section Reference

### egress

Controls network egress.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `allowlist` | `allowlist`, `denylist`, or `open` |
| `allowed_domains` | list | `[]` | Domains to allow (with wildcards) |
| `denied_domains` | list | `[]` | Domains to deny |
| `allowed_cidrs` | list | `[]` | IP ranges to allow (CIDR notation) |

### filesystem

Controls filesystem access.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_write_roots` | list | `[]` | Directories where writes are allowed |
| `forbidden_paths` | list | `[]` | Paths to block (glob patterns) |

Supports environment variables: `${WORKSPACE}`, `${HOME}`, `${TMPDIR}`

### execution

Controls command execution.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `denylist` | `allowlist` or `denylist` |
| `allowed_commands` | list | `[]` | Commands to allow (allowlist mode) |
| `denied_patterns` | list | `[]` | Regex patterns to block |

### tools

Controls MCP tool access.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `denylist` | `allowlist` or `denylist` |
| `allowed` | list | `[]` | Tools to allow |
| `denied` | list | `[]` | Tools to deny |
| `policies` | map | `{}` | Per-tool limits |

### secrets

Controls secret detection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `additional_patterns` | list | `[]` | Extra regex patterns to detect |
| `ignored_patterns` | list | `[]` | Patterns to ignore (false positives) |

### guards

Enable/disable individual guards.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `forbidden_path` | bool | `true` | ForbiddenPathGuard |
| `egress_allowlist` | bool | `true` | EgressAllowlistGuard |
| `secret_leak` | bool | `true` | SecretLeakGuard |
| `patch_integrity` | bool | `true` | PatchIntegrityGuard |
| `mcp_tool` | bool | `true` | McpToolGuard |

### limits

Resource constraints.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_execution_seconds` | int | `300` | Max command runtime |
| `max_memory_mb` | int | `4096` | Max memory usage |
| `max_output_bytes` | int | `10485760` | Max output size |
| `max_file_size_bytes` | int | `52428800` | Max file size |
| `max_processes` | int | `100` | Max concurrent processes |

### on_violation

What happens when a rule is violated.

| Value | Behavior |
|-------|----------|
| `cancel` | Block the operation (default) |
| `warn` | Log warning, allow operation |
| `isolate` | Cut network, continue read-only |
| `escalate` | Require human approval |

## Pattern Syntax

### Glob Patterns (Filesystem)

```yaml
forbidden_paths:
  - "~/.ssh/*"     # All files in directory
  - "*.pem"        # Files ending in .pem
  - ".env*"        # Files starting with .env
  - "**/*.key"     # .key files anywhere
```

### Domain Patterns (Egress)

```yaml
allowed_domains:
  - "api.github.com"     # Exact match
  - "*.github.com"       # Any subdomain
  - "*.*.example.com"    # Two levels of subdomain
```

### Regex Patterns (Execution)

```yaml
denied_patterns:
  - "rm -rf /"           # Literal match
  - "curl.*\\|.*bash"    # Regex with escaping
  - "eval\\("            # Match eval(
```

## Environment Variables

```yaml
filesystem:
  allowed_write_roots:
    - "${WORKSPACE}"     # Current working directory
    - "${HOME}"          # User home directory
    - "${TMPDIR}"        # System temp directory
    - "${CI_PROJECT_DIR}" # CI-specific
```

## Validation

```bash
# Validate syntax and schema
hush policy lint policy.yaml

# Show effective policy (after inheritance)
hush policy show --effective --policy policy.yaml
```
