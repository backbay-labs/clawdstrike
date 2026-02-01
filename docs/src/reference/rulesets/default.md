# Default Ruleset

Balanced security for general development.

## Use Case

The default ruleset is designed for:

- Day-to-day development work
- Projects without special security requirements
- Teams getting started with hushclaw

## Configuration

```yaml
# hushclaw:default
version: "hushclaw-v1.0"
name: default
description: Balanced security for development

egress:
  mode: allowlist
  allowed_domains:
    # AI Provider APIs
    - "api.anthropic.com"
    - "api.openai.com"
    - "generativelanguage.googleapis.com"

    # Code Hosting & Git
    - "github.com"
    - "api.github.com"
    - "*.githubusercontent.com"
    - "gitlab.com"
    - "bitbucket.org"

    # Package Registries
    - "pypi.org"
    - "files.pythonhosted.org"
    - "registry.npmjs.org"
    - "crates.io"
    - "static.crates.io"
    - "rubygems.org"
    - "pkg.go.dev"
    - "proxy.golang.org"

    # Documentation
    - "docs.python.org"
    - "developer.mozilla.org"
    - "docs.rs"

  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.0.0.1"
    - "10.*"
    - "192.168.*"
    - "172.16.*"

filesystem:
  allowed_write_roots:
    - "${WORKSPACE}"
    - "${TMPDIR}"
    - "/tmp"

  forbidden_paths:
    # Credentials
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "~/.config/gcloud"
    - "~/.kube"
    - "~/.docker/config.json"
    - "~/.npmrc"
    - "~/.pypirc"
    - "~/.netrc"

    # System
    - "/etc/shadow"
    - "/etc/passwd"
    - "/etc/sudoers"

    # Browser data
    - "~/.config/google-chrome"
    - "~/.mozilla"
    - "~/Library/Application Support/Google/Chrome"

execution:
  denied_patterns:
    # Destructive
    - "rm -rf /"
    - "rm -rf /*"
    - "rm -rf ~"
    - ":(){ :|:& };:"

    # Remote code execution
    - "curl.*|.*bash"
    - "wget.*|.*sh"
    - "curl.*|.*python"

    # Disk operations
    - "dd if="
    - "mkfs"
    - "fdisk"

    # Privilege escalation
    - "sudo su"
    - "sudo -i"
    - "chmod 777"

tools:
  allowed: []  # All allowed
  denied:
    - "shell_exec_raw"
    - "network_fetch_any"

limits:
  max_execution_seconds: 300
  max_memory_mb: 4096
  max_output_bytes: 10485760
  max_file_size_bytes: 52428800
  max_processes: 100

on_violation: cancel
```

## What's Allowed

- Read/write files in workspace and temp
- Network access to common dev services
- Standard development commands
- All MCP tools except dangerous ones

## What's Blocked

- Access to credential files (~/.ssh, ~/.aws, etc.)
- Network to private IPs and Tor
- Destructive commands (rm -rf /, fork bombs)
- Remote code execution patterns

## Extending

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:default

# Add your APIs
egress:
  allowed_domains:
    - "api.stripe.com"
    - "sentry.io"

# Add project secrets
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./.env.production"
```

## When to Use Something Else

- **More security needed?** Use [strict](./strict.md)
- **AI agents?** Use [ai-agent](./ai-agent.md)
- **CI/CD pipelines?** Use `hushclaw:cicd`
