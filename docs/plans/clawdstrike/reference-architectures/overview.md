# Clawdstrike/OpenClaw Reference Architectures

## Executive Summary

This collection of reference architectures provides battle-tested blueprints for deploying Clawdstrike security controls across different AI agent deployment scenarios. Each architecture addresses specific security challenges while maintaining operational efficiency.

## What is Clawdstrike?

Clawdstrike is a security SDK for AI agents that provides:

- **Policy Engine**: YAML-based declarative security policies with inheritance
- **Security Guards**: Pluggable enforcement modules (path blocking, egress control, secret detection, patch integrity, MCP tool restrictions)
- **Inline Reference Monitors (IRM)**: Runtime interception for sandboxed execution
- **Audit Ledger**: Tamper-evident logging with cryptographic receipts
- **OpenClaw Integration**: TypeScript SDK for agent framework integration

## Architecture Index

| Architecture | Use Case | Complexity | Time to Deploy |
|-------------|----------|------------|----------------|
| [Build Your Own EDR](./build-your-own-edr.md) | Real-time threat detection | High | 2-4 weeks |
| [Secure Coding Assistant](./secure-coding-assistant.md) | Dev tool integration | Medium | 1-2 weeks |
| [Autonomous Sandbox](./autonomous-sandbox.md) | Isolated agent execution | Medium | 1-2 weeks |
| [Multi-Agent Orchestration](./multi-agent-orchestration.md) | Agent collaboration | High | 3-6 weeks |
| [Enterprise Deployment](./enterprise-deployment.md) | Organization-wide rollout | High | 4-8 weeks |
| [Cloud-Native](./cloud-native.md) | K8s/Serverless deployment | Medium-High | 2-4 weeks |

## Architecture Selection Guide

```
                    Start
                      |
                      v
        +---------------------------+
        | Do you need real-time     |
        | threat detection & response|
        +---------------------------+
                |           |
              Yes           No
                |           |
                v           v
    +---------------+   +---------------------------+
    | Build Your    |   | Is this for a single      |
    | Own EDR       |   | coding assistant?         |
    +---------------+   +---------------------------+
                              |           |
                            Yes           No
                              |           |
                              v           v
              +---------------+   +---------------------------+
              | Secure Coding |   | Do agents need to         |
              | Assistant     |   | collaborate/communicate?  |
              +---------------+   +---------------------------+
                                        |           |
                                      Yes           No
                                        |           |
                                        v           v
                        +---------------+   +---------------------------+
                        | Multi-Agent   |   | Is this for untrusted     |
                        | Orchestration |   | or high-risk workloads?   |
                        +---------------+   +---------------------------+
                                                  |           |
                                                Yes           No
                                                  |           |
                                                  v           v
                                  +---------------+   +---------------+
                                  | Autonomous    |   | Enterprise or |
                                  | Sandbox       |   | Cloud-Native  |
                                  +---------------+   +---------------+
```

## Core Components

### 1. HushEngine (Rust Core)

The central policy enforcement engine written in Rust for performance and safety:

```rust
use clawdstrike::{HushEngine, Policy, GuardContext};

// Create engine with policy
let policy = Policy::from_yaml_file("policy.yaml")?;
let engine = HushEngine::with_policy(policy)
    .with_generated_keypair();

// Check actions
let ctx = GuardContext::new().with_session_id("session-123");
let result = engine.check_file_access("/etc/passwd", &ctx).await?;

if !result.allowed {
    println!("Blocked: {}", result.message);
}
```

### 2. PolicyEngine (TypeScript/OpenClaw)

TypeScript implementation for agent framework integration:

```typescript
import { PolicyEngine, loadPolicy } from '@clawdstrike/openclaw';

const engine = new PolicyEngine({
  policy: 'ai-agent',  // Built-in ruleset
  mode: 'deterministic',
  guards: {
    forbidden_path: true,
    egress: true,
    secret_leak: true,
    patch_integrity: true,
  }
});

const decision = await engine.evaluate({
  eventId: 'evt-123',
  eventType: 'file_write',
  timestamp: new Date().toISOString(),
  data: {
    type: 'file',
    path: '/home/user/.ssh/id_rsa',
    operation: 'write'
  }
});
```

### 3. Security Guards

| Guard | Purpose | Default Severity |
|-------|---------|-----------------|
| `ForbiddenPathGuard` | Block access to sensitive paths | Critical |
| `EgressAllowlistGuard` | Control network destinations | Error |
| `SecretLeakGuard` | Detect secrets in output | Critical |
| `PatchIntegrityGuard` | Validate code changes | Error |
| `McpToolGuard` | Restrict MCP tool usage | Warning |
| `PromptInjectionGuard` | Detect injection attacks | Critical |

### 4. Inline Reference Monitors (IRM)

Runtime interception layer for sandboxed execution:

```
+-------------------+     +----------------+     +------------------+
| Sandboxed Agent   | --> | IRM Router     | --> | Host System      |
| (WASM/Container)  |     | - Filesystem   |     | (Actual I/O)     |
+-------------------+     | - Network      |     +------------------+
                          | - Execution    |
                          +----------------+
                                 |
                                 v
                          +----------------+
                          | Policy Engine  |
                          | (Allow/Deny)   |
                          +----------------+
```

## Policy Schema

All architectures use the same policy schema (v1.1.0):

```yaml
version: "1.1.0"
name: "example-policy"
description: "Example security policy"
extends: "ai-agent"  # Optional base policy

guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
    exceptions:
      - "**/.env.example"

  egress_allowlist:
    allow:
      - "*.openai.com"
      - "api.github.com"
    block: []
    default_action: block

  secret_leak:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
    skip_paths:
      - "**/test/**"

  patch_integrity:
    max_additions: 2000
    max_deletions: 1000
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"

  mcp_tool:
    allow: []
    block:
      - shell_exec
    default_action: allow

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600
```

## Built-in Rulesets

| Ruleset | Use Case | Egress | Writes | Session Timeout |
|---------|----------|--------|--------|-----------------|
| `default` | General purpose | Allowlist | Restricted | 1 hour |
| `strict` | High security | Blocked | Minimal | 30 min |
| `ai-agent` | Coding assistants | AI APIs + Repos | Project dirs | 2 hours |
| `cicd` | CI/CD pipelines | Package registries | Build dirs | 1 hour |
| `permissive` | Development/testing | Open | Open | 4 hours |

## Common Integration Patterns

### Pattern 1: Hook-Based (OpenClaw)

```typescript
// openclaw.plugin.json
{
  "name": "@clawdstrike/openclaw",
  "hooks": {
    "agent:bootstrap": "./hooks/agent-bootstrap/handler.js",
    "tool_result_persist": "./hooks/tool-guard/handler.js",
    "audit:log": "./hooks/audit-logger/handler.js"
  }
}
```

### Pattern 2: API Gateway (hushd)

```bash
# Start the daemon
hushd --policy policy.yaml --bind 127.0.0.1:8080

# Check actions via HTTP
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"action_type": "file_access", "target": "/etc/passwd"}'
```

### Pattern 3: Library Integration (Rust)

```rust
use clawdstrike::{Sandbox, SandboxConfig, Policy};

let sandbox = Sandbox::with_config(
    Policy::from_yaml_file("policy.yaml")?,
    SandboxConfig {
        fail_fast: true,
        max_events: 10000,
        emit_telemetry: true,
    }
);

sandbox.init().await?;
let decision = sandbox.check_fs("/workspace/file.txt", false).await?;
```

## Security Principles

1. **Defense in Depth**: Layer multiple guards for comprehensive protection
2. **Fail Closed**: Unknown actions are blocked by default
3. **Least Privilege**: Start with minimal permissions, add as needed
4. **Audit Everything**: Maintain tamper-evident logs for compliance
5. **Policy as Code**: Version control security policies alongside application code

## Getting Started

1. Choose your architecture from the index above
2. Review the prerequisites and component breakdown
3. Follow the step-by-step implementation guide
4. Customize the provided policy templates
5. Test with the included validation scripts
6. Monitor using the audit dashboard

## Support Matrix

| Component | Rust | TypeScript | Python | Go |
|-----------|------|------------|--------|-----|
| Core Engine | Native | WASM | FFI | Planned |
| OpenClaw Plugin | N/A | Native | Planned | N/A |
| CLI Tools | Native | Native | N/A | N/A |
| SDK | Native | Native | Planned | Planned |

## Version Compatibility

- Clawdstrike Core: 0.1.x
- OpenClaw Plugin: 0.1.x
- Policy Schema: 1.0.0
- Minimum Rust: 1.75+
- Minimum Node.js: 20+
