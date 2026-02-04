# Custom Guard API and Plugin System: Executive Overview

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Related Specs** | plugin-system.md, marketplace.md, composition-dsl.md, async-guards.md, guard-sdk.md, versioning.md |

---

## 1. Problem Statement

### 1.1 Current Limitations

The Clawdstrike security SDK currently ships with a fixed set of built-in guards:

- **ForbiddenPathGuard** - Blocks access to sensitive file paths
- **EgressAllowlistGuard** - Controls network egress
- **SecretLeakGuard** - Detects leaked secrets in content
- **PatchIntegrityGuard** - Validates patch/diff safety
- **McpToolGuard** - Controls MCP tool invocations
- **PromptInjectionGuard** - Detects prompt injection attempts

While these guards cover common security scenarios, organizations face unique security requirements:

1. **Industry-specific compliance** - Healthcare (HIPAA), finance (SOX, PCI-DSS), government (FedRAMP)
2. **Proprietary detection rules** - Internal secret formats, company-specific sensitive paths
3. **Third-party integrations** - VirusTotal scanning, Snyk vulnerability checks, Datadog security monitoring
4. **Custom business logic** - Rate limiting, approval workflows, risk scoring

### 1.2 Market Opportunity

The AI agent security market is nascent but rapidly growing. By enabling extensibility:

- **Enterprise adoption increases** - Organizations can adapt Clawdstrike to their security posture
- **Community innovation accelerates** - Third-party developers contribute specialized guards
- **Partnership opportunities emerge** - Security vendors integrate their services
- **Competitive moat deepens** - Ecosystem effects create switching costs

### 1.3 Technical Debt Risk

Without a well-designed plugin system, we risk:

1. **Monolithic growth** - All guards shipped in core, increasing bundle size and attack surface
2. **Slow iteration** - Every guard addition requires a core release
3. **Fork proliferation** - Customers fork to add custom logic
4. **Integration burden** - N:N integrations between Clawdstrike and external services

---

## 2. Proposed Solution

### 2.1 High-Level Architecture

```
+------------------------------------------------------------------+
|                         Clawdstrike Core                          |
|  +-----------------------------------------------------------+   |
|  |                    Policy Engine                          |   |
|  |  +----------+  +----------+  +----------+  +----------+  |   |
|  |  | Built-in |  | Built-in |  | Custom   |  | Custom   |  |   |
|  |  | Guard 1  |  | Guard 2  |  | Guard A  |  | Guard B  |  |   |
|  |  +----------+  +----------+  +----------+  +----------+  |   |
|  +----------------------------+------------------------------+   |
|                               |                                   |
|  +----------------------------v------------------------------+   |
|  |                Guard Plugin Loader                        |   |
|  |  - npm package discovery     - Rust crate loading        |   |
|  |  - WASM sandbox              - Capability permissions    |   |
|  +-----------------------------------------------------------+   |
+------------------------------------------------------------------+
         |                                     |
         v                                     v
+------------------+                +----------------------+
| Guard Marketplace|                | External Services    |
| (npm / crates.io)|                | (VirusTotal, Snyk)   |
+------------------+                +----------------------+
```

### 2.2 Core Components

| Component | Purpose | Spec Document |
|-----------|---------|---------------|
| **Plugin System** | First-class loading of npm packages and Rust crates | plugin-system.md |
| **Guard Marketplace** | Registry for discovering and installing guards | marketplace.md |
| **Composition DSL** | Combine guards with AND, OR, NOT, IF_THEN logic | composition-dsl.md |
| **Async Guards** | Guards that call external APIs (VirusTotal, etc.) | async-guards.md |
| **Guard SDK** | Developer tools for building custom guards | guard-sdk.md |
| **Versioning System** | Compatibility and dependency management | versioning.md |

### 2.3 Design Principles

1. **Security-First**
   - Custom guards run in sandboxed environments (WASM for untrusted, native for vetted)
   - Explicit capability declarations (network, filesystem, secrets)
   - Audit logging for all guard actions

2. **Zero Runtime Cost**
   - Unused guards are never loaded
   - Lazy initialization until first invocation
   - Optional async support (sync guards pay no async overhead)

3. **TypeScript and Rust Parity**
   - Guards can be written in TypeScript (npm) or Rust (crates.io)
   - Identical interfaces, capabilities, and lifecycle
   - Cross-language composition (TypeScript policy can use Rust guard)

4. **Backward Compatibility**
   - Existing policies work without modification
   - Built-in guards remain first-class
   - Gradual migration path for custom logic

---

## 3. Use Cases

### 3.1 Enterprise: Custom Secret Patterns

**Scenario**: Acme Corp uses internal API key formats not covered by default patterns.

```yaml
# policy.yaml
version: "1.1.0"
guards:
  custom:
    - package: "@acme/clawdstrike-secrets"
      config:
        patterns:
          - name: acme_api_key
            pattern: "ACME_[A-Z0-9]{32}"
            severity: critical
```

### 3.2 Security Vendor: VirusTotal Integration

**Scenario**: Security team requires all downloaded files be scanned.

```yaml
guards:
  custom:
    - package: "@virustotal/clawdstrike-scanner"
      config:
        api_key: ${VT_API_KEY}
        scan_downloads: true
        block_on_detection: true
        min_score_threshold: 5
```

### 3.3 Compliance: HIPAA Data Guards

**Scenario**: Healthcare org needs PHI detection and audit logging.

```yaml
guards:
  custom:
    - package: "@hipaa/clawdstrike-phi-guard"
      config:
        detect_ssn: true
        detect_medical_record_numbers: true
        audit_destination: s3://compliance-logs/
```

### 3.4 DevOps: Custom Approval Workflow

**Scenario**: Production deployments require manager approval.

```yaml
guards:
  custom:
    - package: "@internal/deployment-guard"
      config:
        require_approval_for:
          - git_push --remote origin --branch main
          - deploy --env production
        approval_channel: slack://approvals
```

### 3.5 Composition: Multi-Guard Policies

**Scenario**: Block action if ANY guard triggers (OR), or only if ALL trigger (AND).

```yaml
guards:
  composition:
    - name: high_risk_action
      logic:
        AND:
          - guard: secret_leak
            sensitivity: critical
          - guard: egress
            to_external: true
      action: block_and_alert
```

---

## 4. Success Metrics

### 4.1 Adoption Metrics

| Metric | Target (6 months) | Target (12 months) |
|--------|-------------------|---------------------|
| Published guard packages | 10 | 50 |
| Organizations using custom guards | 50 | 500 |
| Community-contributed guards | 5 | 25 |
| Enterprise custom guards (private) | 20 | 200 |

### 4.2 Technical Metrics

| Metric | Target |
|--------|--------|
| Guard load latency (cold) | < 100ms |
| Guard evaluation latency (p99) | < 10ms |
| Memory overhead per guard | < 5MB |
| Security vulnerabilities in plugin system | 0 critical/high |

### 4.3 Developer Experience Metrics

| Metric | Target |
|--------|--------|
| Time to first custom guard (tutorial) | < 30 minutes |
| SDK documentation coverage | 100% |
| Guard test framework adoption | 80% of published guards |

---

## 5. Implementation Phases

### Phase 1: Foundation (Weeks 1-4)

- [ ] Guard interface stabilization (TypeScript + Rust)
- [ ] Basic plugin loader for local packages
- [ ] Guard SDK scaffolding CLI
- [ ] Unit test framework for guards

### Phase 2: Sandboxing (Weeks 5-8)

- [ ] WASM runtime integration (Wasmtime)
- [ ] Capability permission system
- [ ] Sandboxed network access for async guards
- [ ] Audit logging infrastructure

### Phase 3: Marketplace (Weeks 9-12)

- [ ] npm registry integration
- [ ] crates.io registry integration
- [ ] Guard verification pipeline
- [ ] Installation CLI commands

### Phase 4: Composition (Weeks 13-16)

- [ ] Composition DSL parser
- [ ] AND/OR/NOT/IF_THEN operators
- [ ] Guard dependency resolution
- [ ] Composition validation

### Phase 5: Async Guards (Weeks 17-20)

- [ ] Async guard execution model
- [ ] External service integrations (reference implementations)
- [ ] Timeout and retry policies
- [ ] Circuit breaker patterns

### Phase 6: Production Hardening (Weeks 21-24)

- [ ] Performance optimization
- [ ] Security audit
- [ ] Documentation completion
- [ ] Migration guides for existing users

---

## 6. Security Considerations

### 6.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious guard executes arbitrary code | WASM sandbox, capability restrictions |
| Guard exfiltrates sensitive data | Network capability must be declared, audit logging |
| Supply chain attack via compromised package | Package signing, verification pipeline |
| Guard causes denial of service | Resource limits (CPU, memory, time) |
| Guard bypasses other guards | Immutable guard results, composition validation |

### 6.2 Trust Levels

| Tier | Name | Description | Execution |
|------|------|-------------|-----------|
| 1 | **Community** (default) | Unreviewed third-party guards | WASM sandbox (strict limits) |
| 2 | **Verified** | Passed automated security scan | WASM sandbox (relaxed limits) |
| 3 | **Certified** | Manual security audit by Clawdstrike | Native with capability restrictions |
| 4 | **First-party** | Built-in Clawdstrike guards | Native, no sandbox |

> **Note:** In code and configuration, tier 1 may be referred to as `untrusted` or `community` interchangeably. The terms are synonymous.

### 6.3 Security Boundary Invariants

1. A guard CANNOT modify another guard's result
2. A guard CANNOT access host filesystem without `fs` capability
3. A guard CANNOT make network calls without `network` capability
4. A guard CANNOT exceed declared resource limits
5. All guard actions MUST be audit logged

### 6.4 Untrusted Plugin Hardening

For community (untrusted) plugins, additional restrictions apply:

| Capability | Allowed for Untrusted | Notes |
|------------|----------------------|-------|
| `filesystem.read` | Limited | Only explicit path patterns, no `**/*` wildcards |
| `filesystem.write` | Never | Writing could enable persistence/escape |
| `network` | Limited | Must declare explicit host allowlist |
| `subprocess` | Never | Could escape sandbox entirely |
| `secrets` | Limited | Only explicitly named keys, no enumeration |

**Enforcement Mechanisms:**
- WASM sandbox (Wasmtime) with memory isolation
- Capability checks before every host function call
- Resource limits enforced at runtime (CPU, memory, wall-clock time)
- All denied capability access logged for security monitoring

---

## 7. Open Questions

1. **Q: Should we support Python guards?**
   - Pro: Large ML/security ecosystem
   - Con: Complex sandboxing, performance overhead
   - Proposed: Defer to Phase 7, assess demand

2. **Q: How do we handle guard versioning conflicts?**
   - See versioning.md for detailed analysis

3. **Q: Should async guards block or allow-by-default during timeout?**
   - See async-guards.md for policy options

4. **Q: How do we prevent marketplace spam?**
   - See marketplace.md for moderation strategy

---

## 8. Related Work

- **ESLint Plugin System** - Inspiration for npm-based discovery
- **Envoy Filter API** - Inspiration for WASM sandboxing
- **OPA (Open Policy Agent)** - Inspiration for policy composition
- **Falco Rules** - Inspiration for security-focused DSL

---

## 9. Appendix: Glossary

| Term | Definition |
|------|------------|
| **Guard** | A modular security check that evaluates actions against policy |
| **Policy** | YAML configuration defining enabled guards and their settings |
| **Composition** | Combining multiple guards with logical operators |
| **Capability** | Permission granted to a guard (network, fs, secrets) |
| **Sandbox** | Isolated execution environment (WASM) for untrusted code |
| **Marketplace** | Registry for discovering and installing guard packages |

---

*This document provides the strategic overview. See linked specifications for detailed designs.*
