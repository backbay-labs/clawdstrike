# Threat Intelligence Subsystem - Executive Overview

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0.0-draft |
| Status | Proposal |
| Authors | Clawdstrike Security Team |
| Last Updated | 2026-02-02 |

---

## 1. Problem Statement

Modern AI agents operate with significant autonomy, executing code, accessing filesystems, making network requests, and interacting with external services. This autonomy creates a large attack surface that traditional security controls struggle to address:

1. **Blind Spots in Static Policy**: Current allowlist/denylist approaches cannot detect emerging threats, zero-day exploits, or sophisticated attack patterns that don't match predefined rules.

2. **Lack of Contextual Risk Assessment**: The existing guard system makes binary allow/deny decisions without understanding the broader security context or cumulative risk of a sequence of actions.

3. **No Integration with Threat Feeds**: The security community maintains extensive databases of known malicious indicators (IPs, domains, file hashes, YARA signatures), but Clawdstrike currently cannot leverage this intelligence.

4. **Reactive vs. Proactive Security**: Without honeypots and canary detection, attacks are only detected after they succeed rather than when they attempt to access decoy resources.

5. **Vulnerability Blindness**: AI agents can unknowingly write code that introduces vulnerable dependencies or modify packages with known CVEs.

---

## 2. Vision

The Threat Intelligence Subsystem transforms Clawdstrike from a rule-based policy engine into an intelligence-driven security platform that:

- **Proactively detects** attack attempts through honeypot paths and canary domains
- **Quantifies risk** through blast radius estimation before allowing destructive actions
- **Integrates threat feeds** from industry-standard sources (VirusTotal, urlscan.io, MISP)
- **Scans content** using YARA rules for malware and suspicious patterns
- **Prevents vulnerability introduction** through CVE-aware dependency guards
- **Auto-updates blocklists** of known malicious infrastructure

---

## 3. Architecture Overview

```
                                    +----------------------------------+
                                    |        Threat Intel Hub          |
                                    |   (Central Coordination Layer)   |
                                    +----------------------------------+
                                              |
              +-------------------------------+-------------------------------+
              |               |               |               |               |
              v               v               v               v               v
       +-----------+   +-----------+   +-----------+   +-----------+   +-----------+
       | Honeypot  |   |  Blast    |   | Blocklist |   |    CVE    |   |   YARA    |
       | Detector  |   |  Radius   |   |  Manager  |   |  Guard    |   |  Scanner  |
       +-----------+   +-----------+   +-----------+   +-----------+   +-----------+
              |               |               |               |               |
              +-------------------------------+-------------------------------+
                                              |
                                              v
                            +----------------------------------+
                            |       Existing Guard System      |
                            |  (ForbiddenPath, Egress, etc.)   |
                            +----------------------------------+
                                              |
                                              v
                            +----------------------------------+
                            |         Policy Engine            |
                            +----------------------------------+
```

### Component Summary

| Component | Purpose | Data Sources |
|-----------|---------|--------------|
| **Honeypot Detector** | Detect access to decoy paths/domains that indicate reconnaissance or attack | Local config, threat intel feeds |
| **Blast Radius Estimator** | Quantify potential damage before allowing risky operations | Dependency graphs, permission analysis |
| **Blocklist Manager** | Auto-update and query known malicious indicators | VirusTotal, urlscan.io, abuse.ch, MISP |
| **CVE Guard** | Block writes to packages with known vulnerabilities | NVD, OSV, GitHub Advisory Database |
| **YARA Scanner** | Content scanning with industry-standard signatures | YARA rule repositories, custom rules |
| **External Integrations** | VirusTotal and urlscan.io API integration | External APIs |

---

## 4. Integration with Existing System

### 4.1 Guard System Extension

The threat intelligence components integrate as new guards implementing the existing `Guard` trait:

```rust
// New guards that plug into the existing system
pub struct HoneypotGuard { ... }
pub struct BlastRadiusGuard { ... }
pub struct BlocklistGuard { ... }
pub struct CveGuard { ... }
pub struct YaraGuard { ... }
```

```typescript
// TypeScript equivalents for OpenClaw
import type { Guard, GuardResult, PolicyEvent, Policy } from './types.js';

// Each guard implements the Guard interface
interface Guard {
  name(): string;
  handles(): EventType[];
  isEnabled(): boolean;
  check(event: PolicyEvent, policy: Policy): Promise<GuardResult>;
  checkSync?(event: PolicyEvent, policy: Policy): GuardResult;
}

// New threat intel guards
export class HoneypotGuard implements Guard { /* ... */ }
export class BlastRadiusGuard implements Guard { /* ... */ }
export class BlocklistGuard implements Guard { /* ... */ }
export class CveGuard implements Guard { /* ... */ }
export class YaraGuard implements Guard { /* ... */ }
export class VirusTotalGuard implements Guard { /* ... */ }
export class UrlscanGuard implements Guard { /* ... */ }

// See individual spec files for complete implementations
```

### 4.2 Policy Configuration Extension

```yaml
version: "1.1.0"
name: "threat-intel-enabled"
extends: default

guards:
  # Existing guards...
  forbidden_path:
    patterns: ["**/.ssh/**"]

  # New threat intel guards
  honeypot:
    enabled: true
    paths:
      - "/var/secrets/**"
      - "/admin/credentials/**"
    domains:
      - "internal-admin.company.local"
    alert_severity: critical

  blast_radius:
    enabled: true
    max_score: 75
    warn_threshold: 50

  blocklist:
    enabled: true
    sources:
      - "clawdstrike:malware-domains"
      - "clawdstrike:malware-ips"
      - "https://custom.blocklist.org/list.json"
    update_interval_hours: 6

  cve:
    enabled: true
    block_severity: ["critical", "high"]
    warn_severity: ["medium"]
    data_sources:
      - nvd
      - osv
      - github_advisory

  yara:
    enabled: true
    rule_sets:
      - "clawdstrike:default"
      - "/path/to/custom/rules.yar"
    scan_limit_bytes: 10485760  # 10MB

  virustotal:
    enabled: true
    api_key_env: "VIRUSTOTAL_API_KEY"
    check_urls: true
    check_files: true
    min_detection_threshold: 3

  urlscan:
    enabled: true
    api_key_env: "URLSCAN_API_KEY"
    check_urls: true
```

### 4.3 IRM Router Integration

The Inline Reference Monitor (IRM) system gains new specialized monitors:

```rust
impl IrmRouter {
    pub fn new_with_threat_intel(policy: Policy, intel_config: ThreatIntelConfig) -> Self {
        let monitors: Vec<Arc<dyn Monitor>> = vec![
            Arc::new(FilesystemIrm::new()),
            Arc::new(NetworkIrm::new()),
            Arc::new(ExecutionIrm::new()),
            // New threat intel monitors
            Arc::new(HoneypotIrm::new(&intel_config)),
            Arc::new(BlocklistIrm::new(&intel_config)),
            Arc::new(YaraIrm::new(&intel_config)),
        ];
        Self { monitors, policy }
    }
}
```

---

## 5. Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Agent Action                                   │
│  (file_write, network_egress, command_exec, patch_apply, etc.)         │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                         Event Classification                             │
│  - Extract indicators (paths, domains, IPs, hashes, content)            │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          v                         v                         v
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Honeypot Check │      │ Blocklist Check │      │   YARA Scan     │
│  - Path match   │      │ - Domain/IP     │      │  - Content      │
│  - Domain match │      │ - Hash lookup   │      │  - Signatures   │
└────────┬────────┘      └────────┬────────┘      └────────┬────────┘
         │                        │                        │
         v                        v                        v
┌─────────────────────────────────────────────────────────────────────────┐
│                        Decision Aggregation                              │
│  - Combine results from all threat intel sources                        │
│  - Calculate composite threat score                                      │
│  - Determine action (allow, warn, deny, escalate)                       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                        Blast Radius Assessment                           │
│  (For write/delete/exec operations)                                     │
│  - Impact scope estimation                                               │
│  - Reversibility analysis                                                │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                          Final Decision                                  │
│  - GuardResult with threat intel enrichment                             │
│  - Audit log with IOCs                                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Security Considerations

### 6.1 Defense in Depth

Threat intelligence augments but does not replace existing guards:

1. **Base Guards** (ForbiddenPath, Egress) provide deterministic policy enforcement
2. **Threat Intel Guards** add probabilistic/heuristic detection
3. **Blast Radius** provides risk quantification
4. **Combined Decision** requires consensus or applies fail-safe defaults

### 6.2 Data Integrity

- All blocklist updates are cryptographically signed
- YARA rules from external sources are validated before use
- API responses are cached with integrity checks
- Threat intel data is stored encrypted at rest

### 6.3 Privacy

- No telemetry is sent without explicit opt-in
- Local-only mode available for air-gapped environments
- API queries can be anonymized through proxy
- Sensitive indicators are redacted in logs

### 6.4 Availability

- Graceful degradation when threat intel services are unavailable
- Local caches provide continued protection during outages
- Configurable timeout and retry policies
- Circuit breakers prevent cascade failures

---

## 7. Performance Considerations

### 7.1 Latency Budget

| Operation | Target Latency | Strategy |
|-----------|---------------|----------|
| Honeypot check | < 1ms | In-memory pattern matching |
| Blocklist lookup | < 5ms | Bloom filter + local cache |
| YARA scan | < 100ms | Streaming scan, size limits |
| CVE check | < 50ms | Local DB with async refresh |
| VirusTotal lookup | < 2s | Async, non-blocking |
| Blast radius calc | < 50ms | Pre-computed dependency graphs |

### 7.2 Resource Limits

```yaml
threat_intel:
  cache:
    max_memory_mb: 256
    max_entries: 100000
    ttl_hours: 24

  yara:
    max_scan_size_bytes: 10485760
    max_rules_loaded: 1000
    scan_timeout_ms: 5000

  external_api:
    max_concurrent_requests: 10
    request_timeout_ms: 5000
    rate_limit_per_minute: 60
```

---

## 8. Implementation Phases

### Phase 1: Foundation (4 weeks)

- [ ] Threat Intel Hub core infrastructure
- [ ] Honeypot Guard implementation
- [ ] Blocklist Manager with basic sources
- [ ] Integration tests and benchmarks

### Phase 2: Content Analysis (3 weeks)

- [ ] YARA rule engine integration
- [ ] CVE Guard with NVD/OSV
- [ ] Blast radius estimation (basic)
- [ ] Policy configuration schema

### Phase 3: External Integrations (3 weeks)

- [ ] VirusTotal API integration
- [ ] urlscan.io API integration
- [ ] MISP feed support
- [ ] Custom feed protocol

### Phase 4: Advanced Features (4 weeks)

- [ ] Advanced blast radius with dependency analysis
- [ ] Machine learning threat scoring (optional)
- [ ] Real-time feed streaming
- [ ] SOC/SIEM integration hooks

### Phase 5: Hardening (2 weeks)

- [ ] Security audit
- [ ] Performance optimization
- [ ] Documentation
- [ ] Production readiness

---

## 9. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Detection rate for known threats | > 99% | Automated test suite with threat samples |
| False positive rate | < 0.1% | Production monitoring |
| Guard check latency (P99) | < 100ms | APM instrumentation |
| Blocklist freshness | < 6 hours | Update timestamp monitoring |
| CVE database coverage | > 95% NVD | Comparison with NVD releases |

---

## 10. Dependencies

### External Services

- VirusTotal API (optional, premium recommended)
- urlscan.io API (optional)
- NVD/OSV databases (required for CVE guard)

### Rust Crates

- `yara` - YARA rule engine bindings
- `bloom` - Bloom filter for blocklists
- `reqwest` - HTTP client for API calls
- `sled` or `rocksdb` - Local threat intel cache

### Node.js Packages

- `yara-js` - YARA for JavaScript
- `bloom-filters` - Bloom filter implementation
- `node-cache` - In-memory caching

---

## 11. Open Questions

1. **Licensing**: What are the licensing implications of bundling YARA rule sets?
2. **Data Retention**: How long should threat intel hits be retained for forensics?
3. **Multi-tenancy**: Should threat intel be shared across tenants in SaaS deployments?
4. **Offline Mode**: What subset of functionality works without network access?
5. **Custom Indicators**: Should enterprises be able to contribute to shared blocklists?

---

## 12. Related Documents

- [honeypots.md](./honeypots.md) - Honeypot path and domain architecture
- [blast-radius.md](./blast-radius.md) - Blast radius estimation design
- [blocklists.md](./blocklists.md) - Auto-updating blocklist architecture
- [cve-guards.md](./cve-guards.md) - CVE-aware guard design
- [yara-integration.md](./yara-integration.md) - YARA rule integration
- [virustotal-integration.md](./virustotal-integration.md) - VirusTotal/urlscan.io integration

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **IOC** | Indicator of Compromise - observable artifact indicating potential breach |
| **TTP** | Tactics, Techniques, and Procedures - adversary behavior patterns |
| **YARA** | Pattern matching tool for malware researchers |
| **CVE** | Common Vulnerabilities and Exposures - vulnerability identifier |
| **NVD** | National Vulnerability Database - NIST CVE database |
| **OSV** | Open Source Vulnerabilities - Google's vulnerability database |
| **MISP** | Malware Information Sharing Platform - threat intel sharing platform |
| **Blast Radius** | Estimated scope of damage from a successful attack |
