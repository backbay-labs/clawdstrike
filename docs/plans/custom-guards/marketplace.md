# Guard Marketplace and Registry Design

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Prerequisites** | overview.md, plugin-system.md |

---

## 1. Problem Statement

### 1.1 Current State

Today, users who want to extend Clawdstrike must:

1. Write guards from scratch without guidance
2. Manually copy guards between projects
3. Have no visibility into community solutions
4. Cannot easily share guards with the ecosystem

### 1.2 Goals

1. **Discovery**: Users can find guards that solve their security needs
2. **Trust**: Users understand the security posture of guards they install
3. **Quality**: Published guards meet minimum quality standards
4. **Ecosystem**: Third-party developers can monetize guard development

### 1.3 Non-Goals (Phase 1)

1. Paid/commercial guard marketplace
2. Private enterprise registries
3. Guard analytics/telemetry

---

## 2. Architecture

### 2.1 Registry Model

We adopt a **federated registry model** that builds on existing package managers:

```
+------------------------------------------------------------------+
|                    Clawdstrike Marketplace                        |
|                    (marketplace.clawdstrike.dev)                  |
+------------------------------------------------------------------+
|                                                                    |
|  +--------------------+     +---------------------+                |
|  |   Guard Index      |     |   Verification      |                |
|  |   (metadata only)  |     |   Pipeline          |                |
|  +--------------------+     +---------------------+                |
|           |                           |                            |
|           v                           v                            |
|  +----------------------------------------------------------+     |
|  |                Package Resolution                         |     |
|  +----------------------------------------------------------+     |
|           |                           |                            |
+-----------|---------------------------|----------------------------+
            |                           |
            v                           v
    +---------------+           +---------------+
    |    npm        |           |  crates.io    |
    |  (packages)   |           |  (crates)     |
    +---------------+           +---------------+
```

### 2.2 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Use npm/crates.io for packages** | Leverage existing infrastructure, familiar workflows |
| **Separate metadata index** | Fast search without downloading packages |
| **Optional verification** | Balance between security and permissionless publishing |
| **Namespace convention** | `@clawdstrike-guard/*` for verified, any namespace for community |

### 2.3 Trust Tiers

```
+------------------------------------------------------------------+
|                         Trust Hierarchy                           |
+------------------------------------------------------------------+
|                                                                    |
|  Tier 4: First-Party                                              |
|  ┌─────────────────────────────────────────────────────────────┐  |
|  │ Built into Clawdstrike core                                 │  |
|  │ Examples: forbidden_path, egress_allowlist, secret_leak     │  |
|  │ Execution: Native, no sandbox                               │  |
|  └─────────────────────────────────────────────────────────────┘  |
|                                                                    |
|  Tier 3: Certified                                                |
|  ┌─────────────────────────────────────────────────────────────┐  |
|  │ Manual security audit by Clawdstrike team                   │  |
|  │ Namespace: @clawdstrike-guard/certified-*                   │  |
|  │ Execution: Native (with capability restrictions)            │  |
|  └─────────────────────────────────────────────────────────────┘  |
|                                                                    |
|  Tier 2: Verified                                                 |
|  ┌─────────────────────────────────────────────────────────────┐  |
|  │ Automated security scan passed                              │  |
|  │ Namespace: @clawdstrike-guard/*                             │  |
|  │ Execution: WASM sandbox (relaxed limits)                    │  |
|  └─────────────────────────────────────────────────────────────┘  |
|                                                                    |
|  Tier 1: Community (Default)                                      |
|  ┌─────────────────────────────────────────────────────────────┐  |
|  │ No verification, use at own risk                            │  |
|  │ Namespace: Any (e.g., @acme/clawdstrike-*)                  │  |
|  │ Execution: WASM sandbox (strict limits)                     │  |
|  └─────────────────────────────────────────────────────────────┘  |
|                                                                    |
+------------------------------------------------------------------+
```

---

## 3. Guard Index

### 3.1 Index Schema

```typescript
// Guard index entry stored in marketplace
interface GuardIndexEntry {
  // Identity
  name: string;                    // e.g., "@acme/clawdstrike-secrets"
  displayName: string;             // "ACME Secret Detector"
  description: string;
  version: string;                 // Latest version
  versions: VersionInfo[];         // All versions

  // Registry
  registry: 'npm' | 'crates.io';
  packageName: string;             // Original package name

  // Classification
  category: GuardCategory;
  tags: string[];

  // Trust
  trustTier: 'community' | 'verified' | 'certified' | 'first-party';
  verifiedAt?: string;             // ISO timestamp
  certifiedAt?: string;

  // Metrics
  downloads: number;
  stars: number;                   // GitHub stars if linked
  dependents: number;              // Packages that depend on this

  // Security
  capabilities: PluginCapabilities;
  lastSecurityScan?: SecurityScanResult;

  // Authorship
  author: AuthorInfo;
  maintainers: AuthorInfo[];
  repository?: string;
  homepage?: string;

  // Timestamps
  createdAt: string;
  updatedAt: string;
  publishedAt: string;             // Latest version publish date
}

interface VersionInfo {
  version: string;
  publishedAt: string;
  clawdstrikeMinVersion: string;
  clawdstrikeMaxVersion: string;
  deprecated?: boolean;
  deprecationReason?: string;
  securityAdvisory?: string;
}

type GuardCategory =
  | 'secrets'           // Secret detection
  | 'paths'             // Path/filesystem protection
  | 'network'           // Network egress control
  | 'execution'         // Command/tool execution control
  | 'compliance'        // Compliance (HIPAA, SOC2, etc.)
  | 'integration'       // External service integrations
  | 'composition'       // Guard composition utilities
  | 'other';

interface AuthorInfo {
  name: string;
  email?: string;
  url?: string;
  verified?: boolean;
}

interface SecurityScanResult {
  scannedAt: string;
  scanVersion: string;
  passed: boolean;
  findings: SecurityFinding[];
}

interface SecurityFinding {
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  message: string;
  file?: string;
  line?: number;
}
```

### 3.2 Index API

```typescript
// marketplace.clawdstrike.dev/api/v1

/**
 * Search guards
 * GET /guards
 */
interface SearchGuardsRequest {
  q?: string;                      // Full-text search
  category?: GuardCategory;
  trustTier?: TrustTier;
  tags?: string[];
  minVersion?: string;             // Clawdstrike version compatibility
  sort?: 'relevance' | 'downloads' | 'updated' | 'created';
  page?: number;
  limit?: number;
}

interface SearchGuardsResponse {
  guards: GuardIndexEntry[];
  total: number;
  page: number;
  pages: number;
}

/**
 * Get guard details
 * GET /guards/:name
 */
interface GetGuardResponse {
  guard: GuardIndexEntry;
  readme: string;                  // Rendered markdown
  changelog?: string;
  configSchema: JSONSchema7;       // For configuration UI
}

/**
 * Get guard versions
 * GET /guards/:name/versions
 */
interface GetVersionsResponse {
  versions: VersionInfo[];
}

/**
 * Submit guard for verification
 * POST /guards/:name/verify
 */
interface VerifyGuardRequest {
  version: string;
  repositoryUrl: string;           // For source audit
}

interface VerifyGuardResponse {
  requestId: string;
  status: 'pending' | 'in_progress';
  estimatedCompletion: string;
}

/**
 * Report guard security issue
 * POST /guards/:name/security-report
 */
interface SecurityReportRequest {
  version: string;
  type: 'vulnerability' | 'malicious' | 'policy_violation';
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  contactEmail?: string;
}
```

### 3.3 Index Synchronization

```
+------------------------------------------------------------------+
|                  Index Synchronization Flow                       |
+------------------------------------------------------------------+
|                                                                    |
|  1. Package Published to npm/crates.io                            |
|     │                                                              |
|     v                                                              |
|  2. Webhook notification to Marketplace                           |
|     │                                                              |
|     v                                                              |
|  3. Marketplace fetches package metadata                          |
|     │                                                              |
|     v                                                              |
|  4. Validate clawdstrike.plugin.json exists                       |
|     │                                                              |
|     ├── No plugin manifest → Skip (not a Clawdstrike guard)       |
|     │                                                              |
|     v                                                              |
|  5. Validate manifest schema                                       |
|     │                                                              |
|     ├── Invalid → Index with warning, notify author               |
|     │                                                              |
|     v                                                              |
|  6. Run automated security scan                                    |
|     │                                                              |
|     ├── Critical findings → Index with security warning           |
|     │                                                              |
|     v                                                              |
|  7. Update index entry                                             |
|     │                                                              |
|     v                                                              |
|  8. Invalidate CDN cache                                          |
|                                                                    |
+------------------------------------------------------------------+
```

---

## 4. Verification Pipeline

### 4.1 Automated Security Scan

```yaml
# Security scan configuration
security_scan:
  version: "1.0"

  static_analysis:
    # Check for known vulnerable dependencies
    - name: dependency_audit
      severity: critical
      npm: "npm audit"
      rust: "cargo audit"

    # Check for suspicious patterns
    - name: suspicious_patterns
      severity: error
      patterns:
        - pattern: "eval\\s*\\("
          message: "eval() usage detected"
        - pattern: "Function\\s*\\("
          message: "Dynamic Function constructor detected"
        - pattern: "child_process"
          message: "Child process module imported"
        - pattern: "process\\.env"
          message: "Environment variable access"
        - pattern: "fs\\.(write|unlink|rmdir)"
          message: "Filesystem write operations"

    # TypeScript-specific checks
    - name: typescript_checks
      severity: warning
      checks:
        - any_type_usage
        - unsafe_type_assertions

    # Rust-specific checks
    - name: rust_checks
      severity: error
      checks:
        - unsafe_blocks
        - raw_pointers
        - ffi_calls

  capability_verification:
    # Verify declared capabilities match code behavior
    - name: capability_match
      severity: critical
      description: "Ensure code doesn't exceed declared capabilities"

  sandbox_test:
    # Attempt sandbox escape in isolated environment
    - name: sandbox_escape_test
      severity: critical
      tests:
        - filesystem_escape
        - network_escape
        - process_spawn
        - memory_corruption
```

### 4.2 Manual Certification Process

```
+------------------------------------------------------------------+
|                  Certification Workflow                           |
+------------------------------------------------------------------+
|                                                                    |
|  1. Developer submits certification request                       |
|     - Package URL                                                  |
|     - Source repository access                                    |
|     - Contact information                                         |
|     - Certification fee ($500 one-time)                          |
|     │                                                              |
|     v                                                              |
|  2. Automated scan (must pass)                                    |
|     │                                                              |
|     v                                                              |
|  3. Manual code review                                            |
|     - Security engineer reviews all code                          |
|     - Checks for backdoors, data exfiltration                    |
|     - Validates capability declarations                           |
|     - Reviews test coverage                                       |
|     │                                                              |
|     ├── Issues found → Developer notified, re-review required     |
|     │                                                              |
|     v                                                              |
|  4. Certification granted                                         |
|     - Guard moved to @clawdstrike-guard/certified-* namespace    |
|     - Trust tier updated                                          |
|     - Certificate issued (signed by Clawdstrike)                 |
|     │                                                              |
|     v                                                              |
|  5. Ongoing monitoring                                            |
|     - New versions require re-scan                                |
|     - Major changes require re-certification                      |
|     - Annual re-certification required                            |
|                                                                    |
+------------------------------------------------------------------+
```

### 4.3 Verification Badge System

```html
<!-- Embeddable badges for README -->

<!-- Community (unverified) -->
<img src="https://marketplace.clawdstrike.dev/badges/acme/clawdstrike-secrets/trust.svg" />
<!-- Renders: "Clawdstrike Guard | Community" (gray) -->

<!-- Verified -->
<img src="https://marketplace.clawdstrike.dev/badges/clawdstrike-guard/hipaa-phi/trust.svg" />
<!-- Renders: "Clawdstrike Guard | Verified" (blue) -->

<!-- Certified -->
<img src="https://marketplace.clawdstrike.dev/badges/clawdstrike-guard/certified-virustotal/trust.svg" />
<!-- Renders: "Clawdstrike Guard | Certified" (green) -->
```

---

## 5. Discovery Interface

### 5.1 CLI Discovery

```bash
# Search for guards
$ hush guard search "secret detection"

Found 12 guards matching "secret detection":

  @clawdstrike-guard/certified-secrets    [Certified]  ⭐ 4.8  ⬇ 50K
    Enterprise-grade secret detection with 200+ patterns

  @acme/clawdstrike-secrets               [Verified]   ⭐ 4.2  ⬇ 5K
    ACME-specific secret patterns

  clawdstrike-gitleaks                    [Community]  ⭐ 3.9  ⬇ 2K
    Gitleaks integration for Clawdstrike

# View guard details
$ hush guard info @clawdstrike-guard/certified-secrets

@clawdstrike-guard/certified-secrets v2.1.0
Enterprise-grade secret detection with 200+ patterns

Trust:        Certified (audited 2025-12-01)
Downloads:    50,234 (last 30 days)
Repository:   github.com/clawdstrike/certified-secrets
License:      Apache-2.0

Capabilities:
  - filesystem.read: ["**/*"]
  - network: false
  - subprocess: false

Clawdstrike:  >= 0.5.0

# Install a guard
$ hush guard install @clawdstrike-guard/certified-secrets

Installing @clawdstrike-guard/certified-secrets@2.1.0...
  ✓ Downloaded package
  ✓ Verified signature
  ✓ Validated capabilities
  ✓ Added to policy.yaml

Guard installed successfully.
Enable it in your policy.yaml:

  guards:
    custom:
      - package: "@clawdstrike-guard/certified-secrets"
        config:
          # See docs for configuration options
```

### 5.2 Web Discovery (marketplace.clawdstrike.dev)

```
+------------------------------------------------------------------+
|  Clawdstrike Guard Marketplace                      [Search...]   |
+------------------------------------------------------------------+
|                                                                    |
|  Categories:                                                       |
|  [All] [Secrets] [Paths] [Network] [Compliance] [Integrations]   |
|                                                                    |
|  Trust: [All] [Certified Only] [Verified+]                        |
|                                                                    |
+------------------------------------------------------------------+
|                                                                    |
|  Featured Guards                                                   |
|  ┌──────────────────────────────────────────────────────────────┐ |
|  │ @clawdstrike-guard/certified-virustotal  [Certified]         │ |
|  │ ⭐ 4.9  ⬇ 25K                                                 │ |
|  │ Scan files with VirusTotal API                               │ |
|  │ [Install] [View]                                              │ |
|  └──────────────────────────────────────────────────────────────┘ |
|                                                                    |
|  ┌──────────────────────────────────────────────────────────────┐ |
|  │ @clawdstrike-guard/certified-hipaa       [Certified]         │ |
|  │ ⭐ 4.8  ⬇ 18K                                                 │ |
|  │ HIPAA PHI detection and audit logging                        │ |
|  │ [Install] [View]                                              │ |
|  └──────────────────────────────────────────────────────────────┘ |
|                                                                    |
|  Most Downloaded                                                   |
|  ...                                                               |
|                                                                    |
|  Recently Updated                                                  |
|  ...                                                               |
|                                                                    |
+------------------------------------------------------------------+
```

### 5.3 IDE Integration

```typescript
// VSCode extension: clawdstrike-marketplace

// Hover over guard package in policy.yaml shows:
// - Guard description
// - Trust tier
// - Download count
// - Quick actions (view docs, update)

// Autocomplete suggests guards from marketplace
// when typing in guards.custom section
```

---

## 6. Configuration Schema

### 6.1 Marketplace Backend Configuration

```yaml
# marketplace-config.yaml

server:
  port: 8080
  host: 0.0.0.0

database:
  type: postgresql
  host: ${DB_HOST}
  name: clawdstrike_marketplace

registries:
  npm:
    webhook_secret: ${NPM_WEBHOOK_SECRET}
    api_token: ${NPM_API_TOKEN}
    namespace_prefix: "@clawdstrike-guard/"

  crates_io:
    webhook_secret: ${CRATES_WEBHOOK_SECRET}
    api_token: ${CRATES_API_TOKEN}
    namespace_prefix: "clawdstrike-guard-"

verification:
  auto_scan:
    enabled: true
    max_package_size_mb: 50
    timeout_seconds: 300

  certification:
    fee_usd: 500
    validity_days: 365

security:
  scan_engine: "semgrep"
  malware_scan: "clamav"

cache:
  type: redis
  host: ${REDIS_HOST}
  ttl_seconds: 3600

cdn:
  provider: cloudflare
  zone_id: ${CF_ZONE_ID}
```

### 6.2 Client Configuration

```yaml
# ~/.clawdstrike/marketplace.yaml

# Registry preferences
registries:
  - name: official
    url: https://marketplace.clawdstrike.dev/api/v1
    priority: 1

  # Optional: Private enterprise registry
  - name: acme-internal
    url: https://guards.acme.corp/api/v1
    priority: 2
    auth:
      type: bearer
      token: ${ACME_REGISTRY_TOKEN}

# Trust settings
trust:
  # Minimum trust tier for auto-install
  minimum_tier: verified

  # Allow community guards with explicit flag
  allow_community: true
  community_warning: true

  # Require signature verification
  require_signature: true

# Cache settings
cache:
  enabled: true
  directory: ~/.clawdstrike/cache/guards
  max_size_mb: 500
  ttl_hours: 24
```

---

## 7. Moderation and Abuse Prevention

### 7.1 Content Policy

```markdown
# Clawdstrike Guard Marketplace Content Policy

## Prohibited Content

1. **Malicious Code**
   - Intentional backdoors or data exfiltration
   - Code designed to bypass security controls
   - Cryptocurrency miners or ransomware

2. **Policy Violations**
   - Guards that claim false capabilities
   - Guards that misrepresent their trust tier
   - Typosquatting popular guard names

3. **Low Quality**
   - Guards with no functional code
   - Spam or placeholder packages
   - Duplicates of existing guards without improvement

4. **Legal Issues**
   - Copyright/license violations
   - Export-controlled code
   - Content violating applicable laws

## Enforcement

- First offense: Warning and 48h to remediate
- Second offense: Package delisted
- Third offense: Account suspended
- Malicious code: Immediate permanent ban
```

### 7.2 Automated Abuse Detection

```typescript
// abuse-detection.ts

interface AbuseSignal {
  type: 'typosquat' | 'spam' | 'malicious' | 'policy_violation';
  confidence: number; // 0-1
  details: string;
}

class AbuseDetector {
  /**
   * Check for typosquatting popular packages
   */
  checkTyposquat(name: string): AbuseSignal | null {
    const popularGuards = [
      '@clawdstrike-guard/certified-secrets',
      '@clawdstrike-guard/certified-virustotal',
      // ...
    ];

    for (const popular of popularGuards) {
      const distance = levenshteinDistance(name, popular);
      if (distance > 0 && distance <= 2) {
        return {
          type: 'typosquat',
          confidence: 1 - (distance / popular.length),
          details: `Similar to popular guard: ${popular}`,
        };
      }
    }
    return null;
  }

  /**
   * Check for spam patterns
   */
  checkSpam(pkg: PackageMetadata): AbuseSignal | null {
    const signals = [];

    // Empty or minimal code
    if (pkg.unpackedSize < 1000) {
      signals.push('Minimal package size');
    }

    // No tests
    if (!pkg.hasTests) {
      signals.push('No tests included');
    }

    // Suspicious publishing pattern
    if (pkg.author.publishedPackages > 50 && pkg.author.accountAge < 30) {
      signals.push('New account with many packages');
    }

    if (signals.length >= 2) {
      return {
        type: 'spam',
        confidence: signals.length / 4,
        details: signals.join('; '),
      };
    }

    return null;
  }

  /**
   * Check for malicious patterns
   */
  async checkMalicious(pkg: PackageMetadata): Promise<AbuseSignal | null> {
    // Run static analysis
    const scanResult = await this.securityScanner.scan(pkg);

    if (scanResult.criticalFindings > 0) {
      return {
        type: 'malicious',
        confidence: 0.9,
        details: `${scanResult.criticalFindings} critical security findings`,
      };
    }

    return null;
  }
}
```

### 7.3 Community Reporting

```typescript
// Report flow
interface GuardReport {
  guardName: string;
  reporterEmail: string;
  type: 'security' | 'spam' | 'policy' | 'other';
  description: string;
  evidence?: string[];
}

// Triage workflow
enum ReportStatus {
  Pending = 'pending',
  Investigating = 'investigating',
  Confirmed = 'confirmed',
  Dismissed = 'dismissed',
  Resolved = 'resolved',
}

// Auto-actions based on reports
const reportThresholds = {
  // Auto-delist if 5+ confirmed security reports
  security: { autoAction: 'delist', threshold: 5 },

  // Auto-flag for review if 10+ spam reports
  spam: { autoAction: 'review', threshold: 10 },

  // Manual review required for policy reports
  policy: { autoAction: 'review', threshold: 3 },
};
```

---

## 8. Publishing Workflow

### 8.1 First-Time Publisher Flow

```
+------------------------------------------------------------------+
|                  First-Time Publisher Flow                        |
+------------------------------------------------------------------+
|                                                                    |
|  1. Developer creates guard using SDK                             |
|     $ npx @clawdstrike/cli guard init my-guard                   |
|     │                                                              |
|     v                                                              |
|  2. Develop and test guard locally                                |
|     $ npm test                                                     |
|     $ npx @clawdstrike/cli guard validate                        |
|     │                                                              |
|     v                                                              |
|  3. Create npm account (if needed)                                |
|     │                                                              |
|     v                                                              |
|  4. Publish to npm                                                 |
|     $ npm publish --access public                                 |
|     │                                                              |
|     v                                                              |
|  5. Marketplace webhook receives notification                     |
|     │                                                              |
|     v                                                              |
|  6. Automated scan runs                                           |
|     │                                                              |
|     ├── Pass → Guard listed as "Community"                        |
|     │                                                              |
|     └── Fail → Guard listed with security warning                 |
|               Developer notified via email                         |
|     │                                                              |
|     v                                                              |
|  7. Developer can request verification                            |
|     $ npx @clawdstrike/cli guard request-verification            |
|                                                                    |
+------------------------------------------------------------------+
```

### 8.2 Version Update Flow

```
+------------------------------------------------------------------+
|                   Version Update Flow                             |
+------------------------------------------------------------------+
|                                                                    |
|  1. Developer bumps version                                       |
|     $ npm version patch                                           |
|     │                                                              |
|     v                                                              |
|  2. Publish update                                                 |
|     $ npm publish                                                  |
|     │                                                              |
|     v                                                              |
|  3. Marketplace receives webhook                                  |
|     │                                                              |
|     v                                                              |
|  4. Automated scan runs on new version                            |
|     │                                                              |
|     ├── Trust tier maintained if scan passes                      |
|     │                                                              |
|     ├── Verified → Community if critical findings                 |
|     │   (notification sent to maintainer)                         |
|     │                                                              |
|     └── Certified → requires re-review for major changes          |
|     │                                                              |
|     v                                                              |
|  5. Index updated, CDN cache invalidated                          |
|                                                                    |
+------------------------------------------------------------------+
```

---

## 9. Security Considerations

### 9.1 Supply Chain Security

| Threat | Mitigation |
|--------|------------|
| Compromised npm account | Package signing, 2FA requirement for verified guards |
| Malicious dependency | Dependency scanning, lock file verification |
| Typosquatting | Automated detection, namespace reservation |
| Package takeover | Maintainer verification, transfer alerts |

### 9.2 Package Signing

```typescript
// Package signature verification

interface PackageSignature {
  // Signature algorithm
  algorithm: 'ed25519';

  // Public key identifier
  keyId: string;

  // Signature over package contents
  signature: string;

  // What was signed
  signed: {
    packageName: string;
    version: string;
    contentHash: string;  // SHA-256 of tarball
    timestamp: string;
  };
}

// Verification
class SignatureVerifier {
  private trustedKeys: Map<string, PublicKey>;

  async verify(pkg: Package, sig: PackageSignature): Promise<boolean> {
    // Get trusted public key
    const publicKey = this.trustedKeys.get(sig.keyId);
    if (!publicKey) {
      throw new Error(`Unknown signing key: ${sig.keyId}`);
    }

    // Verify signature
    const message = JSON.stringify(sig.signed);
    return ed25519.verify(sig.signature, message, publicKey);
  }
}
```

### 9.3 Incident Response

```markdown
# Security Incident Response Plan

## Severity Levels

- **P0 (Critical)**: Active exploitation, data exfiltration
  - Response time: < 1 hour
  - Auto-delist package immediately
  - Notify all affected users

- **P1 (High)**: Confirmed malicious code, not yet exploited
  - Response time: < 4 hours
  - Delist after verification
  - Advisory published

- **P2 (Medium)**: Vulnerability that could be exploited
  - Response time: < 24 hours
  - Contact maintainer for fix
  - Advisory if not fixed in 7 days

- **P3 (Low)**: Minor security issue
  - Response time: < 7 days
  - Track for fix

## Communication

1. Internal Slack: #clawdstrike-security
2. Public: security@clawdstrike.dev
3. Advisory: marketplace.clawdstrike.dev/advisories
```

### 9.4 Security Considerations for Untrusted Plugins

When installing community (untrusted) plugins, users should be aware of the following risks and mitigations:

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Code Execution** | Plugin runs arbitrary code during guard checks | WASM sandbox isolates execution; strict resource limits enforced |
| **Data Exfiltration** | Plugin could attempt to send data externally | Network capability must be explicitly declared; all network calls are logged |
| **Denial of Service** | Plugin could consume excessive resources | CPU time limits (100ms default), memory limits (64MB default), enforced timeouts |
| **Supply Chain Attack** | Malicious update to previously trusted plugin | Lock file pins versions; integrity hashes verified on load |
| **Privilege Escalation** | Plugin attempts to exceed declared capabilities | Capability gate blocks all undeclared access; violations trigger alerts |

**Recommendations for Users:**

1. **Review capabilities before installing** - Check the plugin manifest for declared capabilities
2. **Prefer verified/certified plugins** - Higher trust tiers have undergone security review
3. **Use lock files in production** - Pin exact versions to prevent unexpected updates
4. **Monitor audit logs** - Watch for capability_denied events indicating suspicious behavior
5. **Enable strict mode in CI** - Fail builds if untrusted plugins request sensitive capabilities

```yaml
# Example: Restricting untrusted plugin capabilities in policy.yaml
guards:
  custom:
    - package: "@community/some-guard"
      trust_override:
        max_trust_tier: "verified"  # Refuse to load if not at least verified
        require_capabilities:
          network: false            # Block even if plugin declares network
          subprocess: false         # Never allow subprocess for community plugins
```

---

## 10. Implementation Phases

### Phase 1: MVP Index (Weeks 1-3)

- [ ] Index database schema
- [ ] npm webhook integration
- [ ] Basic search API
- [ ] CLI `guard search` command

### Phase 2: Verification Pipeline (Weeks 4-6)

- [ ] Automated security scanning
- [ ] Trust tier system
- [ ] Verification request flow
- [ ] Badge generation

### Phase 3: Web Interface (Weeks 7-9)

- [ ] Guard browsing UI
- [ ] Search and filtering
- [ ] Guard detail pages
- [ ] Publisher dashboard

### Phase 4: Certification Program (Weeks 10-12)

- [ ] Certification workflow
- [ ] Payment integration
- [ ] Namespace management
- [ ] Certificate issuance

### Phase 5: Enterprise Features (Weeks 13-16)

- [ ] Private registry support
- [ ] SSO integration
- [ ] Usage analytics
- [ ] SLA monitoring

---

## 11. Open Questions

1. **Q: Should we host packages ourselves or only index?**
   - Current: Index only, packages on npm/crates.io
   - Pro: Leverage existing infra
   - Con: Less control, dependent on third-party availability

2. **Q: How do we handle guard deprecation?**
   - Proposed: Mark deprecated, show warning, keep available for 6 months

3. **Q: Should we charge for marketplace listing?**
   - Current: Free for community/verified, $500 for certification
   - Alternative: Free tier with paid "featured" placement

4. **Q: How do we handle guards that become abandoned?**
   - Proposed: After 2 years without update, mark as "unmaintained"
   - Community can request adoption

---

*Next: See composition-dsl.md for combining guards with logical operators.*
