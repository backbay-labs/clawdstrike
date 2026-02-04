# PCI-DSS Compliance Template for AI Agents

## Overview

This document specifies the Clawdstrike PCI-DSS Compliance Template, enabling merchants, payment processors, and service providers to deploy AI agents that may interact with cardholder data environments (CDE) while maintaining compliance with the Payment Card Industry Data Security Standard.

---

## Problem Statement

### The PCI-DSS Challenge for AI Agents

1. **Cardholder Data Exposure**: AI agents with broad access rights may inadvertently access, process, or transmit Primary Account Numbers (PANs), CVV2, or other cardholder data.

2. **Scope Creep**: Agents interacting with systems "near" the CDE may inadvertently bring those systems into PCI scope.

3. **Network Segmentation**: AI agents that can make arbitrary network connections may bridge segmented networks, violating PCI network requirements.

4. **Key Management**: Agents with file system access could access encryption keys, undermining cryptographic controls.

5. **Logging Requirements**: PCI requires specific audit log content and retention; generic AI logging is insufficient.

6. **Vulnerability Introduction**: AI-generated code or patches could introduce security vulnerabilities into payment systems.

### Use Cases

| Payment Role | AI Agent Use Case | PCI Concern |
|--------------|-------------------|-------------|
| E-commerce Platform | Code assistance for checkout | Access to payment integration code |
| Payment Processor | API development | Interaction with transaction APIs |
| Bank | Fraud detection | Access to transaction logs with PANs |
| POS Vendor | Firmware development | Access to card reader source code |
| Acquirer | Reconciliation | Access to settlement files |
| Service Provider | Support automation | Access to merchant cardholder data |

---

## PCI-DSS Regulatory Mapping

### PCI-DSS v4.0 Requirement Mapping

**Note:** This mapping is based on PCI-DSS v4.0 (March 2022). Organizations should verify requirements against the current PCI-DSS version.

| PCI Requirement | Description | Clawdstrike Guard | Evidence Type |
|-----------------|-------------|-------------------|---------------|
| 1.4.1 | Restrict inbound/outbound traffic to CDE | EgressAllowlistGuard | Network logs |
| 3.5.1 | Render PAN unreadable via encryption/masking | SecretLeakGuard | Masking evidence |
| 6.3.1 | Identify security vulnerabilities | PatchIntegrityGuard | Patch validation |
| 6.3.2 | Protect against known vulnerabilities | PatchIntegrityGuard | Vulnerability checks |
| 7.2.1 | Limit access to system components | ForbiddenPathGuard | Access logs |
| 7.2.2 | Access control systems and mechanisms | McpToolGuard | Tool restrictions |
| 8.3.1 | Strong cryptography for credentials | SecretLeakGuard | Credential detection |
| 10.2.1 | Audit trail for all access to CHD | AuditStore | Complete audit log |
| 10.3.1 | Record audit trail entries with details | AuditEvent schema | Structured events |
| 10.5.1 | Retain audit trail history | Retention policy | 1-year minimum |

### PCI-DSS Scope Considerations

```
+--------------------------------------------------+
|                    CDE (In Scope)                |
|  +--------------------------------------------+  |
|  | Systems that store, process, or transmit  |  |
|  | cardholder data                           |  |
|  +--------------------------------------------+  |
|                       |                          |
|                       | Segmentation             |
|                       v                          |
|  +--------------------------------------------+  |
|  | Connected-to Systems (May be in scope)    |  |
|  | - Systems with connectivity to CDE        |  |
|  | - AI agents with CDE access               |  |
|  +--------------------------------------------+  |
+--------------------------------------------------+
|                                                  |
|              Out of Scope                        |
|  +--------------------------------------------+  |
|  | Systems with no connectivity to CDE        |  |
|  | - Properly segmented development           |  |
|  | - AI agents with NO CDE access             |  |
|  +--------------------------------------------+  |
+--------------------------------------------------+

GOAL: Keep AI agents OUT OF SCOPE via strict segmentation
      OR ensure full PCI compliance if in scope
```

---

## Policy Configuration

### PCI-DSS Compliant Policy Template

```yaml
# pci-dss-policy.yaml
# Clawdstrike PCI-DSS Compliance Policy Template
# Version: 1.1.0

version: "1.1.0"
name: "PCI-DSS Compliance Policy"
description: "Policy template for PCI-DSS compliant AI agent deployments"
extends: clawdstrike:strict

guards:
  # Cardholder Data Protection (Req 3, 7)
  forbidden_path:
    enabled: true
    patterns:
      # Cardholder data storage
      - "**/cardholder/**"
      - "**/cde/**"
      - "**/payment/**"
      - "**/transactions/**"
      - "**/cards/**"
      - "**/pan/**"

      # Encryption keys (Req 3.5, 3.6)
      - "**/keys/**"
      - "**/certs/**"
      - "**/*.key"
      - "**/*.pem"
      - "**/*.p12"
      - "**/*.pfx"
      - "**/keystore/**"
      - "**/vault/**"

      # HSM and tokenization
      - "**/hsm/**"
      - "**/tokens/**"

      # Standard sensitive paths
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gnupg/**"
      - "**/secrets/**"
      - "**/.env"
      - "**/.env.*"

    exceptions:
      # Public certificates only
      - "**/certs/public/**"
      - "**/*.pub"

    additional_patterns:
      # Organization-specific CDE paths
      # Add your paths here

  # Network Segmentation (Req 1.3)
  egress_allowlist:
    enabled: true
    default_action: deny
    allow:
      # Approved payment gateways
      # Add your specific endpoints
      - "api.stripe.com"
      - "api.braintreegateway.com"
      - "api.paypal.com"

      # Package registries (non-CDE)
      - "pypi.org"
      - "registry.npmjs.org"

      # AI provider APIs (ensure no CHD transmitted)
      - "api.anthropic.com"
      - "api.openai.com"

    block:
      # CDE network segments (prevent bridging)
      - "10.100.*"          # Example CDE subnet
      - "172.16.100.*"      # Example CDE subnet

      # Explicitly blocked
      - "*.onion"
      - "localhost"
      - "127.0.0.1"

  # Cardholder Data Detection (Req 3.4, 8.2.1)
  secret_leak:
    enabled: true
    redact: true
    severity_threshold: critical  # Block on CHD detection
    patterns:
      # Primary Account Number (PAN)
      - name: "pan_visa"
        pattern: '\b4[0-9]{12}(?:[0-9]{3})?\b'
        severity: critical
        description: "Visa card number"

      - name: "pan_mastercard"
        pattern: '\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b'
        severity: critical
        description: "Mastercard card number"

      - name: "pan_amex"
        pattern: '\b3[47][0-9]{13}\b'
        severity: critical
        description: "American Express card number"

      - name: "pan_discover"
        pattern: '\b6(?:011|5[0-9]{2}|4[4-9][0-9])[0-9]{12,15}\b'
        severity: critical
        description: "Discover card number"

      - name: "pan_jcb"
        pattern: '\b(?:352[89]|35[3-8][0-9])[0-9]{12,15}\b'
        severity: critical
        description: "JCB card number"

      - name: "pan_diners"
        pattern: '\b3(?:0[0-5]|[68][0-9])[0-9]{11,16}\b'
        severity: critical
        description: "Diners Club card number"

      - name: "pan_unionpay"
        pattern: '\b62[0-9]{14,17}\b'
        severity: critical
        description: "UnionPay card number"

      - name: "pan_generic"
        pattern: '\b[0-9]{13,19}\b'
        severity: high
        description: "Potential card number (generic - requires Luhn validation)"

      # CVV/CVC (MUST NEVER BE STORED)
      - name: "cvv"
        pattern: '\b(cvv|cvc|cvv2|cvc2|cid)[:\s]*[0-9]{3,4}\b'
        severity: critical
        description: "Card verification value"

      # Track data (magnetic stripe)
      - name: "track1"
        pattern: '%B[0-9]{13,19}\^[^\^]+\^[0-9]{4}[0-9]+\?'
        severity: critical
        description: "Track 1 magnetic stripe data"

      - name: "track2"
        pattern: ';[0-9]{13,19}=[0-9]{4}[0-9]+\?'
        severity: critical
        description: "Track 2 magnetic stripe data"

      # PIN blocks
      - name: "pin_block"
        pattern: '\b(pin|pin_block)[:\s]*[0-9A-Fa-f]{16}\b'
        severity: critical
        description: "PIN block"

      # Encryption keys
      - name: "encryption_key"
        pattern: '\b(dek|kek|bdk|ipek|ksn)[:\s]*[0-9A-Fa-f]{32,64}\b'
        severity: critical
        description: "Encryption key"

      # Standard secrets
      - name: "api_key"
        pattern: '(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'
        severity: high

  # Secure Development (Req 6.4, 6.5)
  patch_integrity:
    enabled: true
    forbidden_patterns:
      # Dangerous patterns
      - 'eval\s*\('
      - 'exec\s*\('
      - 'system\s*\('
      - 'subprocess\.call'
      - 'os\.popen'

      # SQL injection risks
      - 'SELECT.*\+.*FROM'
      - 'INSERT.*\+.*INTO'
      - 'EXECUTE\s+IMMEDIATE'

      # Payment-specific dangerous patterns
      - 'decrypt.*pan'
      - 'log.*card'
      - 'print.*cvv'
      - 'console\.log.*payment'

  # Tool Restrictions (Req 7.2)
  mcp_tool:
    enabled: true
    default_action: deny
    allow:
      - "read"            # File reading
      - "glob"            # File search
      - "grep"            # Content search
      - "bash"            # With command restrictions

    deny:
      - "webfetch"        # Prevent arbitrary network
      - "database_query"  # Prevent direct DB access
      - "mcp_*"           # Block unknown tools

  # Prompt Injection Defense (additional security)
  prompt_injection:
    enabled: true
    max_scan_bytes: 100000
    warn_at_or_above: low
    block_at_or_above: medium

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 1800  # 30 minutes

on_violation: cancel
```

### CDE Segmentation Configuration

```yaml
# cde-segmentation.yaml
# Cardholder Data Environment boundaries

cde_boundaries:
  network_segments:
    cde_primary:
      cidr: "10.100.0.0/16"
      description: "Primary CDE network"
      systems:
        - "payment-gateway"
        - "card-vault"
        - "hsm-cluster"

    cde_secondary:
      cidr: "172.16.100.0/24"
      description: "Backup/DR CDE network"

  databases:
    - host: "card-vault.internal"
      port: 5432
      database: "cardholder"
      classification: "CDE"
      access: "deny"

  applications:
    - name: "payment-processor"
      endpoints:
        - "https://payment.internal/process"
        - "https://payment.internal/tokenize"
      classification: "CDE"
      access: "deny"

  ai_agent_policy:
    # AI agents should NEVER have direct CDE access
    cde_access: "prohibited"
    segmentation_required: true
    compensating_controls:
      - "Tokenization for any payment data"
      - "No direct database access"
      - "All access via tokenized APIs"
```

---

## Guard Implementation Details

### PAN Detection Guard

```typescript
// Luhn algorithm validation for card numbers
function luhnCheck(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  let sum = 0;
  let isEven = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

// Extended SecretLeakGuard for PCI
class PciSecretLeakGuard extends SecretLeakGuard {
  private panPatterns: Array<{
    name: string;
    pattern: RegExp;
    issuer: string;
  }> = [
    { name: 'visa', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g, issuer: 'Visa' },
    { name: 'mastercard', pattern: /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b/g, issuer: 'Mastercard' },
    { name: 'amex', pattern: /\b3[47][0-9]{13}\b/g, issuer: 'American Express' },
    { name: 'discover', pattern: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/g, issuer: 'Discover' },
  ];

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    const baseResult = super.checkSync(event, policy);

    // Scan for valid PANs
    const content = this.extractContent(event);
    if (!content) return baseResult;

    for (const { name, pattern, issuer } of this.panPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          if (luhnCheck(match)) {
            return this.deny(
              `Valid ${issuer} PAN detected - PCI-DSS violation`,
              'critical'
            );
          }
        }
      }
    }

    return baseResult;
  }

  maskPan(pan: string): string {
    // PCI-DSS compliant masking: first 6, last 4
    const digits = pan.replace(/\D/g, '');
    if (digits.length < 13) return '[INVALID PAN]';

    const first6 = digits.slice(0, 6);
    const last4 = digits.slice(-4);
    const masked = '*'.repeat(digits.length - 10);

    return `${first6}${masked}${last4}`;
  }
}
```

### Network Segmentation Guard

```typescript
// Extended EgressAllowlistGuard for CDE protection
class PciEgressGuard extends EgressAllowlistGuard {
  private cdeSubnets: string[] = [
    '10.100.0.0/16',
    '172.16.100.0/24',
  ];

  private isIpInCidr(ip: string, cidr: string): boolean {
    const [network, prefixLength] = cidr.split('/');
    const networkInt = this.ipToInt(network);
    const ipInt = this.ipToInt(ip);
    const mask = ~((1 << (32 - parseInt(prefixLength))) - 1);

    return (networkInt & mask) === (ipInt & mask);
  }

  private ipToInt(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
  }

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    if (event.data.type !== 'network') {
      return super.checkSync(event, policy);
    }

    const host = event.data.host;

    // Check if target is in CDE subnet
    for (const subnet of this.cdeSubnets) {
      if (this.isIpInCidr(host, subnet)) {
        return this.deny(
          `Network access to CDE subnet ${subnet} is prohibited`,
          'critical'
        );
      }
    }

    return super.checkSync(event, policy);
  }
}
```

---

## Audit Requirements

### PCI-DSS Audit Log Schema (Req 10.3)

```typescript
interface PciAuditEvent extends AuditEvent {
  pci: {
    // Requirement 10.3.1 - User identification
    userId: string;
    userType: 'system' | 'service' | 'application';

    // Requirement 10.3.2 - Event type
    eventClass: PciEventClass;

    // Requirement 10.3.3 - Date and time
    // Already in base: timestamp

    // Requirement 10.3.4 - Success/failure
    outcome: 'success' | 'failure';

    // Requirement 10.3.5 - Origin of event
    originIp?: string;
    originHostname?: string;

    // Requirement 10.3.6 - Identity/name of affected resource
    resourceId: string;
    resourceType: 'file' | 'database' | 'application' | 'network';

    // CDE context
    cdeRelated: boolean;
    cdeSystem?: string;

    // Cardholder data context
    chdAccess: boolean;
    chdType?: ChdType[];
    chdMasked: boolean;
  };
}

enum PciEventClass {
  // Requirement 10.2.1
  CHD_ACCESS = "chd_access",

  // Requirement 10.2.2
  ROOT_ACTION = "root_action",
  ADMIN_ACTION = "admin_action",

  // Requirement 10.2.3
  AUDIT_LOG_ACCESS = "audit_log_access",

  // Requirement 10.2.4
  INVALID_ACCESS = "invalid_access",

  // Requirement 10.2.5
  AUTH_MECHANISM_CHANGE = "auth_mechanism_change",

  // Requirement 10.2.6
  AUDIT_LOG_CHANGE = "audit_log_change",

  // Requirement 10.2.7
  SYSTEM_OBJECT_CHANGE = "system_object_change",
}

enum ChdType {
  PAN = "pan",
  CARDHOLDER_NAME = "cardholder_name",
  EXPIRATION_DATE = "expiration_date",
  SERVICE_CODE = "service_code",
  // SAD (Sensitive Authentication Data) - should never be stored
  CVV = "cvv",
  PIN = "pin",
  TRACK_DATA = "track_data",
}
```

### Audit Log Retention (Req 10.7)

```yaml
pci_dss_retention:
  # Requirement 10.7.1 - 1 year minimum, 3 months immediately available
  audit_events:
    hot_tier: 90 days     # Immediately available
    warm_tier: 275 days   # Accessible within 24 hours
    total: 365 days       # 1 year minimum

  # Daily review requirement (Req 10.6)
  daily_review:
    automated: true
    alerts:
      - type: "chd_access"
        threshold: "any"
      - type: "invalid_access"
        threshold: 5
      - type: "admin_action"
        threshold: "any"

  # Quarterly log review (Req 10.6.2)
  quarterly_review:
    automated_report: true
    manual_signoff: required
```

---

## Evidence Collection

### Required Evidence for PCI-DSS Certification

```yaml
pci_dss_evidence_requirements:
  requirement_1:  # Network Security
    evidence:
      - "EgressAllowlistGuard configuration"
      - "Network segmentation policy"
      - "All egress events with decisions"
      - "CDE isolation verification"

  requirement_3:  # Protect Stored Data
    evidence:
      - "SecretLeakGuard configuration with PAN patterns"
      - "PAN detection and masking logs"
      - "Key management policy (no key access)"
      - "Tokenization usage logs"

  requirement_6:  # Develop Secure Systems
    evidence:
      - "PatchIntegrityGuard configuration"
      - "Code change validation logs"
      - "Vulnerability pattern detection results"

  requirement_7:  # Restrict Access
    evidence:
      - "ForbiddenPathGuard configuration"
      - "Access denial logs for CDE paths"
      - "McpToolGuard configuration"
      - "Tool restriction enforcement logs"

  requirement_8:  # Identify Users
    evidence:
      - "Session management configuration"
      - "Authentication event logs"
      - "Session timeout enforcement"

  requirement_10:  # Track Access
    evidence:
      - "Complete audit log for review period"
      - "Audit log integrity verification"
      - "Daily log review results"
      - "Quarterly review signoff"

  requirement_12:  # Security Policies
    evidence:
      - "Policy version history"
      - "Policy change logs"
      - "Incident response documentation"
```

### SAQ Mapping

```typescript
interface SaqEvidence {
  saqType: 'A' | 'A-EP' | 'B' | 'B-IP' | 'C' | 'C-VT' | 'D-Merchant' | 'D-SP';
  applicableRequirements: string[];
  evidence: Map<string, EvidenceItem[]>;
}

// Example: SAQ D-Merchant (full PCI-DSS)
const saqDMerchant: SaqEvidence = {
  saqType: 'D-Merchant',
  applicableRequirements: [
    '1.1', '1.2', '1.3', '1.4', '1.5',  // Network
    '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7',  // Storage
    '6.1', '6.2', '6.3', '6.4', '6.5',  // Development
    '7.1', '7.2', '7.3',  // Access
    '8.1', '8.2', '8.3', '8.4', '8.5', '8.6',  // Authentication
    '10.1', '10.2', '10.3', '10.4', '10.5', '10.6', '10.7',  // Logging
    '12.1', '12.2', '12.3', '12.4', '12.5', '12.6', '12.7', '12.8',  // Policies
  ],
  evidence: new Map(),
};
```

### Evidence Bundle for QSA

```typescript
interface PciEvidenceBundle extends EvidenceBundle {
  pciSpecific: {
    // Self-Assessment Questionnaire type
    saqType: string;

    // Attestation of Compliance (AOC) data
    aoc: {
      merchantName: string;
      merchantId: string;
      acquirer: string;
      assessorCompany?: string;
      assessmentDate: string;
    };

    // Compensating controls (if any)
    compensatingControls: CompensatingControl[];

    // Scope definition
    scope: {
      cdeDescription: string;
      networkDiagram: string;  // Reference to diagram
      dataFlowDiagram: string; // Reference to diagram
      systemInventory: string[]; // List of in-scope systems
    };

    // Vulnerability scans (Req 11.2)
    vulnerabilityScans: {
      asvScans: AsvScanResult[];
      internalScans: ScanResult[];
    };

    // Penetration tests (Req 11.3)
    penetrationTests: PenTestResult[];
  };
}

interface CompensatingControl {
  requirement: string;
  control: string;
  justification: string;
  mitigationDescription: string;
  validationEvidence: string;
}
```

---

## Compliance Verification

### Automated Compliance Checks

```typescript
const pciChecks: ComplianceCheck[] = [
  {
    checkId: "pci-1.3.1",
    name: "Inbound/Outbound Traffic Restriction",
    requirement: "1.3.1",
    check: async () => {
      // Verify EgressAllowlistGuard is enabled
      // Verify default action is deny
      // Check for any CDE subnet access attempts
    },
  },
  {
    checkId: "pci-3.4",
    name: "PAN Rendering",
    requirement: "3.4",
    check: async () => {
      // Verify PAN detection patterns are configured
      // Check that all detected PANs were masked
      // Verify no unmasked PANs in audit logs
    },
  },
  {
    checkId: "pci-7.1",
    name: "Access Restriction",
    requirement: "7.1",
    check: async () => {
      // Verify ForbiddenPathGuard is enabled
      // Check for CDE path patterns
      // Verify no unauthorized CDE access
    },
  },
  {
    checkId: "pci-10.7",
    name: "Audit Log Retention",
    requirement: "10.7",
    check: async () => {
      // Verify audit log retention >= 1 year
      // Check that 90 days are immediately available
      // Validate log integrity
    },
  },
];
```

### Daily Log Review Automation (Req 10.6)

```yaml
daily_log_review:
  schedule: "0 0 * * *"  # Daily at midnight
  checks:
    - name: "CHD Access Review"
      query: "eventType = 'chd_access' AND timestamp > NOW() - 24h"
      alert_threshold: 1
      severity: critical

    - name: "Invalid Access Attempts"
      query: "decision.allowed = false AND timestamp > NOW() - 24h"
      alert_threshold: 5
      severity: high

    - name: "Administrative Actions"
      query: "pci.eventClass = 'admin_action' AND timestamp > NOW() - 24h"
      alert_threshold: 1
      severity: medium

    - name: "Audit Log Modifications"
      query: "pci.eventClass = 'audit_log_change' AND timestamp > NOW() - 24h"
      alert_threshold: 1
      severity: critical

  reporting:
    format: pdf
    recipients:
      - "security@company.com"
      - "pci-compliance@company.com"
    retention: 1 year
```

---

## Evidence Collection Automation

### Automated Evidence Collectors

```typescript
// PCI-DSS Evidence Automation Configuration
interface PciEvidenceAutomation {
  collectors: EvidenceCollector[];
  schedule: AutomationSchedule;
  dailyReview: DailyReviewConfig;
}

const pciAutomation: PciEvidenceAutomation = {
  collectors: [
    {
      id: "chd-access-collector",
      control: "10.2.1",
      description: "Track all access to cardholder data",
      query: {
        eventTypes: ["file_access", "database_query", "network_request"],
        filters: { "pci.chdAccess": true },
        interval: "1m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "pan-detection-collector",
      control: "3.5.1",
      description: "Collect PAN masking evidence",
      query: {
        eventTypes: ["secret_detected", "secret_redacted"],
        filters: { "patternName": { "$regex": "^pan_" } },
        interval: "5m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "network-segmentation-collector",
      control: "1.4.1",
      description: "Verify CDE network segmentation",
      query: {
        eventTypes: ["network_egress", "network_connect"],
        filters: { "destination": { "$in": "${CDE_SUBNETS}" } },
        interval: "1m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "admin-action-collector",
      control: "10.2.2",
      description: "Track administrative actions",
      query: {
        eventTypes: ["guard_check", "policy_change"],
        filters: { "pci.eventClass": "admin_action" },
        interval: "1m"
      },
      evidenceFormat: "jsonl"
    }
  ],

  schedule: {
    realtime: ["chd-access-collector", "pan-detection-collector", "network-segmentation-collector"],
    hourly: ["admin-action-collector"],
    aggregation: {
      daily: true,
      weekly: true,
      quarterly: true
    }
  },

  // PCI-DSS Requirement 10.4.1 - Daily log review
  dailyReview: {
    enabled: true,
    schedule: "0 0 * * *",
    checks: [
      { name: "CHD Access", eventClass: "chd_access", threshold: 0, alert: true },
      { name: "Invalid Access", filter: { allowed: false }, threshold: 5, alert: true },
      { name: "Admin Actions", eventClass: "admin_action", threshold: 0, alert: true },
      { name: "Audit Log Changes", eventClass: "audit_log_change", threshold: 0, alert: true }
    ],
    reportRecipients: ["security@company.com", "pci-compliance@company.com"],
    retentionDays: 365
  }
};
```

### Evidence Collection CLI Commands

```bash
# Collect evidence for a specific PCI requirement
openclaw evidence collect --control 10.2.1 --period 30d

# Generate PCI-DSS evidence bundle
openclaw evidence bundle \
  --template pci-dss \
  --start 2025-01-01 \
  --end 2025-03-31 \
  --output pci_q1_evidence.zip

# Run daily log review manually
openclaw pci daily-review --date 2025-01-15

# Generate quarterly review report
openclaw pci quarterly-report \
  --quarter Q1 \
  --year 2025 \
  --output pci_quarterly_q1.pdf

# Schedule automated collection and review
openclaw evidence schedule \
  --template pci-dss \
  --daily-review \
  --destination s3://pci-evidence/
```

---

## Implementation Phases

### Phase 1: Core PCI Policy (Q1 2025)
- [ ] PAN detection patterns (all card brands)
- [ ] Luhn validation integration
- [ ] PAN masking implementation
- [ ] CDE path protection
- [ ] Network segmentation guards

### Phase 2: Audit Enhancement (Q2 2025)
- [ ] PCI-specific audit schema
- [ ] 1-year retention implementation
- [ ] Daily log review automation
- [ ] Quarterly review workflows
- [ ] Log integrity verification

### Phase 3: Evidence Collection (Q3 2025)
- [ ] SAQ evidence mapping
- [ ] AOC data collection
- [ ] Compensating control documentation
- [ ] QSA portal integration
- [ ] Vulnerability scan integration

### Phase 4: Certification (Q4 2025)
- [ ] QSA validation support
- [ ] PCI-DSS certification badge
- [ ] ROC/SAQ generation assistance
- [ ] Ongoing compliance monitoring
- [ ] Annual reassessment workflow

---

## Pricing for PCI Tier

| Item | Price | Includes |
|------|-------|----------|
| PCI-DSS Policy Template | Included in Gold | Policy YAML + documentation |
| 1-Year Audit Retention | $0.40/GB/month | PCI-compliant storage |
| Daily Log Review | Included in Gold | Automated reports |
| Quarterly Review Report | $500/report | QSA-ready documentation |
| Annual PCI Assessment | $7,500 | QSA-facilitated review |
| ASV Scan Integration | $2,000/year | Quarterly scan automation |

---

## Appendix: PCI-DSS Quick Reference

### Card Brand PANs

| Brand | Prefix | Length | Regex Pattern |
|-------|--------|--------|---------------|
| Visa | 4 | 13, 16, 19 | `4[0-9]{12}(?:[0-9]{3})?(?:[0-9]{3})?` |
| Mastercard | 51-55, 2221-2720 | 16 | `(?:5[1-5][0-9]{2}\|222[1-9]\|22[3-9][0-9]\|2[3-6][0-9]{2}\|27[01][0-9]\|2720)[0-9]{12}` |
| American Express | 34, 37 | 15 | `3[47][0-9]{13}` |
| Discover | 6011, 65, 644-649 | 16-19 | `6(?:011\|5[0-9]{2}\|4[4-9][0-9])[0-9]{12,15}` |
| JCB | 3528-3589 | 16-19 | `(?:352[89]\|35[3-8][0-9])[0-9]{12,15}` |
| Diners Club | 36, 38, 300-305 | 14-19 | `3(?:0[0-5]\|[68][0-9])[0-9]{11,16}` |
| UnionPay | 62 | 16-19 | `62[0-9]{14,17}` |

### Sensitive Authentication Data (SAD)

**MUST NEVER BE STORED:**
- Full track data (magnetic stripe)
- CVV2/CVC2/CID
- PIN/PIN block

### PCI-DSS Compliance Levels

| Level | Transactions/Year | Assessment |
|-------|-------------------|------------|
| 1 | >6 million | Annual ROC by QSA |
| 2 | 1-6 million | Annual SAQ |
| 3 | 20,000 - 1 million | Annual SAQ |
| 4 | <20,000 | Annual SAQ |

### Key Timelines

| Requirement | Timeline |
|-------------|----------|
| Audit log retention | 1 year (90 days immediate) |
| Vulnerability scans | Quarterly |
| Penetration tests | Annual |
| Policy review | Annual |
| Incident reporting | Immediate |
