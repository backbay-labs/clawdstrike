# HIPAA Compliance Template for AI Agents

## Overview

This document specifies the Clawdstrike HIPAA Compliance Template, enabling covered entities and business associates to deploy AI agents that handle Protected Health Information (PHI) while maintaining compliance with the Health Insurance Portability and Accountability Act.

---

## Problem Statement

### The HIPAA Challenge for AI Agents

1. **PHI Exposure Risk**: AI agents with file system and network access can inadvertently access, transmit, or expose PHI.

2. **Audit Trail Requirements**: HIPAA requires detailed audit logs of all PHI access; AI agent actions are often opaque.

3. **Minimum Necessary Standard**: Agents may access more data than necessary for a given task, violating HIPAA's minimum necessary principle.

4. **Business Associate Agreements**: Organizations deploying third-party AI tools need assurance of HIPAA compliance.

5. **Breach Notification Complexity**: Determining whether an AI agent action constitutes a breach requires detailed forensics.

6. **De-identification Requirements**: AI outputs may inadvertently reveal PHI; automated de-identification is needed.

### Use Cases

| Healthcare Role | AI Agent Use Case | HIPAA Concern |
|----------------|-------------------|---------------|
| Hospital IT | Coding assistant | Access to EHR codebases with PHI test data |
| Health Tech Startup | API development | Agent interacting with FHIR endpoints |
| Insurance Company | Claims processing | Automated access to claims databases |
| Research Institution | Data analysis | Access to de-identified datasets |
| Pharmacy | Inventory management | Access to prescription records |
| Telehealth | Chat support | Real-time PHI in conversation |

---

## HIPAA Regulatory Mapping

### Security Rule Requirements (45 CFR 164.312)

| HIPAA Requirement | CFR Reference | Clawdstrike Guard | Evidence Type |
|-------------------|---------------|-------------------|---------------|
| Access Control | 164.312(a)(1) | ForbiddenPathGuard | Access logs |
| Audit Controls | 164.312(b) | AuditStore | Audit trail |
| Integrity Controls | 164.312(c)(1) | PatchIntegrityGuard | Change logs |
| Person/Entity Authentication | 164.312(d)(1) | SessionContext | Auth records |
| Transmission Security | 164.312(e)(1) | EgressAllowlistGuard | Network logs |

### Privacy Rule Requirements (45 CFR 164.500-534)

| Privacy Requirement | CFR Reference | Clawdstrike Feature | Implementation |
|--------------------|---------------|---------------------|----------------|
| Minimum Necessary | 164.502(b) | Policy Scoping | Path allowlists |
| Individual Rights | 164.524-528 | Audit Export | Access reports |
| Accounting of Disclosures | 164.528 | AuditStore | Disclosure log |
| De-identification | 164.514 | SecretLeakGuard | PHI redaction |

### Breach Notification Requirements (45 CFR 164.400-414)

| Requirement | Clawdstrike Feature | Evidence |
|-------------|---------------------|----------|
| Breach Detection | ViolationWebhook | Real-time alerts |
| Breach Investigation | SessionReconstruction | Timeline analysis |
| Breach Documentation | EvidenceBundle | Incident package |
| Risk Assessment | SeverityScoring | Impact analysis |

---

## Policy Configuration

### HIPAA-Compliant Policy Template

```yaml
# hipaa-policy.yaml
# Clawdstrike HIPAA Compliance Policy Template
# Version: 1.0.0

version: "1.0.0"
name: "HIPAA Compliance Policy"
description: "Policy template for HIPAA-covered AI agent deployments"
extends: clawdstrike:strict

guards:
  # PHI Access Protection
  forbidden_path:
    enabled: true
    patterns:
      # PHI storage locations
      - "**/phi/**"
      - "**/patient_data/**"
      - "**/medical_records/**"
      - "**/ehr/**"
      - "**/emr/**"
      - "**/claims/**"
      - "**/billing/**"

      # PHI identifiers in filenames
      - "**/*ssn*"
      - "**/*social_security*"
      - "**/*mrn*"
      - "**/*medical_record_number*"
      - "**/*dob*"
      - "**/*date_of_birth*"

      # Credential files (standard)
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gnupg/**"
      - "**/secrets/**"
      - "**/.env"
      - "**/*.pem"
      - "**/*.key"

    exceptions:
      # Allow specific PHI access for authorized operations
      - "**/phi/de-identified/**"

    additional_patterns:
      # Organization-specific PHI locations
      # Add your paths here
      - "**/custom_phi_path/**"

  # Network Egress Control
  egress_allowlist:
    enabled: true
    default_action: deny
    allow:
      # Healthcare APIs (add your approved endpoints)
      - "api.yourehr.com"
      - "fhir.yourorg.com"

      # Package registries (for development)
      - "pypi.org"
      - "registry.npmjs.org"

      # AI provider APIs
      - "api.anthropic.com"
      - "api.openai.com"

    block:
      # Explicitly blocked
      - "*.onion"
      - "localhost"
      - "127.0.0.1"
      - "10.*"
      - "192.168.*"

      # Consumer cloud storage (PHI exfiltration risk)
      - "*.dropbox.com"
      - "*.box.com"
      - "drive.google.com"

  # PHI Detection and Redaction
  secret_leak:
    enabled: true
    redact: true
    severity_threshold: warning
    patterns:
      # Standard secrets
      - name: "api_key"
        pattern: '(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'

      # PHI-specific patterns
      - name: "ssn"
        pattern: '\b\d{3}-\d{2}-\d{4}\b'
        severity: critical
        description: "Social Security Number"

      - name: "mrn"
        pattern: '\b(MRN|mrn)[:\s]*(\d{6,12})\b'
        severity: critical
        description: "Medical Record Number"

      - name: "npi"
        pattern: '\b\d{10}\b'  # NPI is 10 digits
        severity: high
        description: "National Provider Identifier"

      - name: "dea"
        pattern: '\b[A-Z]{2}\d{7}\b'
        severity: high
        description: "DEA Number"

      - name: "icd10"
        pattern: '\b[A-Z]\d{2}(\.\d{1,4})?\b'
        severity: medium
        description: "ICD-10 Diagnosis Code"

      - name: "cpt"
        pattern: '\b\d{5}[A-Z]?\b'
        severity: medium
        description: "CPT Procedure Code"

      - name: "dob"
        pattern: '\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(19|20)\d{2}\b'
        severity: high
        description: "Date of Birth (MM/DD/YYYY)"

      - name: "patient_name"
        pattern: '(?i)(patient|pt)[:\s]+([A-Z][a-z]+\s+[A-Z][a-z]+)'
        severity: high
        description: "Patient Name"

  # Patch Integrity
  patch_integrity:
    enabled: true
    forbidden_patterns:
      # Dangerous patterns (standard)
      - 'eval\s*\('
      - 'exec\s*\('
      - 'system\s*\('
      - 'subprocess\.call'

      # PHI-specific dangerous patterns
      - 'SELECT.*FROM.*patient'
      - 'INSERT.*INTO.*medical'
      - 'UPDATE.*SET.*phi'
      - 'DELETE.*FROM.*claims'

  # MCP Tool Restrictions
  mcp_tool:
    enabled: true
    default_action: deny
    allow:
      - "read"
      - "glob"
      - "grep"
      - "bash"  # With command restrictions below

    deny:
      - "webfetch"  # Prevent arbitrary network access
      - "mcp_*"     # Block unknown MCP tools

  # Prompt Injection Defense
  prompt_injection:
    enabled: true
    max_scan_bytes: 100000
    warn_at_or_above: low
    block_at_or_above: medium

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 3600  # 1 hour max session

on_violation: cancel
```

### PHI Location Configuration

```yaml
# phi-locations.yaml
# Organization-specific PHI storage locations

phi_storage:
  databases:
    - host: "ehr-db.internal.yourorg.com"
      port: 5432
      database: "patient_records"
      tables:
        - "patients"
        - "encounters"
        - "diagnoses"
        - "medications"
        - "lab_results"

  file_systems:
    - path: "/data/phi"
      description: "Primary PHI storage"
    - path: "/mnt/ehr-exports"
      description: "EHR export directory"
    - path: "/var/lib/claims"
      description: "Claims processing data"

  api_endpoints:
    - url: "https://fhir.yourorg.com/Patient"
      description: "FHIR Patient resource"
    - url: "https://fhir.yourorg.com/Observation"
      description: "FHIR Observation resource"

  cloud_storage:
    - bucket: "s3://yourorg-phi-data"
      region: "us-east-1"
      kms_key: "arn:aws:kms:us-east-1:123456789:key/abc123"
```

---

## Guard Implementation Details

### PHI Access Guard

```typescript
// Extended ForbiddenPathGuard for PHI
class PhiAccessGuard extends ForbiddenPathGuard {
  private phiPatterns: string[] = [
    '**/phi/**',
    '**/patient_data/**',
    '**/medical_records/**',
  ];

  private phiIdentifiers: RegExp[] = [
    /ssn/i,
    /social_security/i,
    /mrn/i,
    /medical_record_number/i,
    /patient_id/i,
    /dob/i,
    /date_of_birth/i,
  ];

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    // Standard forbidden path check
    const baseResult = super.checkSync(event, policy);
    if (baseResult.status === 'deny') {
      return baseResult;
    }

    // PHI-specific checks
    if (event.data.type === 'file') {
      const path = event.data.path.toLowerCase();

      // Check for PHI identifiers in path
      for (const pattern of this.phiIdentifiers) {
        if (pattern.test(path)) {
          return this.deny(
            `Path contains PHI identifier: ${pattern.source}`,
            'critical'
          );
        }
      }
    }

    return this.allow();
  }
}
```

### PHI Redaction Guard

```typescript
// Extended SecretLeakGuard for PHI
class PhiRedactionGuard extends SecretLeakGuard {
  private phiPatterns: Array<{
    name: string;
    pattern: RegExp;
    replacement: string;
  }> = [
    {
      name: 'ssn',
      pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
      replacement: '[SSN REDACTED]',
    },
    {
      name: 'mrn',
      pattern: /\b(MRN|mrn)[:\s]*(\d{6,12})\b/g,
      replacement: '[MRN REDACTED]',
    },
    {
      name: 'dob',
      pattern: /\b(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}\b/g,
      replacement: '[DOB REDACTED]',
    },
    {
      name: 'phone',
      pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
      replacement: '[PHONE REDACTED]',
    },
    {
      name: 'email',
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      replacement: '[EMAIL REDACTED]',
    },
  ];

  redactPhi(content: string): string {
    let redacted = content;
    for (const { pattern, replacement } of this.phiPatterns) {
      redacted = redacted.replace(pattern, replacement);
    }
    return redacted;
  }

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    const baseResult = super.checkSync(event, policy);

    // Additional PHI scanning
    if (event.data.type === 'tool' && event.data.result) {
      const result = String(event.data.result);
      for (const { name, pattern } of this.phiPatterns) {
        if (pattern.test(result)) {
          return this.warn(`Potential PHI detected: ${name}`);
        }
      }
    }

    return baseResult;
  }
}
```

---

## Audit Requirements

### HIPAA Audit Log Schema

```typescript
interface HipaaAuditEvent extends AuditEvent {
  hipaa: {
    // PHI access classification
    phiAccessed: boolean;
    phiType?: PhiType[];
    phiLocation?: string;

    // User/patient context
    userRole?: string;           // e.g., "physician", "nurse", "admin"
    patientContext?: string;     // De-identified patient reference
    purposeOfUse?: string;       // e.g., "treatment", "payment", "operations"

    // Authorization
    authorizationRef?: string;   // BAA or consent reference
    minimumNecessary: boolean;   // Was access limited?

    // Disclosure tracking
    disclosureTo?: string;       // Third party if applicable
    disclosureType?: string;     // "required", "permitted", "authorized"
  };
}

enum PhiType {
  NAME = "name",
  ADDRESS = "address",
  DATES = "dates",
  PHONE = "phone",
  FAX = "fax",
  EMAIL = "email",
  SSN = "ssn",
  MRN = "mrn",
  HEALTH_PLAN = "health_plan_number",
  ACCOUNT = "account_number",
  CERTIFICATE = "certificate_number",
  VEHICLE = "vehicle_identifier",
  DEVICE = "device_identifier",
  URL = "web_url",
  IP = "ip_address",
  BIOMETRIC = "biometric",
  PHOTO = "photo",
  OTHER = "other_unique_identifier",
}
```

### Accounting of Disclosures Report

```typescript
interface DisclosureAccountingReport {
  reportId: string;
  patientId: string;            // De-identified reference
  requestedBy: string;          // Patient or authorized representative
  requestDate: string;
  reportPeriod: {
    start: string;              // Max 6 years back
    end: string;
  };

  disclosures: Disclosure[];

  certification: {
    generatedBy: string;
    generatedAt: string;
    signature: string;
  };
}

interface Disclosure {
  date: string;
  recipientName: string;
  recipientAddress?: string;
  purpose: string;
  phiDescription: string;       // What was disclosed (not actual PHI)
  agentSessionId?: string;      // If AI agent involved
  policyHash?: string;          // Policy in effect
}
```

### 6-Year Retention

```yaml
# HIPAA requires 6-year retention for audit logs
# Reference: 45 CFR 164.530(j) - 6 years from date of creation
# or last effective date, whichever is later
hipaa_retention:
  audit_events:
    retention_days: 2190        # 6 years minimum
    retention_basis: "creation_or_last_effective"
    encryption: AES-256-GCM
    backup_frequency: daily
    backup_retention: 2190 days
    geographic_redundancy: true

  disclosure_logs:
    retention_days: 2190
    patient_accessible: true
    export_format: ["json", "pdf"]

  access_reports:
    retention_days: 2190
    quarterly_review: required
    annual_attestation: required
```

---

## Evidence Collection

### Required Evidence for HIPAA Certification

```yaml
hipaa_evidence_requirements:
  security_rule:
    access_control:
      - "ForbiddenPathGuard configuration"
      - "Access denial logs for PHI paths"
      - "Allowlist/denylist policy snapshots"

    audit_controls:
      - "Complete audit log for review period"
      - "Audit log integrity verification (hash chain)"
      - "Log retention policy documentation"

    integrity_controls:
      - "PatchIntegrityGuard configuration"
      - "All patch/edit operations with validation"
      - "Change management documentation"

    authentication:
      - "Session management configuration"
      - "Authentication event logs"
      - "Timeout policy enforcement evidence"

    transmission_security:
      - "EgressAllowlistGuard configuration"
      - "TLS enforcement evidence"
      - "Encryption key management documentation"

  privacy_rule:
    minimum_necessary:
      - "Scope restriction policy"
      - "Access pattern analysis"
      - "Justification for broad access (if any)"

    accounting_of_disclosures:
      - "Disclosure event logs"
      - "Third-party access records"
      - "Patient access request logs"

    de_identification:
      - "SecretLeakGuard configuration with PHI patterns"
      - "Redaction event logs"
      - "De-identification verification"

  breach_notification:
    incident_response:
      - "Incident detection evidence"
      - "Timeline reconstruction capability"
      - "Notification workflow documentation"

    risk_assessment:
      - "Severity scoring configuration"
      - "Impact analysis methodology"
      - "Breach determination criteria"
```

### Evidence Bundle for Auditors

```typescript
interface HipaaEvidenceBundle extends EvidenceBundle {
  hipaaSpecific: {
    // Risk Analysis (164.308(a)(1)(ii)(A))
    riskAnalysis: {
      threatAssessment: string;
      vulnerabilityAssessment: string;
      impactAnalysis: string;
      lastUpdated: string;
    };

    // Workforce Training (164.308(a)(5))
    workforceTraining: {
      trainingPolicy: string;
      completionRecords: string;
    };

    // Contingency Plan (164.308(a)(7))
    contingencyPlan: {
      backupProcedures: string;
      recoveryProcedures: string;
      testingResults: string;
    };

    // BAA Documentation
    businessAssociates: {
      baaList: BusinessAssociate[];
      baaTemplates: string;
    };
  };
}

interface BusinessAssociate {
  name: string;
  service: string;
  baaEffectiveDate: string;
  baaExpiryDate?: string;
  lastReview: string;
  subcontractors?: string[];
}
```

---

## Compliance Verification

### Automated Compliance Checks

```typescript
interface HipaaComplianceCheck {
  checkId: string;
  name: string;
  cfrReference: string;
  frequency: "continuous" | "daily" | "weekly" | "quarterly";
  automated: boolean;
  check: () => Promise<ComplianceResult>;
}

const hipaaChecks: HipaaComplianceCheck[] = [
  {
    checkId: "hipaa-access-001",
    name: "PHI Path Protection",
    cfrReference: "164.312(a)(1)",
    frequency: "continuous",
    automated: true,
    check: async () => {
      // Verify ForbiddenPathGuard is enabled
      // Verify PHI patterns are configured
      // Check for any bypasses in last 24 hours
    },
  },
  {
    checkId: "hipaa-audit-001",
    name: "Audit Log Integrity",
    cfrReference: "164.312(b)",
    frequency: "daily",
    automated: true,
    check: async () => {
      // Verify hash chain integrity
      // Check for gaps in sequence numbers
      // Validate signature on signed events
    },
  },
  {
    checkId: "hipaa-encryption-001",
    name: "Transmission Encryption",
    cfrReference: "164.312(e)(1)",
    frequency: "continuous",
    automated: true,
    check: async () => {
      // Verify EgressAllowlistGuard is enabled
      // Check that all egress is to HTTPS endpoints
      // Verify no plaintext transmission of PHI
    },
  },
  {
    checkId: "hipaa-retention-001",
    name: "Audit Log Retention",
    cfrReference: "164.312(b)",
    frequency: "weekly",
    automated: true,
    check: async () => {
      // Verify oldest logs are within retention window
      // Check backup verification results
      // Validate encryption of archived logs
    },
  },
];
```

### Compliance Dashboard

```yaml
hipaa_dashboard:
  overview:
    - metric: "PHI Access Events (24h)"
      query: "COUNT(*) WHERE hipaa.phiAccessed = true AND timestamp > NOW() - 24h"

    - metric: "PHI Access Denials (24h)"
      query: "COUNT(*) WHERE hipaa.phiAccessed = true AND decision.allowed = false AND timestamp > NOW() - 24h"

    - metric: "Audit Log Coverage"
      query: "percentage of sessions with complete audit chains"

    - metric: "Days Since Last Incident"
      query: "NOW() - MAX(timestamp) WHERE decision.severity = 'critical'"

  control_status:
    - control: "164.312(a)(1) - Access Control"
      status: "pass | fail | warning"
      last_check: timestamp
      evidence_count: number

    - control: "164.312(b) - Audit Controls"
      status: "pass | fail | warning"
      last_check: timestamp
      evidence_count: number

    # ... all other controls
```

---

## Evidence Collection Automation

### Automated Evidence Collectors

```typescript
// HIPAA Evidence Automation Configuration
interface HipaaEvidenceAutomation {
  collectors: EvidenceCollector[];
  schedule: AutomationSchedule;
  destinations: EvidenceDestination[];
}

const hipaaAutomation: HipaaEvidenceAutomation = {
  collectors: [
    {
      id: "phi-access-collector",
      control: "164.312(a)(1)",
      description: "Collect PHI access events",
      query: {
        eventTypes: ["file_access", "tool_call"],
        filters: { "hipaa.phiAccessed": true },
        interval: "5m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "audit-integrity-collector",
      control: "164.312(b)",
      description: "Verify audit log integrity",
      query: {
        action: "verify_hash_chain",
        interval: "1h"
      },
      evidenceFormat: "verification_report"
    },
    {
      id: "encryption-collector",
      control: "164.312(e)(1)",
      description: "Collect transmission security evidence",
      query: {
        eventTypes: ["network_egress"],
        filters: { "protocol": "https" },
        interval: "15m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "disclosure-collector",
      control: "164.528",
      description: "Track PHI disclosures for accounting",
      query: {
        eventTypes: ["tool_call", "network_egress"],
        filters: { "hipaa.disclosureTo": { "$exists": true } },
        interval: "5m"
      },
      evidenceFormat: "disclosure_log"
    }
  ],

  schedule: {
    realtime: ["phi-access-collector", "disclosure-collector"],
    hourly: ["audit-integrity-collector"],
    daily: ["encryption-collector"],
    aggregation: {
      daily: true,
      weekly: true,
      monthly: true
    }
  },

  destinations: [
    {
      type: "local_store",
      path: ".clawdstrike/evidence/hipaa/",
      retention: "2190d"
    },
    {
      type: "s3",
      bucket: "hipaa-evidence-${organization_id}",
      encryption: "AES-256-GCM",
      kmsKey: "${HIPAA_KMS_KEY_ARN}"
    },
    {
      type: "siem",
      integration: "splunk",
      index: "hipaa_compliance"
    }
  ]
};
```

### Evidence Collection CLI Commands

```bash
# Collect evidence for a specific control
openclaw evidence collect --control 164.312(a)(1) --period 30d

# Generate HIPAA evidence bundle
openclaw evidence bundle \
  --template hipaa \
  --start 2025-01-01 \
  --end 2025-03-31 \
  --output hipaa_q1_evidence.zip

# Verify evidence integrity
openclaw evidence verify --bundle hipaa_q1_evidence.zip

# Schedule automated collection
openclaw evidence schedule \
  --template hipaa \
  --cron "0 0 * * *" \
  --destination s3://hipaa-evidence/
```

### Evidence Report Generation

```yaml
hipaa_reports:
  daily_phi_access:
    schedule: "0 1 * * *"
    controls: ["164.312(a)(1)", "164.312(b)"]
    format: pdf
    recipients: ["compliance@org.com"]

  weekly_security_summary:
    schedule: "0 8 * * 1"
    controls: ["164.312(a)(1)", "164.312(c)(1)", "164.312(e)(1)"]
    format: pdf
    recipients: ["security@org.com", "hipaa-officer@org.com"]

  quarterly_compliance:
    schedule: "0 9 1 */3 *"
    controls: "all"
    format: pdf
    include_attestation: true
    recipients: ["compliance@org.com", "legal@org.com"]
```

---

## Implementation Phases

### Phase 1: Core HIPAA Policy (Q1 2025)
- [ ] PHI pattern library
- [ ] Extended ForbiddenPathGuard for PHI
- [ ] PHI redaction in SecretLeakGuard
- [ ] HIPAA policy template
- [ ] Basic compliance checks

### Phase 2: Audit Enhancement (Q2 2025)
- [ ] HIPAA-specific audit event schema
- [ ] Accounting of disclosures report
- [ ] 6-year retention implementation
- [ ] Audit log integrity verification
- [ ] Hash chain validation

### Phase 3: Evidence Collection (Q3 2025)
- [ ] Evidence bundle generation
- [ ] Compliance check automation
- [ ] Dashboard metrics
- [ ] Alert integration
- [ ] Auditor portal access

### Phase 4: Certification (Q4 2025)
- [ ] External auditor validation
- [ ] HIPAA certification badge
- [ ] BAA template integration
- [ ] Ongoing compliance monitoring
- [ ] Annual attestation workflow

---

## Pricing for HIPAA Tier

| Item | Price | Includes |
|------|-------|----------|
| HIPAA Policy Template | Included in Gold | Policy YAML + documentation |
| 6-Year Audit Retention | $0.50/GB/month | Encrypted, compliant storage |
| Compliance Dashboard | Included in Gold | Real-time metrics |
| Quarterly Compliance Report | $500/report | Auditor-ready PDF |
| Annual HIPAA Assessment | $5,000 | External auditor review |
| Breach Response Support | $10,000/incident | 24/7 support + forensics |

---

## Appendix: HIPAA Quick Reference

### 18 HIPAA Identifiers (PHI Elements)

1. Names
2. Geographic data (smaller than state)
3. Dates (except year) related to an individual
4. Phone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers and serial numbers
13. Device identifiers and serial numbers
14. Web URLs
15. IP addresses
16. Biometric identifiers
17. Full-face photos
18. Any other unique identifying number or code

### Key HIPAA Timelines

| Requirement | Timeline |
|-------------|----------|
| Breach notification (to individuals) | 60 days |
| Breach notification (to HHS) | 60 days (or annual for <500) |
| Accounting of disclosures | 30 days (60 with extension) |
| Access to records | 30 days (60 with extension) |
| Audit log retention | 6 years |
| Policy/procedure retention | 6 years |
