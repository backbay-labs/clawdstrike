# SOC2 Compliance Template for AI Agents

## Overview

This document specifies the Clawdstrike SOC2 Compliance Template, enabling SaaS providers, cloud services, and technology companies to demonstrate that their AI agent deployments meet the American Institute of CPAs (AICPA) Trust Services Criteria for security, availability, processing integrity, confidentiality, and privacy.

---

## Problem Statement

### The SOC2 Challenge for AI Agents

1. **Control Gaps**: Traditional SOC2 controls don't address AI-specific risks like prompt injection, model behavior, or emergent capabilities.

2. **Evidence Collection**: Auditors need structured evidence of AI agent controls; ad-hoc documentation is insufficient.

3. **Continuous Monitoring**: SOC2 Type II requires 6-12 months of operational evidence; AI agents need continuous compliance tracking.

4. **Third-Party Risk**: AI agents often use external APIs (OpenAI, Anthropic); these introduce subservice organization dependencies.

5. **Change Management**: AI agent behavior can change significantly with model updates; SOC2 requires controlled change processes.

6. **User Entity Controls**: Organizations deploying certified agents need clarity on their responsibilities (UECs).

### Use Cases

| Service Type | AI Agent Use Case | SOC2 Concern |
|--------------|-------------------|--------------|
| SaaS Platform | Customer support AI | Customer data confidentiality |
| DevOps Tool | Code generation | Source code security |
| HR Platform | Resume screening | Personally identifiable information |
| Financial SaaS | Data analysis | Processing integrity |
| Healthcare SaaS | Clinical documentation | PHI confidentiality |
| Security Vendor | Threat analysis | System availability |

---

## Trust Services Criteria Mapping

### SOC2 Trust Principles

```
+--------------------------------------------------+
|                 SOC2 TRUST PRINCIPLES             |
+--------------------------------------------------+
|                                                  |
|  +------------+  +------------+  +------------+  |
|  |  SECURITY  |  |AVAILABILITY|  |  PROCESS   |  |
|  |   (CC)     |  |   (A)      |  | INTEGRITY  |  |
|  +------------+  +------------+  | (PI)       |  |
|                                  +------------+  |
|  +------------+  +------------+                  |
|  |CONFIDENTIAL|  |  PRIVACY   |                  |
|  |  ITY (C)   |  |    (P)     |                  |
|  +------------+  +------------+                  |
|                                                  |
+--------------------------------------------------+

REQUIRED: Security (Common Criteria - CC)
OPTIONAL: Availability, Processing Integrity,
          Confidentiality, Privacy
```

### Control Mapping Matrix

**Security (Common Criteria - Required)**

| Trust Criteria | Control ID | Description | Clawdstrike Guard | Evidence |
|----------------|------------|-------------|-------------------|----------|
| **CC5.2** | Control Activities | Selects and develops control activities | PolicyEngine | Policy configs |
| **CC5.3** | Technology Controls | Selects and deploys technology controls | All Guards | Guard configs |
| **CC6.1** | Logical Access | Restrict access to authorized users | ForbiddenPathGuard | Access logs |
| **CC6.2** | Access Removal | Remove access when no longer needed | SessionTimeout | Session logs |
| **CC6.3** | Access Provisioning | Establishes access based on authorization | McpToolGuard | Tool allowlists |
| **CC6.6** | Network Boundaries | Restrict transmission and movement | EgressAllowlistGuard | Network logs |
| **CC6.7** | Input Restrictions | Restrict input to authorized sources | McpToolGuard | Tool logs |
| **CC7.1** | System Operations | Detect configuration deviations | SecretLeakGuard | Scan results |
| **CC7.2** | Security Anomalies | Monitor and detect security events | PromptInjectionGuard | Detection logs |
| **CC7.3** | Security Evaluation | Evaluate detected events | ViolationWebhook | Alert logs |
| **CC7.4** | Incident Response | Respond to identified incidents | IncidentWorkflow | Response logs |
| **CC8.1** | Change Authorization | Authorize, test, and approve changes | PatchIntegrityGuard | Patch logs |

**Availability (Optional)**

| Trust Criteria | Control ID | Description | Clawdstrike Guard | Evidence |
|----------------|------------|-------------|-------------------|----------|
| **A1.1** | Capacity Planning | Meet capacity commitments | ResourceLimits | Usage metrics |
| **A1.2** | Environmental Protections | Protect against environmental threats | InfraMonitoring | Health logs |

**Processing Integrity (Optional)**

| Trust Criteria | Control ID | Description | Clawdstrike Guard | Evidence |
|----------------|------------|-------------|-------------------|----------|
| **PI1.1** | Input Validation | Obtains accurate and complete input | InputValidation | Validation logs |
| **PI1.2** | Processing Accuracy | Processes data accurately | AuditStore | Processing logs |

**Confidentiality (Optional)**

| Trust Criteria | Control ID | Description | Clawdstrike Guard | Evidence |
|----------------|------------|-------------|-------------------|----------|
| **C1.1** | Information Classification | Identifies confidential information | SecretLeakGuard | Classification |
| **C1.2** | Information Disposal | Disposes of confidential information | RetentionPolicy | Disposal logs |

**Privacy (Optional)**

| Trust Criteria | Control ID | Description | Clawdstrike Guard | Evidence |
|----------------|------------|-------------|-------------------|----------|
| **P3.1** | Notice to Data Subjects | Provides notice to data subjects | PolicyDisclosure | Disclosure logs |
| **P4.1** | Collection Limitation | Collects personal info per objectives | DataMinimization | Collection logs |

---

## Policy Configuration

### SOC2 Compliant Policy Template

```yaml
# soc2-policy.yaml
# Clawdstrike SOC2 Compliance Policy Template
# Version: 1.1.0

version: "1.1.0"
name: "SOC2 Compliance Policy"
description: "Policy template for SOC2-compliant AI agent deployments"
extends: clawdstrike:strict

guards:
  # CC6.1 - Logical Access Security
  forbidden_path:
    enabled: true
    patterns:
      # System configuration
      - "**/config/**"
      - "**/settings/**"
      - "**/.config/**"

      # Credentials and secrets
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.gnupg/**"
      - "**/secrets/**"
      - "**/vault/**"
      - "**/.env"
      - "**/.env.*"
      - "**/*.pem"
      - "**/*.key"
      - "**/*.p12"

      # Database files
      - "**/*.sqlite"
      - "**/*.db"
      - "**/database/**"

      # Log files (prevent log poisoning)
      - "**/logs/**"
      - "**/*.log"

      # Customer data
      - "**/customer_data/**"
      - "**/user_data/**"
      - "**/pii/**"

    exceptions:
      # Application-specific exceptions
      - "**/logs/debug.log"  # If needed for debugging

  # CC6.6 - Transmission Security
  egress_allowlist:
    enabled: true
    default_action: deny
    allow:
      # Production API endpoints
      # Add your specific endpoints

      # AI provider APIs
      - "api.anthropic.com"
      - "api.openai.com"

      # Package registries
      - "pypi.org"
      - "registry.npmjs.org"
      - "crates.io"

      # Cloud provider APIs
      - "*.amazonaws.com"
      - "*.azure.com"
      - "*.googleapis.com"

    block:
      # Consumer services
      - "*.dropbox.com"
      - "*.box.com"
      - "drive.google.com"

      # Tor/anonymization
      - "*.onion"

      # Local networks
      - "localhost"
      - "127.0.0.1"
      - "10.*"
      - "192.168.*"

  # CC7.1 - Vulnerability Detection
  secret_leak:
    enabled: true
    redact: true
    severity_threshold: warning
    patterns:
      # API keys
      - name: "generic_api_key"
        pattern: '(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'
        severity: high

      # AWS credentials
      - name: "aws_access_key"
        pattern: 'AKIA[0-9A-Z]{16}'
        severity: critical

      - name: "aws_secret_key"
        pattern: '(?i)aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?'
        severity: critical

      # Database connection strings
      - name: "connection_string"
        pattern: '(?i)(mysql|postgres|mongodb|redis)://[^\s]+'
        severity: critical

      # JWT tokens
      - name: "jwt_token"
        pattern: 'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        severity: high

      # Private keys
      - name: "private_key"
        pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        severity: critical

      # PII patterns
      - name: "email"
        pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        severity: medium

      - name: "phone"
        pattern: '\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        severity: medium

      - name: "ssn"
        pattern: '\b\d{3}-\d{2}-\d{4}\b'
        severity: critical

  # CC7.2 - Security Anomaly Detection
  prompt_injection:
    enabled: true
    max_scan_bytes: 100000
    warn_at_or_above: low
    block_at_or_above: medium

  # CC8.1 - Change Authorization
  patch_integrity:
    enabled: true
    forbidden_patterns:
      # Code injection risks
      - 'eval\s*\('
      - 'exec\s*\('
      - 'system\s*\('
      - 'subprocess\.call'
      - '__import__\s*\('

      # SQL injection
      - 'DROP\s+TABLE'
      - 'DELETE\s+FROM.*WHERE\s+1=1'
      - 'TRUNCATE\s+TABLE'

      # Privilege escalation
      - 'chmod\s+777'
      - 'chown\s+root'
      - 'sudo\s+'
      - 'su\s+-'

      # Malicious patterns
      - 'rm\s+-rf\s+/'
      - 'mkfs\.'
      - 'dd\s+if='

  # CC6.7 - Tool Restrictions
  mcp_tool:
    enabled: true
    default_action: allow
    deny:
      - "database_query"  # Direct DB access
      - "admin_*"         # Administrative tools
      - "system_*"        # System-level tools

settings:
  fail_fast: true
  verbose_logging: true
  session_timeout_secs: 3600  # 1 hour

on_violation: cancel
```

### Control Environment Configuration

```yaml
# soc2-control-environment.yaml
# SOC2 Control Environment Definition

control_environment:
  organization:
    name: "Your Company Name"
    service_description: "AI-assisted development platform"
    service_commitments:
      - "Secure processing of customer code"
      - "Confidentiality of customer data"
      - "99.9% service availability"

  trust_principles:
    security: required
    availability: true
    processing_integrity: true
    confidentiality: true
    privacy: false  # Enable if processing PII

  subservice_organizations:
    - name: "Anthropic (Claude API)"
      service: "AI inference"
      carve_out: true  # Or inclusive
      monitoring: "API response validation"

    - name: "AWS"
      service: "Cloud infrastructure"
      carve_out: false
      soc2_report: "AWS SOC2 Type II"

  complementary_user_entity_controls:
    - "User must maintain secure API key storage"
    - "User must implement access management for their team"
    - "User must monitor agent activity in their environment"
```

---

## Guard Implementation Details

### Security Control Guard (CC6.1)

```typescript
// Comprehensive access control guard for SOC2
class Soc2AccessGuard extends ForbiddenPathGuard {
  private accessLog: AccessLogEntry[] = [];

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    const result = await super.check(event, policy);

    // Log all access attempts (CC6.1 evidence)
    this.accessLog.push({
      timestamp: new Date().toISOString(),
      resource: event.data.path || event.data.toolName,
      action: event.eventType,
      outcome: result.status === 'allow' ? 'granted' : 'denied',
      reason: result.reason,
      sessionId: event.sessionId,
    });

    return result;
  }

  getAccessLog(): AccessLogEntry[] {
    return this.accessLog;
  }
}

interface AccessLogEntry {
  timestamp: string;
  resource: string;
  action: string;
  outcome: 'granted' | 'denied';
  reason?: string;
  sessionId?: string;
}
```

### Anomaly Detection Guard (CC7.2)

```typescript
// Enhanced prompt injection guard with anomaly detection
class Soc2AnomalyGuard extends PromptInjectionGuard {
  private anomalyBaseline: Map<string, AnomalyStats> = new Map();

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    // Standard injection check
    const injectionResult = await super.check(event, policy);

    // Behavioral anomaly detection
    const anomalyResult = await this.detectAnomalies(event);

    // Return the more severe result
    if (!anomalyResult.allowed) {
      return anomalyResult;
    }

    return injectionResult;
  }

  private async detectAnomalies(event: PolicyEvent): Promise<GuardResult> {
    const sessionId = event.sessionId || 'unknown';
    const stats = this.anomalyBaseline.get(sessionId) || this.initStats();

    // Update statistics
    stats.eventCount++;
    stats.lastEventTime = new Date();

    // Detect anomalies
    const anomalies = [];

    // High event rate
    if (stats.eventCount > 100 && this.getEventRate(stats) > 10) {
      anomalies.push('High event rate detected');
    }

    // Unusual access patterns
    if (event.eventType === 'file_read' && this.isUnusualPath(event.data.path)) {
      anomalies.push('Unusual file access pattern');
    }

    this.anomalyBaseline.set(sessionId, stats);

    if (anomalies.length > 0) {
      return this.warn(`Security anomaly: ${anomalies.join(', ')}`);
    }

    return this.allow();
  }
}
```

### Change Management Guard (CC8.1)

```typescript
// Enhanced patch integrity with change authorization
class Soc2ChangeGuard extends PatchIntegrityGuard {
  private changeLog: ChangeLogEntry[] = [];

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    // Standard integrity check
    const result = await super.check(event, policy);

    // Log all change attempts (CC8.1 evidence)
    if (event.eventType === 'patch_apply' || event.eventType === 'file_write') {
      this.changeLog.push({
        timestamp: new Date().toISOString(),
        changeType: event.eventType,
        resource: event.data.filePath || event.data.path,
        changeHash: this.computeHash(event.data.patchContent || ''),
        outcome: result.status,
        sessionId: event.sessionId,
        agentId: event.metadata?.agentId as string,
      });
    }

    return result;
  }

  getChangeLog(): ChangeLogEntry[] {
    return this.changeLog;
  }
}

interface ChangeLogEntry {
  timestamp: string;
  changeType: string;
  resource: string;
  changeHash: string;
  outcome: string;
  sessionId?: string;
  agentId?: string;
}
```

---

## Audit Requirements

### SOC2 Audit Event Schema

```typescript
interface Soc2AuditEvent extends AuditEvent {
  soc2: {
    // Trust principle mapping
    trustPrinciples: TrustPrinciple[];

    // Control reference
    controlId: string;           // e.g., "CC6.1", "A1.1"
    controlDescription: string;

    // Evidence classification
    evidenceType: EvidenceType;
    evidenceCategory: string;

    // User context
    userType: 'system' | 'service' | 'human';
    userRole?: string;

    // Service context
    serviceComponent: string;
    subserviceOrg?: string;

    // Risk context
    riskCategory?: string;
    riskSeverity?: 'low' | 'medium' | 'high' | 'critical';
  };
}

enum TrustPrinciple {
  SECURITY = "security",
  AVAILABILITY = "availability",
  PROCESSING_INTEGRITY = "processing_integrity",
  CONFIDENTIALITY = "confidentiality",
  PRIVACY = "privacy",
}

enum EvidenceType {
  INQUIRY = "inquiry",           // Documentation
  OBSERVATION = "observation",   // Point-in-time check
  INSPECTION = "inspection",     // Document review
  REPERFORMANCE = "reperformance", // Testing controls
}
```

### Audit Period Requirements

```yaml
soc2_audit_periods:
  type_i:
    description: "Point-in-time assessment"
    evidence_date: "single date"
    typical_duration: "1-2 months"

  type_ii:
    description: "Operating effectiveness over time"
    minimum_period: 6 months
    recommended_period: 12 months
    evidence_collection: continuous
    sampling_requirements:
      - control_testing: "25+ samples per control"
      - exception_handling: "all exceptions documented"
      - deviation_analysis: "root cause for failures"

retention:
  audit_evidence: 7 years
  control_testing: 5 years
  exception_reports: 7 years
```

---

## Evidence Collection

### Control Testing Evidence

```yaml
soc2_evidence_requirements:
  cc6_logical_access:
    cc6.1:
      control: "Restrict access to information assets"
      test_procedures:
        - "Review access control policy"
        - "Test ForbiddenPathGuard configuration"
        - "Sample 25 access events"
      evidence:
        - "ForbiddenPathGuard policy YAML"
        - "Access denial logs"
        - "Access approval workflow logs"

    cc6.2:
      control: "Remove access when no longer required"
      test_procedures:
        - "Review session timeout configuration"
        - "Test session termination"
        - "Sample terminated sessions"
      evidence:
        - "Session timeout policy"
        - "Session termination logs"
        - "Access review documentation"

    cc6.6:
      control: "Restrict data transmission"
      test_procedures:
        - "Review network segmentation"
        - "Test EgressAllowlistGuard"
        - "Sample network events"
      evidence:
        - "EgressAllowlistGuard policy"
        - "Network egress logs"
        - "Allowed domain justification"

  cc7_system_operations:
    cc7.1:
      control: "Detect and respond to vulnerabilities"
      test_procedures:
        - "Review SecretLeakGuard patterns"
        - "Test secret detection"
        - "Sample detected secrets"
      evidence:
        - "SecretLeakGuard configuration"
        - "Secret detection logs"
        - "Remediation documentation"

    cc7.2:
      control: "Detect security anomalies"
      test_procedures:
        - "Review PromptInjectionGuard"
        - "Test anomaly detection"
        - "Sample security events"
      evidence:
        - "PromptInjectionGuard configuration"
        - "Anomaly detection logs"
        - "Incident response records"

  cc8_change_management:
    cc8.1:
      control: "Authorize and test changes"
      test_procedures:
        - "Review PatchIntegrityGuard"
        - "Test change validation"
        - "Sample code changes"
      evidence:
        - "PatchIntegrityGuard configuration"
        - "Change validation logs"
        - "Change approval records"
```

### Evidence Bundle for Auditors

```typescript
interface Soc2EvidenceBundle extends EvidenceBundle {
  soc2Specific: {
    // Assessment scope
    assessmentScope: {
      serviceName: string;
      serviceDescription: string;
      assessmentPeriod: { start: string; end: string };
      trustPrinciples: TrustPrinciple[];
      auditorName: string;
    };

    // Control matrix
    controlMatrix: ControlMatrixEntry[];

    // Testing results
    testingResults: {
      controlId: string;
      testProcedure: string;
      sampleSize: number;
      exceptionsFound: number;
      conclusion: 'effective' | 'deviation' | 'exception';
      deviationDetails?: string;
    }[];

    // Management assertions
    managementAssertions: {
      systemDescription: string;
      suitabilityCriteria: string;
      controlsDesign: string;
      controlsOperating: string;
    };

    // Subservice organization reports
    subserviceReports: {
      organization: string;
      reportType: string;
      reportPeriod: string;
      carveOut: boolean;
      gapsIdentified?: string[];
    }[];

    // Complementary user entity controls
    cuecs: {
      controlId: string;
      description: string;
      responsibility: 'user' | 'shared';
    }[];
  };
}

interface ControlMatrixEntry {
  controlId: string;
  trustPrinciple: TrustPrinciple;
  controlDescription: string;
  clawdstrikeGuard?: string;
  testingStatus: 'not_tested' | 'in_progress' | 'tested';
  testResult?: 'effective' | 'deviation' | 'exception';
  evidenceRef: string[];
}
```

---

## Compliance Verification

### Automated Control Testing

```typescript
interface Soc2ControlTest {
  controlId: string;
  controlName: string;
  trustPrinciple: TrustPrinciple;
  testType: 'inquiry' | 'observation' | 'inspection' | 'reperformance';
  frequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly';
  automated: boolean;
  test: () => Promise<ControlTestResult>;
}

interface ControlTestResult {
  passed: boolean;
  sampleSize: number;
  exceptionsFound: number;
  evidenceCollected: string[];
  notes?: string;
}

const soc2ControlTests: Soc2ControlTest[] = [
  {
    controlId: "CC6.1",
    controlName: "Access Restriction",
    trustPrinciple: TrustPrinciple.SECURITY,
    testType: "reperformance",
    frequency: "continuous",
    automated: true,
    test: async (): Promise<ControlTestResult> => {
      // Verify ForbiddenPathGuard is enabled
      // Sample recent access events
      // Check for unauthorized access attempts
      // Verify all denials are logged
      return {
        passed: true,
        sampleSize: 25,
        exceptionsFound: 0,
        evidenceCollected: ['access_log_sample.json', 'guard_config.yaml'],
      };
    },
  },
  {
    controlId: "CC6.6",
    controlName: "Network Segmentation",
    trustPrinciple: TrustPrinciple.SECURITY,
    testType: "reperformance",
    frequency: "continuous",
    automated: true,
    test: async (): Promise<ControlTestResult> => {
      // Verify EgressAllowlistGuard is enabled
      // Sample network events
      // Check that blocked domains are enforced
      // Verify no unauthorized egress
      return {
        passed: true,
        sampleSize: 25,
        exceptionsFound: 0,
        evidenceCollected: ['network_log_sample.json', 'egress_policy.yaml'],
      };
    },
  },
  {
    controlId: "CC7.2",
    controlName: "Anomaly Detection",
    trustPrinciple: TrustPrinciple.SECURITY,
    testType: "observation",
    frequency: "weekly",
    automated: true,
    test: async (): Promise<ControlTestResult> => {
      // Verify PromptInjectionGuard is enabled
      // Check for anomaly alerts
      // Verify incident response for detected anomalies
      return {
        passed: true,
        sampleSize: 10,
        exceptionsFound: 0,
        evidenceCollected: ['anomaly_log_sample.json', 'incident_response.pdf'],
      };
    },
  },
  {
    controlId: "CC8.1",
    controlName: "Change Authorization",
    trustPrinciple: TrustPrinciple.SECURITY,
    testType: "inspection",
    frequency: "weekly",
    automated: true,
    test: async (): Promise<ControlTestResult> => {
      // Verify PatchIntegrityGuard is enabled
      // Sample recent code changes
      // Check for unauthorized change attempts
      // Verify change validation
      return {
        passed: true,
        sampleSize: 25,
        exceptionsFound: 0,
        evidenceCollected: ['change_log_sample.json', 'patch_policy.yaml'],
      };
    },
  },
];
```

### SOC2 Dashboard

```yaml
soc2_dashboard:
  overview:
    - metric: "Control Coverage"
      value: "percentage of controls with evidence"
      target: "100%"

    - metric: "Control Effectiveness"
      value: "percentage of controls passing tests"
      target: "95%+"

    - metric: "Exception Rate"
      value: "exceptions / total tests"
      target: "<5%"

    - metric: "Days in Audit Period"
      value: "days since Type II start"
      target: "180+ days"

  by_trust_principle:
    security:
      - control: "CC6.1 - Access Restriction"
        status: "effective | deviation | exception"
        last_test: timestamp
        sample_size: number

      - control: "CC6.6 - Network Segmentation"
        status: "effective | deviation | exception"
        last_test: timestamp
        sample_size: number

      # ... all security controls

    availability:
      - control: "A1.1 - Capacity Planning"
        status: "effective | deviation | exception"
        last_test: timestamp

  exceptions:
    - exception_id: string
      control_id: string
      description: string
      root_cause: string
      remediation: string
      status: "open | in_progress | closed"
      target_date: date
```

---

## Continuous Compliance

### Type II Evidence Collection

```yaml
type_ii_monitoring:
  evidence_collection:
    # Collect evidence continuously
    interval: "real-time"

    # Aggregate daily for testing
    aggregation: "daily"

    # Sample for auditor review
    sampling:
      method: "random"
      size_per_control: 25
      selection_frequency: "monthly"

  control_monitoring:
    cc6.1_access:
      metric: "Unauthorized access attempts"
      threshold: 0
      alert: "immediate"

    cc6.6_network:
      metric: "Blocked egress attempts"
      threshold: 10  # per day
      alert: "daily summary"

    cc7.2_anomaly:
      metric: "Security anomalies detected"
      threshold: 5  # per day
      alert: "immediate"

    cc8.1_change:
      metric: "Unauthorized change attempts"
      threshold: 0
      alert: "immediate"

  exception_management:
    detection: "automated"
    escalation:
      - severity: high
        notify: ["security@company.com", "compliance@company.com"]
        sla: "24 hours"
      - severity: medium
        notify: ["compliance@company.com"]
        sla: "72 hours"

    remediation_tracking: true
    root_cause_required: true
```

### Readiness Assessment

```typescript
interface Soc2ReadinessAssessment {
  assessmentId: string;
  assessmentDate: string;
  targetType: 'type_i' | 'type_ii';
  trustPrinciples: TrustPrinciple[];

  controlGaps: {
    controlId: string;
    gapDescription: string;
    remediationPlan: string;
    targetDate: string;
    status: 'identified' | 'in_progress' | 'resolved';
  }[];

  readinessScore: {
    overall: number;      // 0-100%
    byPrinciple: Record<TrustPrinciple, number>;
    byControlFamily: Record<string, number>;
  };

  recommendations: string[];
  estimatedAuditDate: string;
}
```

---

## Evidence Collection Automation

### Automated Evidence Collectors

```typescript
// SOC2 Evidence Automation Configuration
interface Soc2EvidenceAutomation {
  collectors: EvidenceCollector[];
  schedule: AutomationSchedule;
  controlTesting: ControlTestingConfig;
}

const soc2Automation: Soc2EvidenceAutomation = {
  collectors: [
    {
      id: "access-control-collector",
      control: "CC6.1",
      trustPrinciple: "security",
      description: "Collect logical access control evidence",
      query: {
        eventTypes: ["file_access", "file_write", "guard_deny"],
        interval: "5m"
      },
      evidenceFormat: "jsonl",
      samplingConfig: {
        method: "random",
        sizePerPeriod: 25,
        period: "monthly"
      }
    },
    {
      id: "network-boundary-collector",
      control: "CC6.6",
      trustPrinciple: "security",
      description: "Collect network transmission evidence",
      query: {
        eventTypes: ["network_egress", "network_connect"],
        interval: "5m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "anomaly-detection-collector",
      control: "CC7.2",
      trustPrinciple: "security",
      description: "Collect security anomaly detection evidence",
      query: {
        eventTypes: ["injection_detected", "anomaly_detected"],
        interval: "1m"
      },
      evidenceFormat: "jsonl"
    },
    {
      id: "change-management-collector",
      control: "CC8.1",
      trustPrinciple: "security",
      description: "Collect change authorization evidence",
      query: {
        eventTypes: ["patch_apply", "file_write", "policy_change"],
        interval: "5m"
      },
      evidenceFormat: "jsonl"
    }
  ],

  schedule: {
    realtime: ["access-control-collector", "network-boundary-collector", "anomaly-detection-collector"],
    hourly: ["change-management-collector"],
    aggregation: {
      daily: true,
      weekly: true,
      monthly: true
    }
  },

  // Type II continuous testing configuration
  controlTesting: {
    enabled: true,
    minimumSampleSize: 25,
    testingFrequency: {
      "CC6.1": "continuous",
      "CC6.6": "continuous",
      "CC7.2": "weekly",
      "CC8.1": "weekly"
    },
    exceptionHandling: {
      autoDetect: true,
      escalation: {
        high: { notify: ["security@company.com"], sla: "24h" },
        medium: { notify: ["compliance@company.com"], sla: "72h" }
      },
      rootCauseRequired: true
    }
  }
};
```

### Evidence Collection CLI Commands

```bash
# Collect evidence for a specific control
openclaw evidence collect --control CC6.1 --period 30d

# Generate SOC2 evidence bundle
openclaw evidence bundle \
  --template soc2 \
  --trust-principles security,availability \
  --start 2025-01-01 \
  --end 2025-06-30 \
  --output soc2_h1_evidence.zip

# Run control testing
openclaw soc2 test-controls \
  --controls CC6.1,CC6.6,CC7.2,CC8.1 \
  --sample-size 25

# Generate readiness assessment
openclaw soc2 readiness \
  --type type-ii \
  --trust-principles security,availability,confidentiality

# Schedule automated evidence collection for Type II
openclaw evidence schedule \
  --template soc2 \
  --continuous \
  --sample-monthly 25 \
  --destination s3://soc2-evidence/
```

### Type II Evidence Sampling

```yaml
type_ii_sampling:
  # SOC2 Type II requires evidence over minimum 6-month period
  minimum_period_days: 180
  recommended_period_days: 365

  sampling_strategy:
    method: "stratified_random"
    minimum_per_control: 25
    selection_criteria:
      - "Distribute across full audit period"
      - "Include both successful and failed events"
      - "Cover all guards and control types"

  evidence_requirements:
    per_control:
      - "Policy/configuration documentation"
      - "25+ sampled events"
      - "Exception documentation (if any)"
      - "Testing results and conclusions"

    overall:
      - "System description"
      - "Management assertions"
      - "Control matrix with testing results"
      - "Exception summary and remediation"
```

---

## Implementation Phases

### Phase 1: Core SOC2 Policy (Q1 2025)
- [ ] Trust criteria mapping
- [ ] Control matrix definition
- [ ] SOC2 policy template
- [ ] Basic control testing
- [ ] Evidence schema

### Phase 2: Type I Readiness (Q2 2025)
- [ ] All CC controls implemented
- [ ] Control documentation
- [ ] Point-in-time evidence collection
- [ ] Readiness assessment
- [ ] Auditor portal access

### Phase 3: Type II Monitoring (Q3 2025)
- [ ] Continuous evidence collection
- [ ] Automated control testing
- [ ] Exception management
- [ ] Sampling automation
- [ ] 6-month evidence accumulation

### Phase 4: Certification (Q4 2025)
- [ ] Type II attestation
- [ ] SOC2 certification badge
- [ ] Subservice integration
- [ ] CUEC documentation
- [ ] Annual re-attestation workflow

---

## Pricing for SOC2 Tier

| Item | Price | Includes |
|------|-------|----------|
| SOC2 Policy Template | Included in Gold | Policy YAML + control matrix |
| Continuous Evidence Collection | Included in Gold | Automated logging |
| Control Testing Automation | $1,000/month | Automated test execution |
| Type I Readiness Assessment | $5,000 | Gap analysis + remediation plan |
| Type II Evidence Package | $10,000 | 6-12 month evidence bundle |
| Auditor Portal Access | Included | CPA firm access |
| Annual SOC2 Attestation Support | $15,000 | Auditor coordination |

---

## Appendix: SOC2 Quick Reference

### Common Criteria (CC) Control Families

| Family | Controls | Focus |
|--------|----------|-------|
| CC1 | COSO Principles | Control environment |
| CC2 | Communication | Information & communication |
| CC3 | Risk Assessment | Risk identification |
| CC4 | Monitoring | Control monitoring |
| CC5 | Control Activities | Policies & procedures |
| CC6 | Logical & Physical Access | Access controls |
| CC7 | System Operations | Operations management |
| CC8 | Change Management | Change controls |
| CC9 | Risk Mitigation | Risk response |

### Trust Principle Applicability

| Principle | Common Use Cases |
|-----------|------------------|
| Security | All (required) |
| Availability | SaaS, cloud services |
| Processing Integrity | Financial, data processing |
| Confidentiality | B2B, data handling |
| Privacy | Consumer data, PII |

### SOC Report Types

| Report Type | Audience | Contents |
|-------------|----------|----------|
| SOC1 | Financial auditors | ICFR controls |
| SOC2 Type I | General | Control design (point-in-time) |
| SOC2 Type II | General | Control effectiveness (period) |
| SOC3 | Public | General use report |

### Key Timelines

| Requirement | Timeline |
|-------------|----------|
| Type I assessment | 1-2 months |
| Type II minimum period | 6 months |
| Type II recommended period | 12 months |
| Report issuance | 30-60 days after period |
| Evidence retention | 7 years |
