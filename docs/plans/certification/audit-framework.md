# Security Audit Framework for AI Agents

## Overview

This document specifies the Clawdstrike Security Audit Framework, a comprehensive system for capturing, storing, analyzing, and reporting on AI agent security events. The framework provides the evidentiary foundation for the certification program and compliance attestations.

---

## Problem Statement

### The Audit Evidence Gap

1. **Ephemeral Agent Actions**: AI agents perform thousands of actions per session; without structured logging, evidence is lost.

2. **Non-Repudiation Failure**: Traditional logs can be modified; agents need tamper-evident audit trails.

3. **Compliance Gaps**: Auditors require specific evidence formats; ad-hoc logging doesn't meet regulatory standards.

4. **Cross-Session Correlation**: Understanding agent behavior requires linking actions across sessions, tools, and time.

5. **Scale Challenges**: High-volume agent deployments generate massive audit data; storage and query performance suffer.

6. **Multi-Tenant Isolation**: Enterprise deployments require strict data isolation between tenants/agents.

### Use Cases

| Stakeholder | Audit Need | Framework Solution |
|-------------|------------|-------------------|
| Security Team | Investigate incidents | Timeline reconstruction |
| Compliance Officer | Demonstrate controls | Evidence export |
| External Auditor | Verify policy enforcement | Signed audit packages |
| Developer | Debug agent behavior | Action replay |
| Legal | Litigation hold | Immutable retention |
| Executive | Risk dashboard | Aggregated metrics |

---

## Audit Event Model

### Core Event Structure

```typescript
interface AuditEvent {
  // Identity
  eventId: string;                // UUID v7 (time-ordered)
  eventType: AuditEventType;      // Discriminated union type
  timestamp: string;              // RFC 3339 with nanoseconds
  sequence: number;               // Monotonic sequence within session

  // Context
  sessionId: string;              // Agent session identifier
  agentId: string;                // Agent identifier
  organizationId: string;         // Tenant identifier
  correlationId?: string;         // Cross-session correlation

  // Action
  action: {
    type: ActionType;             // file_read, egress, tool_call, etc.
    resource: string;             // Path, URL, tool name
    parameters: Record<string, unknown>;
    result?: ActionResult;
  };

  // Decision
  decision: {
    allowed: boolean;
    guard?: string;               // Which guard made the decision
    severity?: Severity;
    reason?: string;
    policyHash: string;           // Policy in effect
  };

  // Provenance
  provenance: {
    sourceIp?: string;
    userAgent?: string;
    environment?: string;         // dev, staging, production
    deploymentId?: string;
  };

  // Integrity
  integrity: {
    previousHash: string;         // Hash of previous event (chain)
    contentHash: string;          // Hash of this event's content
    signature?: string;           // Optional Ed25519 signature
  };
}
```

### Event Types

```typescript
enum AuditEventType {
  // Policy events
  POLICY_LOADED = "policy_loaded",
  POLICY_CHANGED = "policy_changed",
  POLICY_VIOLATION = "policy_violation",

  // Guard events
  GUARD_CHECK = "guard_check",
  GUARD_ALLOW = "guard_allow",
  GUARD_DENY = "guard_deny",
  GUARD_WARN = "guard_warn",

  // Session events
  SESSION_START = "session_start",
  SESSION_END = "session_end",
  SESSION_TIMEOUT = "session_timeout",

  // Action events
  FILE_ACCESS = "file_access",
  FILE_WRITE = "file_write",
  NETWORK_EGRESS = "network_egress",
  COMMAND_EXEC = "command_exec",
  TOOL_CALL = "tool_call",
  PATCH_APPLY = "patch_apply",

  // Security events
  SECRET_DETECTED = "secret_detected",
  SECRET_REDACTED = "secret_redacted",
  INJECTION_DETECTED = "injection_detected",
  ANOMALY_DETECTED = "anomaly_detected",

  // Administrative events
  AUDIT_EXPORT = "audit_export",
  RETENTION_APPLIED = "retention_applied",
  CERTIFICATE_ISSUED = "certificate_issued",
}
```

### Action Types

```typescript
enum ActionType {
  FILE_READ = "file_read",
  FILE_WRITE = "file_write",
  FILE_DELETE = "file_delete",
  DIRECTORY_LIST = "directory_list",

  NETWORK_CONNECT = "network_connect",
  NETWORK_REQUEST = "network_request",
  NETWORK_RESPONSE = "network_response",

  COMMAND_EXECUTE = "command_execute",
  COMMAND_OUTPUT = "command_output",

  TOOL_INVOKE = "tool_invoke",
  TOOL_RESULT = "tool_result",

  PATCH_PARSE = "patch_parse",
  PATCH_VALIDATE = "patch_validate",
  PATCH_APPLY = "patch_apply",

  SECRET_SCAN = "secret_scan",
  SECRET_ACCESS = "secret_access",

  PROMPT_RECEIVE = "prompt_receive",
  RESPONSE_GENERATE = "response_generate",
}
```

---

## Audit Chain Architecture

### Hash Chain Design

```
EVENT 1           EVENT 2           EVENT 3           EVENT 4
+---------+       +---------+       +---------+       +---------+
| content |       | content |       | content |       | content |
+---------+       +---------+       +---------+       +---------+
     |                 |                 |                 |
     v                 v                 v                 v
+---------+       +---------+       +---------+       +---------+
|  hash1  |------>|  hash2  |------>|  hash3  |------>|  hash4  |
| prev:00 |       |prev:h1  |       |prev:h2  |       |prev:h3  |
+---------+       +---------+       +---------+       +---------+

Hash Chain Properties:
- Append-only: Cannot insert/modify without breaking chain
- Verifiable: Any party can verify chain integrity
- Portable: Chain can be exported and verified offline
```

### Hash Computation

```rust
fn compute_event_hash(event: &AuditEvent, previous_hash: &[u8; 32]) -> [u8; 32] {
    // Canonical serialization (deterministic JSON)
    let canonical = serde_json::to_vec(&CanonicalEvent {
        event_id: &event.event_id,
        event_type: &event.event_type,
        timestamp: &event.timestamp,
        session_id: &event.session_id,
        action: &event.action,
        decision: &event.decision,
    }).unwrap();

    // Chain hash: SHA256(previous_hash || content)
    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(&canonical);
    hasher.finalize().into()
}
```

### Merkle Tree for Batch Verification

```
                    ROOT HASH
                   /         \
              HASH_A          HASH_B
             /     \         /      \
          H(E1)   H(E2)   H(E3)   H(E4)
           |       |       |       |
         Event1  Event2  Event3  Event4

Benefits:
- Efficient subset verification (log N proofs)
- Parallel hash computation
- Compact audit summaries
```

---

## Storage Architecture

### Storage Tiers

```
HOT TIER (0-7 days)
+--------------------------------------------------+
| In-memory buffer + SSD-backed storage            |
| Full query capability, <10ms latency             |
| Format: JSONL with bloom filter index            |
+--------------------------------------------------+
          |
          | Age-out
          v
WARM TIER (7-90 days)
+--------------------------------------------------+
| Object storage (S3/GCS) with columnar index      |
| Query via Athena/BigQuery, <5s latency           |
| Format: Parquet with partition by date/org       |
+--------------------------------------------------+
          |
          | Age-out
          v
COLD TIER (90 days - retention limit)
+--------------------------------------------------+
| Archive storage (Glacier/Coldline)               |
| Retrieval: 4-12 hours                            |
| Format: Compressed Parquet, encrypted at rest    |
+--------------------------------------------------+
          |
          | Retention expiry
          v
DELETION (with compliance hold exception)
```

### Local Storage (OpenClaw SDK)

```typescript
// From existing AuditStore implementation
interface LocalAuditStore {
  path: string;                    // e.g., ".hush/audit.jsonl"

  // Append event to local store
  append(event: Omit<AuditEvent, 'id' | 'timestamp'>): AuditEvent;

  // Query local events
  query(options: QueryOptions): AuditEvent[];

  // Sync to remote (if configured)
  sync(): Promise<SyncResult>;

  // Export for auditors
  export(options: ExportOptions): Promise<Buffer>;
}

interface QueryOptions {
  since?: number;                  // Unix timestamp
  until?: number;
  guard?: string;
  denied?: boolean;
  limit?: number;
  sessionId?: string;
}
```

### Cloud Storage Schema

```sql
-- Audit events table (partitioned by date and organization)
CREATE TABLE audit_events (
  event_id UUID PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  sequence BIGINT NOT NULL,

  session_id UUID NOT NULL,
  agent_id VARCHAR(255) NOT NULL,
  organization_id UUID NOT NULL,
  correlation_id UUID,

  action_type VARCHAR(50) NOT NULL,
  action_resource TEXT NOT NULL,
  action_parameters JSONB,
  action_result JSONB,

  decision_allowed BOOLEAN NOT NULL,
  decision_guard VARCHAR(50),
  decision_severity VARCHAR(20),
  decision_reason TEXT,
  decision_policy_hash VARCHAR(64) NOT NULL,

  provenance JSONB,

  content_hash VARCHAR(64) NOT NULL,
  previous_hash VARCHAR(64) NOT NULL,
  signature TEXT,

  -- Partitioning
  created_date DATE NOT NULL
)
PARTITION BY RANGE (created_date);

-- Indexes for common queries
CREATE INDEX idx_events_session ON audit_events (session_id, sequence);
CREATE INDEX idx_events_org_time ON audit_events (organization_id, timestamp);
CREATE INDEX idx_events_denied ON audit_events (organization_id, decision_allowed)
  WHERE decision_allowed = FALSE;
CREATE INDEX idx_events_guard ON audit_events (decision_guard, timestamp);
```

---

## Evidence Collection

### Guard-Specific Evidence

#### ForbiddenPathGuard Evidence

```typescript
interface PathAccessEvidence {
  eventType: "file_access" | "file_write";
  path: string;
  normalizedPath: string;
  matchedPattern?: string;         // Which pattern blocked
  allowed: boolean;
  timestamp: string;
  contentHash?: string;            // For writes
}
```

#### EgressAllowlistGuard Evidence

```typescript
interface EgressEvidence {
  eventType: "network_egress";
  host: string;
  port: number;
  protocol: string;
  url?: string;
  matchedRule?: string;            // allow/block pattern
  allowed: boolean;
  timestamp: string;
  bytesTransferred?: number;
}
```

#### SecretLeakGuard Evidence

```typescript
interface SecretLeakEvidence {
  eventType: "secret_detected" | "secret_redacted";
  patternName: string;
  severity: Severity;
  context: string;                 // Surrounding text (redacted)
  location: {
    file?: string;
    line?: number;
    toolName?: string;
  };
  redacted: boolean;
  timestamp: string;
}
```

#### PatchIntegrityGuard Evidence

```typescript
interface PatchEvidence {
  eventType: "patch_apply";
  filePath: string;
  patchSize: number;
  dangerousPatterns: string[];     // Matched patterns
  allowed: boolean;
  patchHash: string;
  timestamp: string;
}
```

#### McpToolGuard Evidence

```typescript
interface ToolCallEvidence {
  eventType: "tool_call";
  toolName: string;
  parameters: Record<string, unknown>;
  allowed: boolean;
  matchedRule?: string;            // allow/deny rule
  executionTime?: number;
  resultSize?: number;
  timestamp: string;
}
```

#### PromptInjectionGuard Evidence

```typescript
interface InjectionEvidence {
  eventType: "injection_detected";
  source: string;                  // URL, file, user input
  level: PromptInjectionLevel;
  signals: string[];               // Detected indicators
  action: "warn" | "block";
  text_snippet: string;            // First 200 chars, redacted
  timestamp: string;
}
```

### Evidence Aggregation

```typescript
// Base evidence bundle format - used across all compliance templates
interface EvidenceBundle {
  bundleId: string;
  bundleVersion: "1.0.0";          // Schema version for compatibility
  organizationId: string;
  generatedAt: string;             // RFC 3339 timestamp

  // Time range
  periodStart: string;             // RFC 3339
  periodEnd: string;               // RFC 3339

  // Summary statistics
  summary: {
    totalEvents: number;
    totalSessions: number;
    totalViolations: number;
    violationsByGuard: Record<string, number>;
    violationsBySeverity: Record<Severity, number>;
    uniqueAgents: number;
    complianceScore: number;       // 0-100%
  };

  // Policy snapshots
  policies: PolicySnapshot[];

  // Guard configurations
  guardConfigs: GuardConfigSnapshot[];

  // Events (or reference to storage)
  events?: AuditEvent[];
  eventsRef?: string;              // S3 URI or similar
  eventCount: number;

  // Compliance-specific extensions
  complianceExtensions?: {
    hipaa?: HipaaEvidenceExtension;
    pciDss?: PciEvidenceExtension;
    soc2?: Soc2EvidenceExtension;
  };

  // Integrity
  integrity: {
    merkleRoot: string;            // SHA-256 Merkle root of all evidence
    hashChainVerified: boolean;    // Whether event chain was verified
    signature: string;             // Ed25519 signature of bundle
    signedBy: string;              // Issuer ID
    signedAt: string;              // RFC 3339 timestamp
    publicKey: string;             // Public key for verification
  };
}

// Extension types for compliance-specific data
interface HipaaEvidenceExtension {
  phiAccessCount: number;
  phiAccessDenied: number;
  disclosureCount: number;
  retentionCompliant: boolean;
}

interface PciEvidenceExtension {
  chdAccessCount: number;
  panDetectionCount: number;
  cdeAccessAttempts: number;
  dailyReviewsCompleted: number;
}

interface Soc2EvidenceExtension {
  controlsTested: number;
  controlsPassing: number;
  exceptionsFound: number;
  trustPrinciplesCovered: TrustPrinciple[];
}

interface PolicySnapshot {
  hash: string;
  effectiveFrom: string;
  effectiveTo?: string;
  policyYaml: string;
}
```

---

## Query and Analysis

### Query Language

```typescript
// Audit Query DSL
interface AuditQuery {
  // Time range (required)
  timeRange: {
    start: string;                 // RFC 3339
    end: string;
  };

  // Filters
  filters?: {
    sessionId?: string;
    agentId?: string;
    organizationId?: string;
    eventTypes?: AuditEventType[];
    actionTypes?: ActionType[];
    guards?: string[];
    allowed?: boolean;
    severity?: Severity[];
    resource?: string;             // Glob pattern
  };

  // Aggregations
  aggregate?: {
    groupBy?: ('hour' | 'day' | 'guard' | 'agent' | 'action_type')[];
    metrics?: ('count' | 'violation_rate' | 'unique_sessions')[];
  };

  // Pagination
  limit?: number;
  offset?: number;
  cursor?: string;

  // Output
  format?: 'json' | 'csv' | 'parquet';
  includeRaw?: boolean;
}
```

### Example Queries

```typescript
// All violations in last 24 hours
const recentViolations: AuditQuery = {
  timeRange: {
    start: "2025-01-14T00:00:00Z",
    end: "2025-01-15T00:00:00Z",
  },
  filters: {
    allowed: false,
  },
  aggregate: {
    groupBy: ['hour', 'guard'],
    metrics: ['count'],
  },
};

// All egress to specific domain
const egressToDomain: AuditQuery = {
  timeRange: {
    start: "2025-01-01T00:00:00Z",
    end: "2025-01-15T00:00:00Z",
  },
  filters: {
    actionTypes: [ActionType.NETWORK_REQUEST],
    resource: "*.evil.com",
  },
};

// Session timeline reconstruction
const sessionTimeline: AuditQuery = {
  timeRange: {
    start: "2025-01-14T10:00:00Z",
    end: "2025-01-14T11:00:00Z",
  },
  filters: {
    sessionId: "sess_abc123",
  },
  includeRaw: true,
};
```

### Analytics Dashboard Metrics

```yaml
dashboard_metrics:
  real_time:
    - name: "Active Sessions"
      query: "COUNT(DISTINCT session_id) WHERE timestamp > NOW() - INTERVAL 5 MINUTE"

    - name: "Violations/Minute"
      query: "COUNT(*) WHERE allowed = false GROUP BY MINUTE(timestamp)"

    - name: "Top Blocked Resources"
      query: "resource, COUNT(*) WHERE allowed = false GROUP BY resource LIMIT 10"

  daily_rollup:
    - name: "Daily Violation Trend"
      query: "DATE(timestamp), guard, COUNT(*) WHERE allowed = false GROUP BY 1, 2"

    - name: "Agent Activity Heatmap"
      query: "agent_id, HOUR(timestamp), COUNT(*) GROUP BY 1, 2"

    - name: "Policy Compliance Score"
      formula: "(1 - violations / total_events) * 100"

  compliance:
    - name: "PHI Access Log (HIPAA)"
      query: "* WHERE resource LIKE '%phi%' OR resource LIKE '%patient%'"

    - name: "Cardholder Data Access (PCI)"
      query: "* WHERE resource LIKE '%card%' OR resource LIKE '%pan%'"
```

---

## Retention and Compliance

### Retention Policies

```yaml
retention_policies:
  default:
    hot_tier: 7 days
    warm_tier: 83 days
    cold_tier: 275 days
    total: 365 days

  hipaa:
    hot_tier: 7 days
    warm_tier: 90 days
    cold_tier: 2465 days  # 6 years + current
    total: 2557 days

  pci_dss:
    hot_tier: 7 days
    warm_tier: 90 days
    cold_tier: 268 days
    total: 365 days

  soc2:
    hot_tier: 7 days
    warm_tier: 90 days
    cold_tier: 268 days
    total: 365 days

  regulatory_investigation:
    # Legal hold - indefinite until released
    legal_hold: true
    hold_reason: "Required field"
    hold_expiry: "Manual release"
```

### Data Deletion

```typescript
interface DeletionPolicy {
  // Scheduled deletion
  scheduledDeletion: {
    enabled: boolean;
    retentionDays: number;
    dryRun: boolean;
  };

  // Legal hold exceptions
  legalHolds: {
    holdId: string;
    reason: string;
    createdBy: string;
    createdAt: string;
    expiresAt?: string;
    affectedOrganizations?: string[];
    affectedSessions?: string[];
  }[];

  // Deletion confirmation
  deletionLog: {
    deletionId: string;
    executedAt: string;
    eventCount: number;
    dateRange: { start: string; end: string };
    executedBy: string;
    confirmationHash: string;  // Hash of deleted event IDs
  }[];
}
```

### Encryption Requirements

```yaml
encryption:
  at_rest:
    algorithm: AES-256-GCM
    key_management: AWS KMS / GCP KMS / Azure Key Vault
    key_rotation: 90 days
    per_tenant_keys: true  # For multi-tenant isolation

  in_transit:
    protocol: TLS 1.3
    certificate_pinning: optional
    mutual_tls: enterprise tier

  backup:
    algorithm: AES-256-GCM
    key_escrow: customer-managed or Clawdstrike-managed
    geographic_redundancy: configurable
```

---

## Export and Reporting

### Export Formats

#### JSONL Export

```bash
# Export all events for a session
$ openclaw audit export --session-id sess_abc123 --format jsonl > session.jsonl

# Sample output
{"eventId":"evt_001","eventType":"session_start",...}
{"eventId":"evt_002","eventType":"tool_call",...}
{"eventId":"evt_003","eventType":"guard_deny",...}
```

#### Parquet Export

```bash
# Export for data analysis
$ openclaw audit export \
    --org-id org_xyz \
    --start 2025-01-01 \
    --end 2025-01-31 \
    --format parquet \
    --output january_audit.parquet
```

#### Compliance Report (PDF)

```bash
# Generate HIPAA compliance report
$ openclaw audit report \
    --template hipaa \
    --org-id org_xyz \
    --period 2025-Q1 \
    --output hipaa_q1_2025.pdf
```

### Report Templates

```typescript
interface ComplianceReport {
  reportId: string;
  template: "hipaa" | "pci_dss" | "soc2" | "custom";
  organizationId: string;
  period: { start: string; end: string };
  generatedAt: string;

  sections: ReportSection[];

  summary: {
    overallCompliance: number;      // 0-100%
    controlsAssessed: number;
    controlsPassing: number;
    criticalFindings: number;
    recommendations: string[];
  };

  signoff: {
    generatedBy: string;
    reviewedBy?: string;
    approvedBy?: string;
    signature?: string;
  };
}

interface ReportSection {
  controlId: string;               // e.g., "HIPAA 164.312(a)(1)"
  controlName: string;
  status: "pass" | "fail" | "partial" | "not_applicable";
  evidence: {
    eventCount: number;
    sampleEvents: AuditEvent[];
    guardMapping: string;
  };
  findings?: string[];
  remediation?: string[];
}
```

---

## Integration Points

### SIEM Integration

```yaml
siem_integrations:
  splunk:
    method: HEC (HTTP Event Collector)
    format: JSON
    batching: 100 events or 5 seconds
    retry: exponential backoff

  datadog:
    method: Logs API
    format: JSON
    enrichment: automatic tag extraction
    alerting: anomaly detection rules

  elastic:
    method: Filebeat / Logstash
    format: JSON / ECS
    index_pattern: "clawdstrike-audit-*"

  azure_sentinel:
    method: Log Analytics API
    format: CEF
    workspace: customer-provided

  generic_webhook:
    method: POST
    format: configurable
    authentication: bearer / basic / hmac
    retry: configurable
```

### Webhook Events

```typescript
// Webhook payload for violations
interface ViolationWebhook {
  webhookType: "audit.violation";
  timestamp: string;
  event: AuditEvent;
  context: {
    sessionUrl: string;
    policyUrl: string;
    remediationUrl?: string;
  };
}

// Webhook registration
POST /api/v1/webhooks
{
  "url": "https://example.com/clawdstrike-webhook",
  "events": ["audit.violation", "audit.session_end"],
  "secret": "hmac_secret_for_signature",
  "enabled": true
}
```

---

## Implementation Phases

### Phase 1: Core Audit (Q1 2025)
- [ ] Event schema finalization
- [ ] Hash chain implementation
- [ ] Local JSONL storage
- [ ] Basic query API
- [ ] CLI export commands

### Phase 2: Cloud Storage (Q2 2025)
- [ ] S3/GCS integration
- [ ] Tiered storage automation
- [ ] Parquet conversion
- [ ] Athena/BigQuery queries
- [ ] Retention automation

### Phase 3: Analytics (Q3 2025)
- [ ] Dashboard metrics
- [ ] Anomaly detection
- [ ] Trend analysis
- [ ] Custom alerts
- [ ] Report generation

### Phase 4: Enterprise (Q4 2025)
- [ ] SIEM integrations
- [ ] Compliance templates
- [ ] Legal hold support
- [ ] Multi-tenant isolation
- [ ] SOC2 Type II attestation

---

## Security Considerations

### Audit Log Protection

| Threat | Mitigation |
|--------|------------|
| Log tampering | Hash chain + signatures |
| Unauthorized access | RBAC + encryption |
| Log injection | Input validation + sanitization |
| Denial of service | Rate limiting + buffering |
| Data exfiltration | Egress monitoring (dogfooding) |

### Access Control

```yaml
audit_access_roles:
  audit_viewer:
    - read audit events (own org)
    - export audit data (own org)
    - view dashboards

  audit_admin:
    - all viewer permissions
    - configure retention
    - manage webhooks
    - create reports

  compliance_officer:
    - all viewer permissions
    - access all orgs (read-only)
    - generate compliance reports
    - manage legal holds

  super_admin:
    - all permissions
    - delete audit data (with approval)
    - manage audit infrastructure
```

---

## Appendix: Audit Event Schema (JSON Schema)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://openclaw.dev/schemas/audit-event/v1.json",
  "title": "Clawdstrike Audit Event",
  "type": "object",
  "required": ["eventId", "eventType", "timestamp", "sessionId", "action", "decision", "integrity"],
  "properties": {
    "eventId": {
      "type": "string",
      "format": "uuid",
      "description": "UUID v7 (time-ordered)"
    },
    "eventType": {
      "type": "string",
      "enum": ["policy_loaded", "guard_check", "guard_deny", ...]
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "sequence": {
      "type": "integer",
      "minimum": 0
    },
    "sessionId": {
      "type": "string"
    },
    "agentId": {
      "type": "string"
    },
    "organizationId": {
      "type": "string"
    },
    "action": {
      "type": "object",
      "properties": {
        "type": { "type": "string" },
        "resource": { "type": "string" },
        "parameters": { "type": "object" },
        "result": { "type": "object" }
      },
      "required": ["type", "resource"]
    },
    "decision": {
      "type": "object",
      "properties": {
        "allowed": { "type": "boolean" },
        "guard": { "type": "string" },
        "severity": { "enum": ["info", "warning", "error", "critical"] },
        "reason": { "type": "string" },
        "policyHash": { "type": "string", "pattern": "^[a-f0-9]{64}$" }
      },
      "required": ["allowed", "policyHash"]
    },
    "integrity": {
      "type": "object",
      "properties": {
        "previousHash": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
        "contentHash": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
        "signature": { "type": "string" }
      },
      "required": ["previousHash", "contentHash"]
    }
  }
}
```
