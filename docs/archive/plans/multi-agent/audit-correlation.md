# Audit Correlation Specification

## Problem Statement

In multi-agent systems, understanding what happened across agent boundaries is critical for security monitoring, incident response, and compliance. Without correlated audit logs:

1. **Incomplete Picture**: Each agent's logs tell only part of the story
2. **Causality Gaps**: Cannot trace which agent action caused another
3. **Time Drift**: Timestamps from different agents may not align
4. **Evidence Fragmentation**: Forensic investigation spans multiple disconnected sources
5. **Compliance Gaps**: Cannot demonstrate end-to-end audit trail

This specification defines how audit events are structured, correlated, and stored across multi-agent systems.

## Threat Model

### Attack Scenarios

#### Scenario 1: Audit Log Tampering

```
Compromised Agent modifies its local audit log
                    |
                    v
Removes evidence of malicious activity
```

**Mitigation**: Cryptographic log chaining, remote attestation of logs

#### Scenario 2: Correlation ID Injection

```
Malicious Agent injects fake trace ID
                    |
                    v
Frames another agent for its actions
```

**Mitigation**: Signed correlation contexts, chain verification

#### Scenario 3: Time Manipulation

```
Compromised Agent backdates audit entries
                    |
                    v
Events appear in wrong order, causality broken
```

**Mitigation**: Trusted timestamps, Merkle tree anchoring

#### Scenario 4: Log Exfiltration

```
Audit logs contain sensitive information
                    |
                    v
Attacker reads audit logs
```

**Mitigation**: Log encryption, access control, data minimization

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| Compromised Agent | Modify local logs | Hide malicious activity |
| Insider | Access to log storage | Surveillance, data theft |
| External Attacker | Network access | Exfiltrate audit data |
| Rogue Admin | Access to correlation service | Manipulate audit trail |

## Architecture

### Audit Event Flow

```
+-------------+     +-------------+     +-------------+
| Agent A     |     | Agent B     |     | Agent C     |
| +---------+ |     | +---------+ |     | +---------+ |
| | Local   | |     | | Local   | |     | | Local   | |
| | Audit   | |     | | Audit   | |     | | Audit   | |
| | Buffer  | |     | | Buffer  | |     | | Buffer  | |
| +----+----+ |     | +----+----+ |     | +----+----+ |
+------+------+     +------+------+     +------+------+
       |                   |                   |
       |    +-----------------------------+    |
       +--->|      Audit Correlator       |<---+
            |  +-----------------------+  |
            |  | Trace Correlation     |  |
            |  | Time Normalization    |  |
            |  | Causal Ordering       |  |
            |  | Integrity Verification|  |
            |  +-----------------------+  |
            +-------------+---------------+
                          |
                          v
            +-----------------------------+
            |      Audit Storage          |
            |  +-----------------------+  |
            |  | Time-Series Store     |  |
            |  | (ClickHouse/TimescaleDB) |
            |  +-----------------------+  |
            |  | Merkle Tree Anchoring |  |
            |  +-----------------------+  |
            |  | Search Index          |  |
            |  | (Elasticsearch)       |  |
            |  +-----------------------+  |
            +-----------------------------+
                          |
                          v
            +-----------------------------+
            |      Audit API              |
            |  - Query by trace ID       |
            |  - Query by agent          |
            |  - Query by time range     |
            |  - Verify integrity        |
            +-----------------------------+
```

### Correlation Model

```
+------------------------------------------------------------------+
|                         Trace                                     |
| +--------------------------------------------------------------+ |
| | trace_id: "trace-abc123"                                      | |
| | root_agent: "orchestrator-001"                                | |
| | started_at: 2026-01-15T10:00:00.000Z                         | |
| | ended_at: 2026-01-15T10:05:23.456Z                           | |
| +--------------------------------------------------------------+ |
|                                                                   |
|   +------------------+    +------------------+                    |
|   | Span A           |    | Span B           |                    |
|   | span_id: span-1  |    | span_id: span-2  |                    |
|   | parent: null     |--->| parent: span-1   |                    |
|   | agent: agent-A   |    | agent: agent-B   |                    |
|   +------------------+    +--------+---------+                    |
|                                    |                              |
|                           +--------+--------+                     |
|                           |                 |                     |
|                    +------v------+   +------v------+              |
|                    | Span C      |   | Span D      |              |
|                    | span_id: 3  |   | span_id: 4  |              |
|                    | parent: 2   |   | parent: 2   |              |
|                    | agent: B    |   | agent: C    |              |
|                    +-------------+   +-------------+              |
|                                                                   |
+------------------------------------------------------------------+
```

### Event Schema

```
+------------------------------------------------------------------+
|                       Audit Event                                 |
+------------------------------------------------------------------+
| Identification:                                                   |
|   event_id: UUID                       # Globally unique          |
|   event_type: string                   # Category of event        |
|   timestamp: ISO8601 + monotonic       # When it happened         |
|                                                                   |
| Correlation:                                                      |
|   trace_id: string                     # End-to-end trace         |
|   span_id: string                      # Current operation        |
|   parent_span_id: string?              # Parent operation         |
|   correlation_context: CorrelationCtx  # Signed context           |
|                                                                   |
| Source:                                                           |
|   agent_id: AgentId                    # Which agent              |
|   session_id: string                   # Agent session            |
|   instance_id: string                  # Instance (for replicas)  |
|                                                                   |
| Content:                                                          |
|   action: string                       # What action was taken    |
|   target: string                       # What was acted upon      |
|   outcome: success | failure | blocked # Result                   |
|   details: Record<string, any>         # Action-specific data     |
|   evidence: Evidence?                  # Cryptographic evidence   |
|                                                                   |
| Security:                                                         |
|   severity: info | warning | error     # Security relevance       |
|   guard: string?                       # Guard that evaluated     |
|   policy_decision: Decision?           # Policy evaluation result |
|   delegation_token_id: string?         # If delegated action      |
|                                                                   |
| Integrity:                                                        |
|   sequence: uint64                     # Local sequence number    |
|   prev_hash: bytes32                   # Hash of previous event   |
|   signature: bytes                     # Agent signature          |
+------------------------------------------------------------------+
```

## API Design

### TypeScript Interface

```typescript
import { AgentId, Capability } from './types';

/**
 * Audit event types
 */
export type AuditEventType =
  // Agent lifecycle
  | 'agent.registered'
  | 'agent.started'
  | 'agent.stopped'
  | 'agent.heartbeat'
  // Policy events
  | 'policy.loaded'
  | 'policy.evaluated'
  | 'policy.violation'
  // Resource access
  | 'resource.read'
  | 'resource.write'
  | 'resource.delete'
  | 'resource.execute'
  // Network
  | 'network.connect'
  | 'network.disconnect'
  | 'network.egress'
  // Delegation
  | 'delegation.created'
  | 'delegation.used'
  | 'delegation.revoked'
  | 'delegation.expired'
  // Coordination
  | 'channel.opened'
  | 'channel.closed'
  | 'task.sent'
  | 'task.received'
  | 'task.completed'
  | 'task.failed'
  // Cross-agent
  | 'cross_agent.access'
  | 'cross_agent.denied'
  // Security
  | 'security.alert'
  | 'security.anomaly';

/**
 * Audit event severity
 */
export type AuditSeverity = 'debug' | 'info' | 'warning' | 'error' | 'critical';

/**
 * Event outcome
 */
export type EventOutcome = 'success' | 'failure' | 'blocked' | 'unknown';

/**
 * Correlation context (propagated across agents)
 */
export interface CorrelationContext {
  /** Trace ID (end-to-end) */
  traceId: string;

  /** Current span ID */
  spanId: string;

  /** Parent span ID */
  parentSpanId?: string;

  /** Original requester agent */
  rootAgent: AgentId;

  /** Baggage (key-value pairs) */
  baggage?: Record<string, string>;

  /** Context signature (prevents tampering) */
  signature: string;

  /** Timestamp of context creation */
  createdAt: number;
}

/**
 * Audit event
 */
export interface AuditEvent {
  /** Unique event identifier */
  eventId: string;

  /** Event type */
  eventType: AuditEventType;

  /** High-precision timestamp */
  timestamp: HighPrecisionTimestamp;

  /** Correlation identifiers */
  traceId: string;
  spanId: string;
  parentSpanId?: string;

  /** Full correlation context */
  correlationContext?: CorrelationContext;

  /** Source agent */
  agentId: AgentId;

  /** Agent session */
  sessionId: string;

  /** Agent instance (for replicas) */
  instanceId?: string;

  /** Action taken */
  action: string;

  /** Target of action */
  target: string;

  /** Outcome */
  outcome: EventOutcome;

  /** Event details */
  details: Record<string, unknown>;

  /** Cryptographic evidence */
  evidence?: EventEvidence;

  /** Severity */
  severity: AuditSeverity;

  /** Guard that evaluated (if applicable) */
  guard?: string;

  /** Policy decision (if applicable) */
  policyDecision?: PolicyDecision;

  /** Delegation token ID (if delegated action) */
  delegationTokenId?: string;

  /** Local sequence number */
  sequence: number;

  /** Hash of previous event */
  prevHash: string;

  /** Agent signature over event */
  signature: string;
}

/**
 * High-precision timestamp
 */
export interface HighPrecisionTimestamp {
  /** Unix milliseconds */
  epochMs: number;

  /** Monotonic counter for same-millisecond ordering */
  monotonic: number;

  /** Clock source */
  source: 'system' | 'ntp' | 'gps' | 'hybrid';

  /** Estimated accuracy in microseconds */
  accuracyUs?: number;
}

/**
 * Event evidence
 */
export interface EventEvidence {
  /** Evidence type */
  type: 'content_hash' | 'merkle_proof' | 'attestation' | 'receipt';

  /** Evidence data */
  data: Uint8Array;

  /** Algorithm used */
  algorithm: string;
}

/**
 * Policy decision record
 */
export interface PolicyDecision {
  /** Whether allowed */
  allowed: boolean;

  /** Reason */
  reason?: string;

  /** Guard that made decision */
  guard: string;

  /** Severity of violation (if any) */
  severity?: AuditSeverity;

  /** Policy hash */
  policyHash: string;
}

/**
 * Trace summary
 */
export interface TraceSummary {
  /** Trace ID */
  traceId: string;

  /** Root agent that started trace */
  rootAgent: AgentId;

  /** When trace started */
  startedAt: Date;

  /** When trace ended (if complete) */
  endedAt?: Date;

  /** Duration in milliseconds */
  durationMs?: number;

  /** Number of spans */
  spanCount: number;

  /** Agents involved */
  agents: AgentId[];

  /** Number of events */
  eventCount: number;

  /** Number of violations */
  violationCount: number;

  /** Overall outcome */
  outcome: EventOutcome;

  /** Trace status */
  status: 'active' | 'completed' | 'failed' | 'timeout';
}

/**
 * Span (unit of work within a trace)
 */
export interface Span {
  /** Span ID */
  spanId: string;

  /** Parent span ID */
  parentSpanId?: string;

  /** Trace ID */
  traceId: string;

  /** Agent that owns this span */
  agentId: AgentId;

  /** Operation name */
  operationName: string;

  /** Start time */
  startTime: HighPrecisionTimestamp;

  /** End time */
  endTime?: HighPrecisionTimestamp;

  /** Duration in milliseconds */
  durationMs?: number;

  /** Span status */
  status: 'active' | 'completed' | 'failed';

  /** Tags */
  tags: Record<string, string>;

  /** Events within this span */
  events: AuditEvent[];

  /** Child spans */
  children: Span[];
}

/**
 * Audit logger (per-agent)
 */
export class AuditLogger {
  private agentId: AgentId;
  private sessionId: string;
  private instanceId: string;
  private sequence: number = 0;
  private prevHash: string = '0'.repeat(64);
  private buffer: AuditEvent[] = [];
  private signingKey: SigningKey;
  private correlator: AuditCorrelator;
  private config: AuditLoggerConfig;

  constructor(config: AuditLoggerConfig) {
    this.agentId = config.agentId;
    this.sessionId = config.sessionId;
    this.instanceId = config.instanceId ?? 'default';
    this.signingKey = config.signingKey;
    this.correlator = config.correlator;
    this.config = config;
  }

  /**
   * Create a new correlation context (start of trace)
   */
  startTrace(operationName: string): CorrelationContext {
    const traceId = this.generateTraceId();
    const spanId = this.generateSpanId();

    const context: CorrelationContext = {
      traceId,
      spanId,
      rootAgent: this.agentId,
      createdAt: Date.now(),
      signature: '', // Will be signed
    };

    context.signature = this.signContext(context);

    // Log trace start
    this.log({
      eventType: 'agent.started',
      action: 'start_trace',
      target: operationName,
      outcome: 'success',
      details: { operationName },
      correlationContext: context,
    });

    return context;
  }

  /**
   * Create a child span from existing context
   */
  createChildSpan(
    parentContext: CorrelationContext,
    operationName: string
  ): CorrelationContext {
    // Verify parent context signature
    if (!this.verifyContext(parentContext)) {
      throw new Error('Invalid correlation context signature');
    }

    const childContext: CorrelationContext = {
      traceId: parentContext.traceId,
      spanId: this.generateSpanId(),
      parentSpanId: parentContext.spanId,
      rootAgent: parentContext.rootAgent,
      baggage: parentContext.baggage,
      createdAt: Date.now(),
      signature: '',
    };

    childContext.signature = this.signContext(childContext);

    return childContext;
  }

  /**
   * Log an audit event
   */
  async log(params: AuditLogParams): Promise<AuditEvent> {
    const timestamp = this.getHighPrecisionTimestamp();
    const sequence = this.sequence++;

    const event: AuditEvent = {
      eventId: this.generateEventId(),
      eventType: params.eventType,
      timestamp,
      traceId: params.correlationContext?.traceId ?? this.generateTraceId(),
      spanId: params.correlationContext?.spanId ?? this.generateSpanId(),
      parentSpanId: params.correlationContext?.parentSpanId,
      correlationContext: params.correlationContext,
      agentId: this.agentId,
      sessionId: this.sessionId,
      instanceId: this.instanceId,
      action: params.action,
      target: params.target,
      outcome: params.outcome,
      details: params.details ?? {},
      evidence: params.evidence,
      severity: params.severity ?? 'info',
      guard: params.guard,
      policyDecision: params.policyDecision,
      delegationTokenId: params.delegationTokenId,
      sequence,
      prevHash: this.prevHash,
      signature: '',
    };

    // Sign event
    event.signature = await this.signEvent(event);

    // Update hash chain
    this.prevHash = this.hashEvent(event);

    // Buffer for batching
    this.buffer.push(event);

    // Flush if buffer is full or high severity
    if (
      this.buffer.length >= this.config.bufferSize ||
      event.severity === 'error' ||
      event.severity === 'critical'
    ) {
      await this.flush();
    }

    return event;
  }

  /**
   * Log a policy evaluation
   */
  async logPolicyEvaluation(
    action: string,
    target: string,
    decision: PolicyDecision,
    context?: CorrelationContext
  ): Promise<AuditEvent> {
    return this.log({
      eventType: decision.allowed ? 'policy.evaluated' : 'policy.violation',
      action,
      target,
      outcome: decision.allowed ? 'success' : 'blocked',
      details: {
        allowed: decision.allowed,
        reason: decision.reason,
      },
      severity: decision.allowed ? 'info' : (decision.severity ?? 'warning'),
      guard: decision.guard,
      policyDecision: decision,
      correlationContext: context,
    });
  }

  /**
   * Log cross-agent access
   */
  async logCrossAgentAccess(
    action: string,
    targetAgent: AgentId,
    resource: string,
    outcome: EventOutcome,
    delegationTokenId?: string,
    context?: CorrelationContext
  ): Promise<AuditEvent> {
    return this.log({
      eventType: outcome === 'success' ? 'cross_agent.access' : 'cross_agent.denied',
      action,
      target: `${targetAgent}:${resource}`,
      outcome,
      details: {
        targetAgent,
        resource,
        hasDelegation: !!delegationTokenId,
      },
      severity: outcome === 'success' ? 'info' : 'warning',
      delegationTokenId,
      correlationContext: context,
    });
  }

  /**
   * Log task coordination event
   */
  async logTask(
    eventType: 'task.sent' | 'task.received' | 'task.completed' | 'task.failed',
    taskId: string,
    taskType: string,
    targetAgent?: AgentId,
    context?: CorrelationContext,
    error?: string
  ): Promise<AuditEvent> {
    return this.log({
      eventType,
      action: taskType,
      target: targetAgent ?? taskId,
      outcome: eventType === 'task.failed' ? 'failure' : 'success',
      details: {
        taskId,
        taskType,
        targetAgent,
        error,
      },
      severity: eventType === 'task.failed' ? 'error' : 'info',
      correlationContext: context,
    });
  }

  /**
   * Flush buffered events to correlator
   */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const events = this.buffer.splice(0, this.buffer.length);
    await this.correlator.ingest(events);
  }

  /**
   * Close the logger
   */
  async close(): Promise<void> {
    await this.flush();
  }

  private getHighPrecisionTimestamp(): HighPrecisionTimestamp {
    const now = Date.now();
    return {
      epochMs: now,
      monotonic: this.sequence,
      source: 'system',
    };
  }

  private generateEventId(): string {
    return `evt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  private generateTraceId(): string {
    // 128-bit trace ID (W3C Trace Context compatible)
    // Format: 32 lowercase hex characters
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private generateSpanId(): string {
    // 64-bit span ID (W3C Trace Context compatible)
    // Format: 16 lowercase hex characters
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Create W3C Trace Context headers for HTTP propagation
   * @see https://www.w3.org/TR/trace-context/
   */
  createTraceHeaders(context: CorrelationContext): Record<string, string> {
    // traceparent format: {version}-{trace-id}-{parent-id}-{trace-flags}
    // version: 00 (current)
    // trace-id: 32 hex chars (128-bit)
    // parent-id: 16 hex chars (64-bit span ID)
    // trace-flags: 01 (sampled)
    const traceparent = `00-${context.traceId}-${context.spanId}-01`;

    const headers: Record<string, string> = {
      'traceparent': traceparent,
    };

    // tracestate for vendor-specific data
    if (context.baggage && Object.keys(context.baggage).length > 0) {
      const baggageItems = Object.entries(context.baggage)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
        .join(',');
      headers['baggage'] = baggageItems;
    }

    // Custom header for signed context (Clawdstrike-specific)
    headers['x-clawdstrike-context'] = base64.encode(
      new TextEncoder().encode(JSON.stringify({
        rootAgent: context.rootAgent,
        signature: context.signature,
        createdAt: context.createdAt,
      }))
    );

    return headers;
  }

  /**
   * Parse W3C Trace Context headers from incoming HTTP request
   */
  parseTraceHeaders(headers: Record<string, string>): CorrelationContext | null {
    const traceparent = headers['traceparent'];
    if (!traceparent) return null;

    // Parse traceparent: 00-{trace-id}-{parent-id}-{flags}
    const parts = traceparent.split('-');
    if (parts.length !== 4 || parts[0] !== '00') return null;

    const traceId = parts[1];
    const parentSpanId = parts[2];

    if (traceId.length !== 32 || parentSpanId.length !== 16) return null;

    // Parse baggage
    const baggage: Record<string, string> = {};
    if (headers['baggage']) {
      headers['baggage'].split(',').forEach(item => {
        const [key, value] = item.split('=');
        if (key && value) {
          baggage[decodeURIComponent(key.trim())] = decodeURIComponent(value.trim());
        }
      });
    }

    // Parse Clawdstrike-specific context
    let rootAgent = this.agentId;
    let signature = '';
    let createdAt = Date.now();

    if (headers['x-clawdstrike-context']) {
      try {
        const decoded = JSON.parse(
          new TextDecoder().decode(base64.decode(headers['x-clawdstrike-context']))
        );
        rootAgent = decoded.rootAgent;
        signature = decoded.signature;
        createdAt = decoded.createdAt;
      } catch {}
    }

    return {
      traceId,
      spanId: this.generateSpanId(), // New span for this agent
      parentSpanId,
      rootAgent,
      baggage,
      signature,
      createdAt,
    };
  }

  private async signEvent(event: AuditEvent): Promise<string> {
    const data = this.canonicalizeEvent(event);
    const signature = await this.signingKey.sign(data);
    return base64.encode(signature);
  }

  private signContext(context: CorrelationContext): string {
    const data = this.canonicalizeContext(context);
    // Synchronous for convenience - in production might be async
    return base64.encode(this.signingKey.signSync(data));
  }

  private verifyContext(context: CorrelationContext): boolean {
    const expectedSignature = context.signature;
    const tempContext = { ...context, signature: '' };
    const data = this.canonicalizeContext(tempContext);

    // Would verify against root agent's public key
    return true; // Placeholder
  }

  private canonicalizeEvent(event: AuditEvent): Uint8Array {
    const canonical = {
      eventId: event.eventId,
      eventType: event.eventType,
      timestamp: event.timestamp,
      traceId: event.traceId,
      spanId: event.spanId,
      parentSpanId: event.parentSpanId,
      agentId: event.agentId,
      sessionId: event.sessionId,
      action: event.action,
      target: event.target,
      outcome: event.outcome,
      sequence: event.sequence,
      prevHash: event.prevHash,
    };
    return new TextEncoder().encode(JSON.stringify(canonical));
  }

  private canonicalizeContext(context: CorrelationContext): Uint8Array {
    const canonical = {
      traceId: context.traceId,
      spanId: context.spanId,
      parentSpanId: context.parentSpanId,
      rootAgent: context.rootAgent,
      createdAt: context.createdAt,
    };
    return new TextEncoder().encode(JSON.stringify(canonical));
  }

  private hashEvent(event: AuditEvent): string {
    const data = this.canonicalizeEvent(event);
    const hash = sha256(data);
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

/**
 * Audit log parameters
 */
export interface AuditLogParams {
  eventType: AuditEventType;
  action: string;
  target: string;
  outcome: EventOutcome;
  details?: Record<string, unknown>;
  evidence?: EventEvidence;
  severity?: AuditSeverity;
  guard?: string;
  policyDecision?: PolicyDecision;
  delegationTokenId?: string;
  correlationContext?: CorrelationContext;
}

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
  agentId: AgentId;
  sessionId: string;
  instanceId?: string;
  signingKey: SigningKey;
  correlator: AuditCorrelator;
  bufferSize?: number;
}

/**
 * Audit correlator (central service)
 */
export class AuditCorrelator {
  private storage: AuditStorage;
  private searchIndex: SearchIndex;
  private integrityVerifier: IntegrityVerifier;
  private config: CorrelatorConfig;

  constructor(config: CorrelatorConfig) {
    this.storage = config.storage;
    this.searchIndex = config.searchIndex;
    this.integrityVerifier = config.integrityVerifier;
    this.config = config;
  }

  /**
   * Ingest events from an agent
   */
  async ingest(events: AuditEvent[]): Promise<void> {
    for (const event of events) {
      // Verify event signature
      if (!await this.verifyEventSignature(event)) {
        console.error(`Invalid signature for event ${event.eventId}`);
        continue;
      }

      // Verify hash chain
      if (!await this.verifyHashChain(event)) {
        console.error(`Hash chain broken for event ${event.eventId}`);
        // Still store but mark as suspicious
        event.details = { ...event.details, _suspicious: true };
      }

      // Store event
      await this.storage.store(event);

      // Index for search
      await this.searchIndex.index(event);

      // Update trace summary
      await this.updateTraceSummary(event);
    }
  }

  /**
   * Query events by trace ID
   */
  async queryByTrace(traceId: string): Promise<AuditEvent[]> {
    return this.storage.queryByTrace(traceId);
  }

  /**
   * Query events by agent
   */
  async queryByAgent(
    agentId: AgentId,
    options?: QueryOptions
  ): Promise<AuditEvent[]> {
    return this.storage.queryByAgent(agentId, options);
  }

  /**
   * Query events by time range
   */
  async queryByTimeRange(
    start: Date,
    end: Date,
    options?: QueryOptions
  ): Promise<AuditEvent[]> {
    return this.storage.queryByTimeRange(start, end, options);
  }

  /**
   * Get trace summary
   */
  async getTraceSummary(traceId: string): Promise<TraceSummary | null> {
    return this.storage.getTraceSummary(traceId);
  }

  /**
   * Build full trace tree
   */
  async buildTraceTree(traceId: string): Promise<Span | null> {
    const events = await this.queryByTrace(traceId);
    if (events.length === 0) return null;

    return this.reconstructTree(events);
  }

  /**
   * Verify audit trail integrity for a trace
   */
  async verifyTraceIntegrity(traceId: string): Promise<IntegrityResult> {
    const events = await this.queryByTrace(traceId);
    return this.integrityVerifier.verifyTrace(events);
  }

  /**
   * Search events with full-text query
   */
  async search(query: string, options?: SearchOptions): Promise<AuditEvent[]> {
    return this.searchIndex.search(query, options);
  }

  /**
   * Get violations for a time period
   */
  async getViolations(
    start: Date,
    end: Date,
    options?: QueryOptions
  ): Promise<AuditEvent[]> {
    return this.storage.queryByTimeRange(start, end, {
      ...options,
      filter: { eventType: 'policy.violation' },
    });
  }

  /**
   * Export audit trail for compliance
   */
  async exportAuditTrail(
    traceId: string,
    format: 'json' | 'csv' | 'pdf'
  ): Promise<Uint8Array> {
    const events = await this.queryByTrace(traceId);
    const summary = await this.getTraceSummary(traceId);
    const integrity = await this.verifyTraceIntegrity(traceId);

    // Would generate formatted export
    return new TextEncoder().encode(JSON.stringify({
      summary,
      events,
      integrity,
      exportedAt: new Date().toISOString(),
    }));
  }

  private async verifyEventSignature(event: AuditEvent): Promise<boolean> {
    // Would verify against agent's public key from identity registry
    return true; // Placeholder
  }

  private async verifyHashChain(event: AuditEvent): Promise<boolean> {
    // Would verify prevHash matches actual previous event
    return true; // Placeholder
  }

  private async updateTraceSummary(event: AuditEvent): Promise<void> {
    // Would update trace summary in storage
  }

  private reconstructTree(events: AuditEvent[]): Span {
    // Build span tree from flat event list
    const spans = new Map<string, Span>();
    const roots: Span[] = [];

    // First pass: create spans
    for (const event of events) {
      if (!spans.has(event.spanId)) {
        spans.set(event.spanId, {
          spanId: event.spanId,
          parentSpanId: event.parentSpanId,
          traceId: event.traceId,
          agentId: event.agentId,
          operationName: event.action,
          startTime: event.timestamp,
          status: 'completed',
          tags: {},
          events: [],
          children: [],
        });
      }
      spans.get(event.spanId)!.events.push(event);
    }

    // Second pass: build tree
    for (const span of spans.values()) {
      if (span.parentSpanId && spans.has(span.parentSpanId)) {
        spans.get(span.parentSpanId)!.children.push(span);
      } else {
        roots.push(span);
      }
    }

    // Return root (or synthetic root if multiple)
    if (roots.length === 1) {
      return roots[0];
    }

    return {
      spanId: 'synthetic-root',
      traceId: events[0].traceId,
      agentId: events[0].agentId,
      operationName: 'trace-root',
      startTime: events[0].timestamp,
      status: 'completed',
      tags: {},
      events: [],
      children: roots,
    };
  }
}

/**
 * Query options
 */
export interface QueryOptions {
  limit?: number;
  offset?: number;
  orderBy?: 'timestamp' | 'sequence';
  orderDir?: 'asc' | 'desc';
  filter?: Record<string, unknown>;
}

/**
 * Search options
 */
export interface SearchOptions extends QueryOptions {
  fields?: string[];
  fuzzy?: boolean;
}

/**
 * Integrity verification result
 */
export interface IntegrityResult {
  valid: boolean;
  issues: IntegrityIssue[];
  verifiedEvents: number;
  totalEvents: number;
}

/**
 * Integrity issue
 */
export interface IntegrityIssue {
  eventId: string;
  type: 'signature_invalid' | 'hash_chain_broken' | 'timestamp_anomaly' | 'sequence_gap';
  description: string;
  severity: AuditSeverity;
}

/**
 * Audit storage interface
 */
export interface AuditStorage {
  store(event: AuditEvent): Promise<void>;
  queryByTrace(traceId: string): Promise<AuditEvent[]>;
  queryByAgent(agentId: AgentId, options?: QueryOptions): Promise<AuditEvent[]>;
  queryByTimeRange(start: Date, end: Date, options?: QueryOptions): Promise<AuditEvent[]>;
  getTraceSummary(traceId: string): Promise<TraceSummary | null>;
}

/**
 * Search index interface
 */
export interface SearchIndex {
  index(event: AuditEvent): Promise<void>;
  search(query: string, options?: SearchOptions): Promise<AuditEvent[]>;
}

/**
 * Integrity verifier interface
 */
export interface IntegrityVerifier {
  verifyTrace(events: AuditEvent[]): Promise<IntegrityResult>;
  verifyEvent(event: AuditEvent): Promise<boolean>;
}

/**
 * Correlator configuration
 */
export interface CorrelatorConfig {
  storage: AuditStorage;
  searchIndex: SearchIndex;
  integrityVerifier: IntegrityVerifier;
}
```

### Rust Interface

```rust
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Audit event types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Agent lifecycle
    AgentRegistered,
    AgentStarted,
    AgentStopped,
    AgentHeartbeat,
    // Policy events
    PolicyLoaded,
    PolicyEvaluated,
    PolicyViolation,
    // Resource access
    ResourceRead,
    ResourceWrite,
    ResourceDelete,
    ResourceExecute,
    // Network
    NetworkConnect,
    NetworkDisconnect,
    NetworkEgress,
    // Delegation
    DelegationCreated,
    DelegationUsed,
    DelegationRevoked,
    DelegationExpired,
    // Coordination
    ChannelOpened,
    ChannelClosed,
    TaskSent,
    TaskReceived,
    TaskCompleted,
    TaskFailed,
    // Cross-agent
    CrossAgentAccess,
    CrossAgentDenied,
    // Security
    SecurityAlert,
    SecurityAnomaly,
}

/// Audit severity
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Event outcome
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventOutcome {
    Success,
    Failure,
    Blocked,
    Unknown,
}

/// High precision timestamp
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HighPrecisionTimestamp {
    pub epoch_ms: i64,
    pub monotonic: u64,
    pub source: ClockSource,
    pub accuracy_us: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClockSource {
    System,
    Ntp,
    Gps,
    Hybrid,
}

/// Correlation context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelationContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub root_agent: AgentId,
    pub baggage: HashMap<String, String>,
    pub signature: String,
    pub created_at: i64,
}

/// Policy decision
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub guard: String,
    pub severity: Option<AuditSeverity>,
    pub policy_hash: String,
}

/// Event evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEvidence {
    pub evidence_type: EvidenceType,
    pub data: Vec<u8>,
    pub algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    ContentHash,
    MerkleProof,
    Attestation,
    Receipt,
}

/// Audit event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_type: AuditEventType,
    pub timestamp: HighPrecisionTimestamp,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub correlation_context: Option<CorrelationContext>,
    pub agent_id: AgentId,
    pub session_id: String,
    pub instance_id: Option<String>,
    pub action: String,
    pub target: String,
    pub outcome: EventOutcome,
    pub details: serde_json::Value,
    pub evidence: Option<EventEvidence>,
    pub severity: AuditSeverity,
    pub guard: Option<String>,
    pub policy_decision: Option<PolicyDecision>,
    pub delegation_token_id: Option<String>,
    pub sequence: u64,
    pub prev_hash: String,
    pub signature: String,
}

/// Trace summary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceSummary {
    pub trace_id: String,
    pub root_agent: AgentId,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub span_count: u32,
    pub agents: Vec<AgentId>,
    pub event_count: u32,
    pub violation_count: u32,
    pub outcome: EventOutcome,
    pub status: TraceStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceStatus {
    Active,
    Completed,
    Failed,
    Timeout,
}

/// Span
#[derive(Clone, Debug)]
pub struct Span {
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub trace_id: String,
    pub agent_id: AgentId,
    pub operation_name: String,
    pub start_time: HighPrecisionTimestamp,
    pub end_time: Option<HighPrecisionTimestamp>,
    pub duration_ms: Option<i64>,
    pub status: SpanStatus,
    pub tags: HashMap<String, String>,
    pub events: Vec<AuditEvent>,
    pub children: Vec<Span>,
}

#[derive(Clone, Debug)]
pub enum SpanStatus {
    Active,
    Completed,
    Failed,
}

/// Audit logger
pub struct AuditLogger {
    agent_id: AgentId,
    session_id: String,
    instance_id: String,
    sequence: RwLock<u64>,
    prev_hash: RwLock<String>,
    buffer: RwLock<Vec<AuditEvent>>,
    signing_key: Arc<dyn SigningKey>,
    correlator: Arc<AuditCorrelator>,
    config: AuditLoggerConfig,
}

impl AuditLogger {
    pub fn new(config: AuditLoggerConfig) -> Self {
        Self {
            agent_id: config.agent_id.clone(),
            session_id: config.session_id.clone(),
            instance_id: config.instance_id.clone().unwrap_or_else(|| "default".to_string()),
            sequence: RwLock::new(0),
            prev_hash: RwLock::new("0".repeat(64)),
            buffer: RwLock::new(Vec::new()),
            signing_key: config.signing_key.clone(),
            correlator: config.correlator.clone(),
            config,
        }
    }

    /// Start a new trace
    pub async fn start_trace(&self, operation_name: &str) -> CorrelationContext {
        let trace_id = self.generate_trace_id();
        let span_id = self.generate_span_id();

        let mut context = CorrelationContext {
            trace_id: trace_id.clone(),
            span_id: span_id.clone(),
            parent_span_id: None,
            root_agent: self.agent_id.clone(),
            baggage: HashMap::new(),
            signature: String::new(),
            created_at: Utc::now().timestamp_millis(),
        };

        context.signature = self.sign_context(&context).await;

        // Log trace start
        self.log(AuditLogParams {
            event_type: AuditEventType::AgentStarted,
            action: "start_trace".to_string(),
            target: operation_name.to_string(),
            outcome: EventOutcome::Success,
            details: serde_json::json!({ "operationName": operation_name }),
            correlation_context: Some(context.clone()),
            ..Default::default()
        }).await.ok();

        context
    }

    /// Create a child span
    pub async fn create_child_span(
        &self,
        parent: &CorrelationContext,
        operation_name: &str,
    ) -> Result<CorrelationContext, Error> {
        if !self.verify_context(parent).await? {
            return Err(Error::InvalidContext);
        }

        let mut child = CorrelationContext {
            trace_id: parent.trace_id.clone(),
            span_id: self.generate_span_id(),
            parent_span_id: Some(parent.span_id.clone()),
            root_agent: parent.root_agent.clone(),
            baggage: parent.baggage.clone(),
            signature: String::new(),
            created_at: Utc::now().timestamp_millis(),
        };

        child.signature = self.sign_context(&child).await;

        Ok(child)
    }

    /// Log an audit event
    pub async fn log(&self, params: AuditLogParams) -> Result<AuditEvent, Error> {
        let timestamp = self.get_high_precision_timestamp().await;
        let sequence = {
            let mut seq = self.sequence.write().await;
            let current = *seq;
            *seq += 1;
            current
        };

        let prev_hash = self.prev_hash.read().await.clone();

        let mut event = AuditEvent {
            event_id: self.generate_event_id(),
            event_type: params.event_type,
            timestamp,
            trace_id: params.correlation_context.as_ref()
                .map(|c| c.trace_id.clone())
                .unwrap_or_else(|| self.generate_trace_id()),
            span_id: params.correlation_context.as_ref()
                .map(|c| c.span_id.clone())
                .unwrap_or_else(|| self.generate_span_id()),
            parent_span_id: params.correlation_context.as_ref()
                .and_then(|c| c.parent_span_id.clone()),
            correlation_context: params.correlation_context,
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            instance_id: Some(self.instance_id.clone()),
            action: params.action,
            target: params.target,
            outcome: params.outcome,
            details: params.details,
            evidence: params.evidence,
            severity: params.severity,
            guard: params.guard,
            policy_decision: params.policy_decision,
            delegation_token_id: params.delegation_token_id,
            sequence,
            prev_hash,
            signature: String::new(),
        };

        // Sign event
        event.signature = self.sign_event(&event).await?;

        // Update hash chain
        let new_hash = self.hash_event(&event);
        *self.prev_hash.write().await = new_hash;

        // Buffer
        {
            let mut buffer = self.buffer.write().await;
            buffer.push(event.clone());

            // Flush if needed
            if buffer.len() >= self.config.buffer_size
                || event.severity >= AuditSeverity::Error
            {
                let events = std::mem::take(&mut *buffer);
                drop(buffer);
                self.correlator.ingest(events).await?;
            }
        }

        Ok(event)
    }

    /// Log a policy evaluation
    pub async fn log_policy_evaluation(
        &self,
        action: &str,
        target: &str,
        decision: PolicyDecision,
        context: Option<CorrelationContext>,
    ) -> Result<AuditEvent, Error> {
        self.log(AuditLogParams {
            event_type: if decision.allowed {
                AuditEventType::PolicyEvaluated
            } else {
                AuditEventType::PolicyViolation
            },
            action: action.to_string(),
            target: target.to_string(),
            outcome: if decision.allowed {
                EventOutcome::Success
            } else {
                EventOutcome::Blocked
            },
            details: serde_json::json!({
                "allowed": decision.allowed,
                "reason": decision.reason,
            }),
            severity: if decision.allowed {
                AuditSeverity::Info
            } else {
                decision.severity.clone().unwrap_or(AuditSeverity::Warning)
            },
            guard: Some(decision.guard.clone()),
            policy_decision: Some(decision),
            correlation_context: context,
            ..Default::default()
        }).await
    }

    /// Flush buffer
    pub async fn flush(&self) -> Result<(), Error> {
        let events = {
            let mut buffer = self.buffer.write().await;
            std::mem::take(&mut *buffer)
        };

        if !events.is_empty() {
            self.correlator.ingest(events).await?;
        }

        Ok(())
    }

    async fn get_high_precision_timestamp(&self) -> HighPrecisionTimestamp {
        let now = Utc::now();
        let seq = *self.sequence.read().await;
        HighPrecisionTimestamp {
            epoch_ms: now.timestamp_millis(),
            monotonic: seq,
            source: ClockSource::System,
            accuracy_us: None,
        }
    }

    fn generate_event_id(&self) -> String {
        format!("evt-{}-{}", Utc::now().timestamp_millis(), uuid::Uuid::new_v4())
    }

    fn generate_trace_id(&self) -> String {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).unwrap();
        hex::encode(bytes)
    }

    fn generate_span_id(&self) -> String {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        hex::encode(bytes)
    }

    async fn sign_event(&self, event: &AuditEvent) -> Result<String, Error> {
        let canonical = self.canonicalize_event(event);
        let signature = self.signing_key.sign(&canonical).await?;
        Ok(base64::encode(&signature))
    }

    async fn sign_context(&self, context: &CorrelationContext) -> String {
        let canonical = self.canonicalize_context(context);
        let signature = self.signing_key.sign(&canonical).await.unwrap_or_default();
        base64::encode(&signature)
    }

    async fn verify_context(&self, context: &CorrelationContext) -> Result<bool, Error> {
        // Would verify against root agent's public key
        Ok(true)
    }

    fn canonicalize_event(&self, event: &AuditEvent) -> Vec<u8> {
        serde_json::json!({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "parent_span_id": event.parent_span_id,
            "agent_id": event.agent_id,
            "session_id": event.session_id,
            "action": event.action,
            "target": event.target,
            "outcome": event.outcome,
            "sequence": event.sequence,
            "prev_hash": event.prev_hash,
        }).to_string().into_bytes()
    }

    fn canonicalize_context(&self, context: &CorrelationContext) -> Vec<u8> {
        serde_json::json!({
            "trace_id": context.trace_id,
            "span_id": context.span_id,
            "parent_span_id": context.parent_span_id,
            "root_agent": context.root_agent,
            "created_at": context.created_at,
        }).to_string().into_bytes()
    }

    fn hash_event(&self, event: &AuditEvent) -> String {
        use sha2::{Sha256, Digest};
        let canonical = self.canonicalize_event(event);
        let hash = Sha256::digest(&canonical);
        hex::encode(hash)
    }
}

/// Audit log parameters
#[derive(Clone, Debug, Default)]
pub struct AuditLogParams {
    pub event_type: AuditEventType,
    pub action: String,
    pub target: String,
    pub outcome: EventOutcome,
    pub details: serde_json::Value,
    pub evidence: Option<EventEvidence>,
    pub severity: AuditSeverity,
    pub guard: Option<String>,
    pub policy_decision: Option<PolicyDecision>,
    pub delegation_token_id: Option<String>,
    pub correlation_context: Option<CorrelationContext>,
}

impl Default for AuditEventType {
    fn default() -> Self {
        AuditEventType::AgentHeartbeat
    }
}

impl Default for EventOutcome {
    fn default() -> Self {
        EventOutcome::Unknown
    }
}

impl Default for AuditSeverity {
    fn default() -> Self {
        AuditSeverity::Info
    }
}

/// Audit logger config
#[derive(Clone)]
pub struct AuditLoggerConfig {
    pub agent_id: AgentId,
    pub session_id: String,
    pub instance_id: Option<String>,
    pub signing_key: Arc<dyn SigningKey>,
    pub correlator: Arc<AuditCorrelator>,
    pub buffer_size: usize,
}

/// Audit correlator
pub struct AuditCorrelator {
    storage: Arc<dyn AuditStorage>,
    search_index: Arc<dyn SearchIndex>,
    integrity_verifier: Arc<dyn IntegrityVerifier>,
}

impl AuditCorrelator {
    pub fn new(
        storage: Arc<dyn AuditStorage>,
        search_index: Arc<dyn SearchIndex>,
        integrity_verifier: Arc<dyn IntegrityVerifier>,
    ) -> Self {
        Self {
            storage,
            search_index,
            integrity_verifier,
        }
    }

    /// Ingest events
    pub async fn ingest(&self, events: Vec<AuditEvent>) -> Result<(), Error> {
        for event in events {
            // Verify signature
            // Verify hash chain
            // Store
            self.storage.store(&event).await?;
            // Index
            self.search_index.index(&event).await?;
        }
        Ok(())
    }

    /// Query by trace
    pub async fn query_by_trace(&self, trace_id: &str) -> Result<Vec<AuditEvent>, Error> {
        self.storage.query_by_trace(trace_id).await
    }

    /// Query by agent
    pub async fn query_by_agent(
        &self,
        agent_id: &AgentId,
        options: Option<QueryOptions>,
    ) -> Result<Vec<AuditEvent>, Error> {
        self.storage.query_by_agent(agent_id, options).await
    }

    /// Get trace summary
    pub async fn get_trace_summary(&self, trace_id: &str) -> Result<Option<TraceSummary>, Error> {
        self.storage.get_trace_summary(trace_id).await
    }

    /// Build trace tree
    pub async fn build_trace_tree(&self, trace_id: &str) -> Result<Option<Span>, Error> {
        let events = self.query_by_trace(trace_id).await?;
        if events.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.reconstruct_tree(events)))
    }

    /// Verify trace integrity
    pub async fn verify_trace_integrity(&self, trace_id: &str) -> Result<IntegrityResult, Error> {
        let events = self.query_by_trace(trace_id).await?;
        self.integrity_verifier.verify_trace(&events).await
    }

    fn reconstruct_tree(&self, events: Vec<AuditEvent>) -> Span {
        // Build span tree from events
        // Similar to TypeScript implementation
        todo!()
    }
}

/// Query options
#[derive(Clone, Debug, Default)]
pub struct QueryOptions {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub order_by: Option<String>,
    pub order_dir: Option<OrderDir>,
    pub filter: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub enum OrderDir {
    Asc,
    Desc,
}

/// Integrity result
#[derive(Clone, Debug)]
pub struct IntegrityResult {
    pub valid: bool,
    pub issues: Vec<IntegrityIssue>,
    pub verified_events: usize,
    pub total_events: usize,
}

/// Integrity issue
#[derive(Clone, Debug)]
pub struct IntegrityIssue {
    pub event_id: String,
    pub issue_type: IntegrityIssueType,
    pub description: String,
    pub severity: AuditSeverity,
}

#[derive(Clone, Debug)]
pub enum IntegrityIssueType {
    SignatureInvalid,
    HashChainBroken,
    TimestampAnomaly,
    SequenceGap,
}

/// Audit storage trait
#[async_trait]
pub trait AuditStorage: Send + Sync {
    async fn store(&self, event: &AuditEvent) -> Result<(), Error>;
    async fn query_by_trace(&self, trace_id: &str) -> Result<Vec<AuditEvent>, Error>;
    async fn query_by_agent(&self, agent_id: &AgentId, options: Option<QueryOptions>) -> Result<Vec<AuditEvent>, Error>;
    async fn query_by_time_range(&self, start: DateTime<Utc>, end: DateTime<Utc>, options: Option<QueryOptions>) -> Result<Vec<AuditEvent>, Error>;
    async fn get_trace_summary(&self, trace_id: &str) -> Result<Option<TraceSummary>, Error>;
}

/// Search index trait
#[async_trait]
pub trait SearchIndex: Send + Sync {
    async fn index(&self, event: &AuditEvent) -> Result<(), Error>;
    async fn search(&self, query: &str, options: Option<QueryOptions>) -> Result<Vec<AuditEvent>, Error>;
}

/// Integrity verifier trait
#[async_trait]
pub trait IntegrityVerifier: Send + Sync {
    async fn verify_trace(&self, events: &[AuditEvent]) -> Result<IntegrityResult, Error>;
    async fn verify_event(&self, event: &AuditEvent) -> Result<bool, Error>;
}

/// Signing key trait
#[async_trait]
pub trait SigningKey: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid correlation context")]
    InvalidContext,
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Signing error: {0}")]
    Signing(String),
}
```

## Cryptographic Primitives

### Event Signing

**Ed25519**:
- 64-byte signatures
- Fast signing and verification
- Agent private key held securely

### Hash Chaining

```
prev_hash[n] = SHA-256(canonical(event[n-1]))
```

Each event includes hash of previous event, creating tamper-evident chain.

### Merkle Tree Anchoring

Periodic checkpoints:
```
checkpoint = {
    root: Merkle_Root(events[checkpoint_start..checkpoint_end]),
    timestamp: timestamp,
    signature: sign(root || timestamp)
}
```

### Context Signing

Correlation contexts are signed by root agent:
```
signature = Ed25519_Sign(
    private_key,
    canonical({trace_id, span_id, parent_span_id, root_agent, created_at})
)
```

## Attack Scenarios and Mitigations

### Attack 1: Log Deletion

**Attack**: Compromised agent deletes incriminating logs

**Mitigation**:
- Immediate forwarding to central correlator
- Hash chain makes deletion detectable
- Merkle tree anchoring to external timestamping

### Attack 2: Correlation ID Spoofing

**Attack**: Malicious agent uses another agent's trace ID

**Mitigation**:
- Signed correlation contexts
- Context signature verification at correlator
- Anomaly detection for unexpected context usage

### Attack 3: Timestamp Manipulation

**Attack**: Agent backdates events to appear legitimate

**Mitigation**:
- Monotonic counter prevents reordering
- Server-side timestamp verification
- NTP synchronization requirements

### Attack 4: Selective Forwarding

**Attack**: Agent forwards only favorable events

**Mitigation**:
- Sequence number gaps detected
- Hash chain breaks detected
- Periodic attestation of local log state

## Implementation Phases

### Phase 1: Basic Logging
- Event schema and logger
- Local buffering and forwarding
- Simple correlator storage

### Phase 2: Correlation
- Trace context propagation
- Span reconstruction
- Cross-agent event linking

### Phase 3: Integrity
- Event signing
- Hash chaining
- Integrity verification

### Phase 4: Advanced Features
- Merkle tree anchoring
- Full-text search
- Compliance reporting

## Configuration Example

```yaml
audit:
  # Per-agent settings
  agent:
    buffer_size: 100
    flush_interval_ms: 5000
    signing_key_path: /etc/clawdstrike/audit-key.pem

  # Correlator settings
  correlator:
    endpoint: https://audit.internal:8443
    tls:
      cert_path: /etc/clawdstrike/tls/cert.pem
      key_path: /etc/clawdstrike/tls/key.pem
      ca_path: /etc/clawdstrike/tls/ca.pem

  # Storage settings
  storage:
    type: clickhouse
    connection: clickhouse://audit:password@clickhouse.internal:9440/audit
    retention_days: 90

  # Search settings
  search:
    type: elasticsearch
    endpoint: https://es.internal:9200
    index_prefix: clawdstrike-audit

  # Integrity settings
  integrity:
    checkpoint_interval: 1000  # events
    merkle_anchor_interval_hours: 24
    external_timestamping:
      enabled: true
      service: https://timestamp.digicert.com

  # Trace context
  trace:
    propagation_format: w3c  # W3C Trace Context
    sample_rate: 1.0  # 100%
    max_trace_duration_hours: 24
```

## Trust Model and Assumptions

### Trusted
- Central correlator service
- Cryptographic primitives
- External timestamping service

### Untrusted
- Individual agents (may omit or modify)
- Network transport (encrypted but observable)

### Security Invariants
1. **Append-Only**: Events can only be added, not modified
2. **Chain Integrity**: Hash chain detects tampering
3. **Signed Events**: Forgery detected via signature verification
4. **Context Authenticity**: Correlation contexts signed by root agent
5. **Eventual Completeness**: Missing events detectable via gaps
