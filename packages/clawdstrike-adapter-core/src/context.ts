import type { AuditEvent } from './audit.js';
import { createId } from './id.js';
import type { Decision, Policy } from './types.js';

export interface SecurityContext {
  readonly id: string;
  readonly sessionId: string;
  readonly userId?: string;
  readonly createdAt: Date;
  readonly policy: Policy;
  readonly metadata: Record<string, unknown>;
  readonly auditEvents: AuditEvent[];
  readonly blockedTools: Set<string>;
  checkCount: number;
  violationCount: number;
  addAuditEvent(event: AuditEvent): void;
  recordBlocked(toolName: string, decision: Decision): void;
  getSummary(): ContextSummary;
}

export interface ContextSummary {
  contextId: string;
  sessionId: string;
  duration: number;
  checkCount: number;
  violationCount: number;
  blockedTools: string[];
  warnings: number;
}

export interface CreateSecurityContextOptions {
  contextId?: string;
  sessionId?: string;
  userId?: string;
  policy?: Policy;
  metadata?: Record<string, unknown>;
}

export class DefaultSecurityContext implements SecurityContext {
  readonly id: string;
  readonly sessionId: string;
  readonly userId?: string;
  readonly createdAt: Date;
  readonly policy: Policy;
  readonly metadata: Record<string, unknown>;
  readonly auditEvents: AuditEvent[] = [];
  readonly blockedTools = new Set<string>();
  checkCount = 0;
  violationCount = 0;

  constructor(options: CreateSecurityContextOptions = {}) {
    this.id = options.contextId ?? createId('ctx');
    this.sessionId = options.sessionId ?? createId('sess');
    this.userId = options.userId;
    this.createdAt = new Date();
    this.policy = options.policy ?? {};
    this.metadata = options.metadata ?? {};
  }

  addAuditEvent(event: AuditEvent): void {
    this.auditEvents.push(event);
  }

  recordBlocked(toolName: string, _decision: Decision): void {
    this.blockedTools.add(toolName);
  }

  getSummary(): ContextSummary {
    const warnings = this.auditEvents.filter(e => e.type === 'tool_call_warning').length;
    return {
      contextId: this.id,
      sessionId: this.sessionId,
      duration: Date.now() - this.createdAt.getTime(),
      checkCount: this.checkCount,
      violationCount: this.violationCount,
      blockedTools: Array.from(this.blockedTools),
      warnings,
    };
  }
}

export function createSecurityContext(
  options: CreateSecurityContextOptions = {},
): SecurityContext {
  return new DefaultSecurityContext(options);
}
