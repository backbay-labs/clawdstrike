import type { AdapterConfig, SessionSummary } from './adapter.js';
import type { SecurityContext } from './context.js';

export function createSessionSummary(
  context: SecurityContext,
  config: AdapterConfig,
): SessionSummary {
  const endTime = new Date();
  const startTime = context.createdAt;
  const duration = endTime.getTime() - startTime.getTime();

  const auditEvents = context.auditEvents;
  const toolsUsed = Array.from(
    new Set(auditEvents.map(e => e.toolName).filter(Boolean) as string[]),
  );

  const toolsBlocked = Array.from(context.blockedTools);
  const warningsIssued = auditEvents.filter(e => e.type === 'tool_call_warning').length;

  return {
    sessionId: context.sessionId,
    startTime,
    endTime,
    duration,
    totalToolCalls: context.checkCount,
    blockedToolCalls: context.violationCount,
    warningsIssued,
    toolsUsed,
    toolsBlocked,
    auditEvents,
    policy: config.policy ?? '',
    mode: config.mode ?? 'deterministic',
  };
}
