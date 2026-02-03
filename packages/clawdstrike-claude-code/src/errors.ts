import type { Decision } from '@clawdstrike/adapter-core';

export class ClawdstrikeBlockedError extends Error {
  readonly toolName: string;
  readonly decision: Decision;

  constructor(toolName: string, decision: Decision, message?: string) {
    const detail = decision.message ?? decision.reason ?? 'denied';
    super(message ?? `Tool '${toolName}' blocked: ${detail}`);
    this.name = 'ClawdstrikeBlockedError';
    this.toolName = toolName;
    this.decision = decision;
  }
}

