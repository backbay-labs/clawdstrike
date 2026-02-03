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

export type PromptSecurityBlockKind =
  | 'instruction_hierarchy'
  | 'jailbreak_detection'
  | 'prompt_injection'
  | 'output_sanitization';

export class ClawdstrikePromptSecurityError extends Error {
  readonly kind: PromptSecurityBlockKind;
  readonly details: Record<string, unknown>;

  constructor(kind: PromptSecurityBlockKind, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ClawdstrikePromptSecurityError';
    this.kind = kind;
    this.details = details;
  }
}
