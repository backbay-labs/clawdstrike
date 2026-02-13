export { ClawdstrikeBlockedError } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from '@clawdstrike/adapter-core';
import type { Decision } from '@clawdstrike/adapter-core';

/**
 * @deprecated Use ClawdstrikeBlockedError instead.
 */
export class ClawdstrikeViolationError extends ClawdstrikeBlockedError {
  constructor(toolName: string, decision: Decision, message?: string) {
    super(toolName, decision, message);
    this.name = 'ClawdstrikeViolationError';
  }
}
