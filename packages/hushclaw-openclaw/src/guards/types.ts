/**
 * @hushclaw/openclaw - Guard Types
 *
 * Type definitions for the guard system.
 */

import type {
  PolicyEvent,
  Policy,
  GuardResult,
  EventType,
} from '../types.js';

/**
 * Guard interface - modular policy enforcement
 */
export interface Guard {
  /** Guard name for identification and logging */
  name(): string;

  /** Check an event against the policy (async) */
  check(event: PolicyEvent, policy: Policy): Promise<GuardResult>;

  /** Check an event against the policy (sync, optional) */
  checkSync?(event: PolicyEvent, policy: Policy): GuardResult;

  /** Whether this guard is enabled */
  isEnabled(): boolean;

  /** Event types this guard handles (empty = all) */
  handles(): EventType[];
}

/**
 * Base class for guards with common functionality
 */
export abstract class BaseGuard implements Guard {
  protected enabled: boolean = true;

  abstract name(): string;
  abstract check(event: PolicyEvent, policy: Policy): Promise<GuardResult>;
  abstract handles(): EventType[];

  checkSync?(event: PolicyEvent, policy: Policy): GuardResult;

  isEnabled(): boolean {
    return this.enabled;
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Helper to create an allow result
   */
  protected allow(): GuardResult {
    return { status: 'allow', guard: this.name() };
  }

  /**
   * Helper to create a deny result
   */
  protected deny(
    reason: string,
    severity: GuardResult['severity'] = 'high',
  ): GuardResult {
    return { status: 'deny', reason, severity, guard: this.name() };
  }

  /**
   * Helper to create a warn result
   */
  protected warn(reason: string): GuardResult {
    return { status: 'warn', reason, guard: this.name() };
  }
}
