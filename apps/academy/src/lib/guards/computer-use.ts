/**
 * Computer Use Guard Simulation
 *
 * Controls CUA (Computer Use Agent) actions for remote desktop sessions.
 * Config has `blocked_actions: string[]` (e.g., ['screenshot', 'click', 'type']).
 * Denies if action data contains a blocked action type.
 */
import type { GuardAction, GuardResult } from './types';

const DEFAULT_BLOCKED_ACTIONS: string[] = [];

export function evaluateComputerUse(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate custom actions with action_type 'computer_use'
  if (action.type !== 'custom' || action.action_type !== 'computer_use') {
    return {
      allowed: true,
      guard: 'computer_use',
      severity: 'info',
      message: 'Action type not evaluated by computer_use guard',
    };
  }

  const blockedActions =
    (config.blocked_actions as string[] | undefined) ?? DEFAULT_BLOCKED_ACTIONS;

  const cuaAction = action.data?.action as string | undefined;
  if (cuaAction && blockedActions.includes(cuaAction)) {
    return {
      allowed: false,
      guard: 'computer_use',
      severity: 'error',
      message: `CUA action blocked: ${cuaAction}`,
      details: { action: cuaAction },
    };
  }

  return {
    allowed: true,
    guard: 'computer_use',
    severity: 'info',
    message: 'CUA action allowed',
    details: { action: cuaAction },
  };
}
