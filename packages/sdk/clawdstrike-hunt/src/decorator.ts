import { CorrelationEngine } from './correlate/index.js';
import { HuntAlertError } from './errors.js';
import type { CorrelationRule, TimelineEvent, Alert } from './types.js';
import { EventSourceType, TimelineEventKind, NormalizedVerdict } from './types.js';

export interface GuardedOptions {
  rules: CorrelationRule[];
  onAlert?: 'deny' | 'log';
}

/**
 * Higher-order function that wraps fn with correlation-based guarding.
 * Captures function name, args, and timing as TimelineEvents.
 * Feeds through CorrelationEngine. On alert:
 * - 'deny' (default): throws HuntAlertError
 * - 'log': collects alerts silently, accessible via returned fn's .alerts property
 */
export function guarded<T extends (...args: unknown[]) => unknown>(
  fn: T,
  options: GuardedOptions
): T & { alerts: Alert[] } {
  const engine = new CorrelationEngine(options.rules);
  const mode = options.onAlert ?? 'deny';
  const collectedAlerts: Alert[] = [];

  function runGuard(): void {
    const start = new Date();

    const event: TimelineEvent = {
      timestamp: start,
      source: EventSourceType.Receipt,
      kind: TimelineEventKind.GuardDecision,
      verdict: NormalizedVerdict.Allow,
      summary: `guarded call: ${fn.name || 'anonymous'}`,
      actionType: 'function_call',
      process: fn.name || 'anonymous',
    };

    const alerts = engine.processEvent(event);

    if (alerts.length > 0) {
      if (mode === 'deny') {
        throw new HuntAlertError(
          `Alert triggered: ${alerts[0].title}`
        );
      }
      collectedAlerts.push(...alerts);
    }
  }

  const wrapper = function (this: unknown, ...args: unknown[]) {
    runGuard();

    const result = fn.apply(this, args);
    if (result && typeof result === 'object' && typeof (result as Promise<unknown>).then === 'function') {
      return result;
    }
    return result;
  } as unknown as T & { alerts: Alert[] };

  Object.defineProperty(wrapper, 'alerts', {
    get: () => collectedAlerts,
  });
  Object.defineProperty(wrapper, 'name', {
    value: fn.name,
  });

  return wrapper;
}
