import { CorrelationError } from "../errors.js";
import type {
  Alert,
  CorrelationRule,
  RuleCondition,
  TimelineEvent,
} from "../types.js";

interface CompiledPatterns {
  target?: RegExp;
  notTarget?: RegExp;
}

interface WindowState {
  startedAt: Date;
  boundEvents: Map<string, TimelineEvent[]>;
}

/**
 * The correlation engine evaluates events against loaded rules using sliding windows.
 *
 * Implements the same sliding-window state machine as the Rust `CorrelationEngine`:
 *
 * 1. Root conditions (no `after`) create new windows.
 * 2. Dependent conditions advance existing windows when prerequisites are met.
 * 3. Fully-matched windows emit alerts and are removed.
 * 4. Expired windows are evicted based on the rule's window duration.
 */
export class CorrelationEngine {
  private _rules: CorrelationRule[];
  private compiledPatterns: Map<string, CompiledPatterns>;
  private windows: Map<number, WindowState[]>;

  constructor(rules: CorrelationRule[]) {
    this._rules = rules;
    this.compiledPatterns = new Map();
    this.windows = new Map();

    for (let ri = 0; ri < rules.length; ri++) {
      const rule = rules[ri];
      for (let ci = 0; ci < rule.conditions.length; ci++) {
        const cond = rule.conditions[ci];
        const key = `${ri}-${ci}`;
        const cp: CompiledPatterns = {};

        if (cond.targetPattern !== undefined) {
          try {
            cp.target = new RegExp(cond.targetPattern);
          } catch (e) {
            throw new CorrelationError(
              `rule '${rule.name}' condition ${ci}: ${e instanceof Error ? e.message : String(e)}`
            );
          }
        }

        if (cond.notTargetPattern !== undefined) {
          try {
            cp.notTarget = new RegExp(cond.notTargetPattern);
          } catch (e) {
            throw new CorrelationError(
              `rule '${rule.name}' condition ${ci} not_target: ${e instanceof Error ? e.message : String(e)}`
            );
          }
        }

        this.compiledPatterns.set(key, cp);
      }
    }
  }

  /**
   * Process a single event against all loaded rules.
   * Returns any alerts that were generated.
   */
  processEvent(event: TimelineEvent, maxWindow?: number): Alert[] {
    if (maxWindow !== undefined) {
      this.evictExpiredAtCapped(event.timestamp, maxWindow);
    } else {
      this.evictExpiredAt(event.timestamp);
    }

    const alerts: Alert[] = [];
    for (let ri = 0; ri < this._rules.length; ri++) {
      const ruleAlerts = this.evaluateRule(ri, event);
      alerts.push(...ruleAlerts);
    }
    return alerts;
  }

  /**
   * Evict expired windows, optionally capping at a maximum window duration (ms).
   */
  evict(maxWindow?: number): void {
    if (maxWindow !== undefined) {
      this.evictExpiredCapped(maxWindow);
    } else {
      this.evictExpired();
    }
  }

  private evictExpiredAt(now: Date): void {
    const nowMs = now.getTime();
    for (const [ri, windows] of this.windows) {
      const rule = this._rules[ri];
      const filtered = windows.filter((ws) => {
        const elapsed = nowMs - ws.startedAt.getTime();
        return elapsed <= rule.window;
      });
      if (filtered.length === 0) {
        this.windows.delete(ri);
      } else {
        this.windows.set(ri, filtered);
      }
    }
  }

  private evictExpired(): void {
    this.evictExpiredAt(new Date());
  }

  private evictExpiredAtCapped(now: Date, maxWindow: number): void {
    const nowMs = now.getTime();
    for (const [ri, windows] of this.windows) {
      const rule = this._rules[ri];
      const effective = Math.min(maxWindow, rule.window);
      const filtered = windows.filter((ws) => {
        const elapsed = nowMs - ws.startedAt.getTime();
        return elapsed <= effective;
      });
      if (filtered.length === 0) {
        this.windows.delete(ri);
      } else {
        this.windows.set(ri, filtered);
      }
    }
  }

  private evictExpiredCapped(maxWindow: number): void {
    this.evictExpiredAtCapped(new Date(), maxWindow);
  }

  /**
   * Flush all windows and return alerts for any fully-matched sequences.
   * When `asOf` is provided, eviction uses that timestamp instead of wall-clock time.
   */
  flush(asOf?: Date): Alert[] {
    if (asOf !== undefined) {
      this.evictExpiredAt(asOf);
    } else {
      this.evictExpired();
    }

    const alerts: Alert[] = [];
    for (const [ri, windows] of this.windows) {
      const rule = this._rules[ri];
      for (const ws of windows) {
        if (allConditionsMet(rule, ws)) {
          alerts.push(buildAlert(rule, ws));
        }
      }
    }
    this.windows.clear();
    return alerts;
  }

  get rules(): readonly CorrelationRule[] {
    return this._rules;
  }

  /**
   * Evaluate a single rule against an event.
   */
  private evaluateRule(ri: number, event: TimelineEvent): Alert[] {
    const alerts: Alert[] = [];
    const rule = this._rules[ri];

    // Snapshot: number of windows before processing this event.
    const preExistingCount = this.windows.get(ri)?.length ?? 0;
    // Track whether this event already advanced each pre-existing window.
    const dependentAdvanced: boolean[] = new Array(preExistingCount).fill(false);

    for (let ci = 0; ci < rule.conditions.length; ci++) {
      const cond = rule.conditions[ci];
      const key = `${ri}-${ci}`;
      const cp = this.compiledPatterns.get(key);
      if (!cp) continue;

      if (!conditionMatches(cond, cp, event)) {
        continue;
      }

      if (cond.after === undefined) {
        // Root condition — start a new window.
        const ws: WindowState = {
          startedAt: event.timestamp,
          boundEvents: new Map([[cond.bind, [event]]]),
        };
        if (!this.windows.has(ri)) {
          this.windows.set(ri, []);
        }
        this.windows.get(ri)!.push(ws);
      } else {
        // Dependent condition — advance existing windows.
        if (preExistingCount === 0) continue;

        const windows = this.windows.get(ri);
        if (!windows) continue;

        for (let wi = 0; wi < preExistingCount; wi++) {
          const ws = windows[wi];

          // A single event may advance at most one dependent bind per window.
          if (dependentAdvanced[wi]) continue;

          // Skip windows that already have this bind matched.
          if (ws.boundEvents.has(cond.bind)) continue;

          // Check that the `after` bind exists in this window.
          const afterEvents = ws.boundEvents.get(cond.after);
          if (!afterEvents || afterEvents.length === 0) continue;

          // Dependent events must never be earlier than the prerequisite event.
          // Use the last event from the prerequisite bind.
          const afterEvent = afterEvents[afterEvents.length - 1];
          const elapsed = event.timestamp.getTime() - afterEvent.timestamp.getTime();
          if (elapsed < 0) continue;

          // Check `within` constraint.
          if (cond.within !== undefined && elapsed > cond.within) continue;

          // Bind this event.
          const existing = ws.boundEvents.get(cond.bind);
          if (existing) {
            existing.push(event);
          } else {
            ws.boundEvents.set(cond.bind, [event]);
          }
          dependentAdvanced[wi] = true;
        }
      }
    }

    // Check if any windows for this rule are now fully matched.
    const windows = this.windows.get(ri);
    if (windows) {
      const completedIndices: number[] = [];
      for (let wi = 0; wi < windows.length; wi++) {
        if (allConditionsMet(rule, windows[wi])) {
          alerts.push(buildAlert(rule, windows[wi]));
          completedIndices.push(wi);
        }
      }
      // Remove completed windows in reverse order to preserve indices.
      for (let i = completedIndices.length - 1; i >= 0; i--) {
        windows.splice(completedIndices[i], 1);
      }
      if (windows.length === 0) {
        this.windows.delete(ri);
      }
    }

    return alerts;
  }
}

/**
 * High-level correlation: create an engine, process all events, flush, and return alerts.
 */
export function correlate(rules: CorrelationRule[], events: TimelineEvent[]): Alert[] {
  const engine = new CorrelationEngine(rules);
  const alerts: Alert[] = [];
  for (const event of events) {
    alerts.push(...engine.processEvent(event));
  }
  const lastTimestamp = events.length > 0 ? events[events.length - 1].timestamp : undefined;
  alerts.push(...engine.flush(lastTimestamp));
  return alerts;
}

function allConditionsMet(rule: CorrelationRule, ws: WindowState): boolean {
  return rule.conditions.every((cond) => {
    const evts = ws.boundEvents.get(cond.bind);
    return evts !== undefined && evts.length > 0;
  });
}

function conditionMatches(
  cond: RuleCondition,
  compiled: CompiledPatterns,
  event: TimelineEvent
): boolean {
  // Source check: case-insensitive.
  const eventSource = event.source.toLowerCase();
  const sourceOk = cond.source.some((s) => s.toLowerCase() === eventSource);
  if (!sourceOk) return false;

  // Action type check (case-insensitive).
  if (cond.actionType !== undefined) {
    if (event.actionType === undefined) return false;
    if (event.actionType.toLowerCase() !== cond.actionType.toLowerCase()) return false;
  }

  // Verdict check (case-insensitive).
  if (cond.verdict !== undefined) {
    const expected = cond.verdict.toLowerCase();
    if (event.verdict.toLowerCase() !== expected) return false;
  }

  // Target pattern: regex must match event.summary.
  if (compiled.target !== undefined) {
    if (!compiled.target.test(event.summary)) return false;
  }

  // Not-target pattern: regex must NOT match event.summary.
  if (compiled.notTarget !== undefined) {
    if (compiled.notTarget.test(event.summary)) return false;
  }

  return true;
}

function buildAlert(rule: CorrelationRule, ws: WindowState): Alert {
  // Collect evidence events in the order specified by output.evidence.
  const evidence: TimelineEvent[] = [];
  for (const bindName of rule.output.evidence) {
    const evts = ws.boundEvents.get(bindName);
    if (evts) {
      evidence.push(...evts);
    }
  }

  // Triggered at = timestamp of the latest evidence event.
  const triggeredAt =
    evidence.length > 0
      ? new Date(Math.max(...evidence.map((e) => e.timestamp.getTime())))
      : new Date();

  return {
    ruleName: rule.name,
    severity: rule.severity,
    title: rule.output.title,
    triggeredAt,
    evidence,
    description: rule.description,
  };
}
