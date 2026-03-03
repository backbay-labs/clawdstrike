import { parseRule, loadRulesFromFiles } from './correlate/index.js';
import { correlate } from './correlate/index.js';
import type { CorrelationRule, TimelineEvent, Alert, RuleSeverity } from './types.js';
import { EventSourceType, TimelineEventKind, NormalizedVerdict } from './types.js';

export interface TestRuleOptions {
  given: TimelineEvent[];
  expectAlerts?: number;
  expectSeverity?: RuleSeverity;
  expectRuleName?: string;
}

export interface TestResult {
  passed: boolean;
  alerts: Alert[];
  eventsProcessed: number;
  mismatches: string[];
}

/**
 * Create a test event with sensible defaults.
 */
export function event(overrides?: Partial<TimelineEvent>): TimelineEvent {
  return {
    timestamp: new Date(),
    source: EventSourceType.Receipt,
    kind: TimelineEventKind.GuardDecision,
    verdict: NormalizedVerdict.Allow,
    summary: 'test event',
    ...overrides,
  };
}

/**
 * Test a correlation rule against given events.
 * Accepts a CorrelationRule object, YAML string (contains newline), or file path.
 */
export async function testRule(
  ruleOrPath: CorrelationRule | string,
  options: TestRuleOptions,
): Promise<TestResult> {
  let rule: CorrelationRule;

  if (typeof ruleOrPath === 'string') {
    if (ruleOrPath.includes('\n')) {
      rule = parseRule(ruleOrPath);
    } else {
      const rules = await loadRulesFromFiles([ruleOrPath]);
      rule = rules[0];
    }
  } else {
    rule = ruleOrPath;
  }

  const alerts = correlate([rule], options.given);
  const mismatches: string[] = [];

  if (options.expectAlerts !== undefined && alerts.length !== options.expectAlerts) {
    mismatches.push(`expected ${options.expectAlerts} alerts, got ${alerts.length}`);
  }
  if (options.expectSeverity !== undefined) {
    for (const alert of alerts) {
      if (alert.severity !== options.expectSeverity) {
        mismatches.push(`expected severity '${options.expectSeverity}', got '${alert.severity}'`);
      }
    }
  }
  if (options.expectRuleName !== undefined) {
    for (const alert of alerts) {
      if (alert.ruleName !== options.expectRuleName) {
        mismatches.push(`expected rule name '${options.expectRuleName}', got '${alert.ruleName}'`);
      }
    }
  }

  return {
    passed: mismatches.length === 0,
    alerts,
    eventsProcessed: options.given.length,
    mismatches,
  };
}
