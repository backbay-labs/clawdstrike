import { hunt } from './local.js';
import type { HuntOptions } from './local.js';
import { correlate } from './correlate/index.js';
import { loadRulesFromFiles } from './correlate/index.js';
import { IocDatabase } from './correlate/index.js';
import type { CorrelationRule, Alert, IocMatch, TimelineEvent } from './types.js';

export interface ReplayOptions extends HuntOptions {
  rules: CorrelationRule[] | string[];
  iocDb?: IocDatabase;
}

export interface ReplayResult {
  alerts: Alert[];
  iocMatches: IocMatch[];
  eventsScanned: number;
  timeRange: { start: Date; end: Date } | undefined;
  rulesEvaluated: number;
}

export async function replay(options: ReplayOptions): Promise<ReplayResult> {
  // Load rules if paths provided
  let rules: CorrelationRule[];
  if (options.rules.length > 0 && typeof options.rules[0] === 'string') {
    rules = await loadRulesFromFiles(options.rules as string[]);
  } else {
    rules = options.rules as CorrelationRule[];
  }

  // Hunt events
  const events = await hunt(options);

  // Correlate
  const alerts = correlate(rules, events);

  // Optional IOC matching
  const iocMatches = options.iocDb ? options.iocDb.matchEvents(events) : [];

  // Compute time range
  let timeRange: { start: Date; end: Date } | undefined;
  if (events.length > 0) {
    const timestamps = events.map(e => e.timestamp.getTime());
    timeRange = {
      start: new Date(Math.min(...timestamps)),
      end: new Date(Math.max(...timestamps)),
    };
  }

  return {
    alerts,
    iocMatches,
    eventsScanned: events.length,
    timeRange,
    rulesEvaluated: rules.length,
  };
}
