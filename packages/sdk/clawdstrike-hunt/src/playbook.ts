import { hunt } from './local.js';
import type { HuntOptions } from './local.js';
import { correlate } from './correlate/index.js';
import { IocDatabase } from './correlate/index.js';
import { buildReport, signReport, collectEvidence } from './report.js';
import { parseHumanDuration } from './duration.js';
import type { CorrelationRule, TimelineEvent, Alert, IocMatch, HuntReport, NormalizedVerdict, EvidenceItem } from './types.js';

export interface PlaybookResult {
  events: TimelineEvent[];
  alerts: Alert[];
  iocMatches: IocMatch[];
  report?: HuntReport;
}

interface PlaybookInit {
  start?: string | Date;
  verdictFilter?: NormalizedVerdict;
  rules: CorrelationRule[];
  iocDb?: IocDatabase;
  deduplicateWindow?: number;
  reportTitle?: string;
  signKey?: string;
  huntOptions: Partial<HuntOptions>;
}

export class Playbook {
  private readonly _start?: string | Date;
  private readonly _verdictFilter?: NormalizedVerdict;
  private readonly _rules: CorrelationRule[];
  private readonly _iocDb?: IocDatabase;
  private readonly _deduplicateWindow?: number;
  private readonly _reportTitle?: string;
  private readonly _signKey?: string;
  private readonly _huntOptions: Partial<HuntOptions>;

  private constructor(init: Partial<PlaybookInit> = {}) {
    this._start = init.start;
    this._verdictFilter = init.verdictFilter;
    this._rules = init.rules ?? [];
    this._iocDb = init.iocDb;
    this._deduplicateWindow = init.deduplicateWindow;
    this._reportTitle = init.reportTitle;
    this._signKey = init.signKey;
    this._huntOptions = init.huntOptions ?? {};
  }

  static create(): Playbook {
    return new Playbook();
  }

  since(timeRange: string | Date): Playbook {
    return new Playbook({ ...this.toInit(), start: timeRange });
  }

  filter(verdict: NormalizedVerdict): Playbook {
    return new Playbook({ ...this.toInit(), verdictFilter: verdict });
  }

  correlate(rules: CorrelationRule[]): Playbook {
    return new Playbook({ ...this.toInit(), rules });
  }

  enrich(iocDb: IocDatabase): Playbook {
    return new Playbook({ ...this.toInit(), iocDb });
  }

  deduplicate(window: string | number): Playbook {
    let windowMs: number;
    if (typeof window === 'string') {
      windowMs = parseHumanDuration(window) ?? 0;
    } else {
      windowMs = window;
    }
    return new Playbook({ ...this.toInit(), deduplicateWindow: windowMs });
  }

  report(title: string): Playbook {
    return new Playbook({ ...this.toInit(), reportTitle: title });
  }

  sign(keyHex: string): Playbook {
    return new Playbook({ ...this.toInit(), signKey: keyHex });
  }

  async run(): Promise<PlaybookResult> {
    // 1. Hunt events
    let events = await hunt({ ...this._huntOptions, start: this._start });

    // 2. Filter by verdict
    if (this._verdictFilter) {
      events = events.filter(e => e.verdict === this._verdictFilter);
    }

    // 3. Correlate
    let alerts: Alert[] = [];
    if (this._rules.length > 0) {
      alerts = correlate(this._rules, events);
    }

    // 4. IOC enrichment
    let iocMatches: IocMatch[] = [];
    if (this._iocDb) {
      iocMatches = this._iocDb.matchEvents(events);
    }

    // 5. Deduplicate alerts
    if (this._deduplicateWindow !== undefined && this._deduplicateWindow > 0) {
      alerts = deduplicateAlerts(alerts, this._deduplicateWindow);
    }

    // 6. Build report
    let report: HuntReport | undefined;
    if (this._reportTitle) {
      const evidenceSources: (Alert | TimelineEvent[] | IocMatch[])[] = [];
      for (const a of alerts) {
        evidenceSources.push(a);
      }
      if (events.length > 0) {
        evidenceSources.push(events);
      }
      if (iocMatches.length > 0) {
        evidenceSources.push(iocMatches);
      }
      if (evidenceSources.length > 0) {
        const evidence = deduplicateEvidence(collectEvidence(...evidenceSources));
        if (evidence.length > 0) {
          report = buildReport(this._reportTitle, evidence);
          // 7. Sign
          if (this._signKey) {
            report = await signReport(report, this._signKey);
          }
        }
      }
    }

    return { events, alerts, iocMatches, report };
  }

  toJSON(): Record<string, unknown> {
    return {
      start: this._start instanceof Date ? this._start.toISOString() : this._start,
      verdictFilter: this._verdictFilter,
      rules: this._rules,
      deduplicateWindow: this._deduplicateWindow,
      reportTitle: this._reportTitle,
      huntOptions: this._huntOptions,
    };
  }

  static fromJSON(json: Record<string, unknown>): Playbook {
    return new Playbook({
      start: json.start as string | undefined,
      verdictFilter: json.verdictFilter as NormalizedVerdict | undefined,
      rules: json.rules as CorrelationRule[] | undefined,
      deduplicateWindow: json.deduplicateWindow as number | undefined,
      reportTitle: json.reportTitle as string | undefined,
      huntOptions: json.huntOptions as Partial<HuntOptions> | undefined,
    });
  }

  private toInit(): PlaybookInit {
    return {
      start: this._start,
      verdictFilter: this._verdictFilter,
      rules: this._rules,
      iocDb: this._iocDb,
      deduplicateWindow: this._deduplicateWindow,
      reportTitle: this._reportTitle,
      signKey: this._signKey,
      huntOptions: this._huntOptions,
    };
  }
}

function deduplicateEvidence(items: EvidenceItem[]): EvidenceItem[] {
  const seen = new Set<string>();
  const result: EvidenceItem[] = [];
  let nextIndex = 0;
  for (const item of items) {
    const key = `${item.sourceType}|${item.timestamp instanceof Date ? item.timestamp.toISOString() : String(item.timestamp)}|${item.summary}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push({ ...item, index: nextIndex });
      nextIndex++;
    }
  }
  return result;
}

function deduplicateAlerts(alerts: Alert[], windowMs: number): Alert[] {
  const seen = new Map<string, Date>();
  return alerts.filter(alert => {
    const key = alert.ruleName;
    const lastSeen = seen.get(key);
    if (lastSeen && (alert.triggeredAt.getTime() - lastSeen.getTime()) < windowMs) {
      return false;
    }
    seen.set(key, alert.triggeredAt);
    return true;
  });
}
