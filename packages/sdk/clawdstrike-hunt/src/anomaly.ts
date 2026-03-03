import type { TimelineEvent } from './types.js';

export interface ScoredEvent {
  event: TimelineEvent;
  anomalyScore: number;
  featureScores: Record<string, number>;
}

export interface BaselineData {
  totalEvents: number;
  sourceCounts: Record<string, number>;
  kindCounts: Record<string, number>;
  verdictCounts: Record<string, number>;
  actionTypeCounts: Record<string, number>;
  processCounts: Record<string, number>;
  namespaceCounts: Record<string, number>;
  hourOfDayCounts: Record<string, number>;
}

export class Baseline {
  private data: BaselineData;

  private constructor(data: BaselineData) {
    this.data = data;
  }

  static build(events: TimelineEvent[]): Baseline {
    const data: BaselineData = {
      totalEvents: events.length,
      sourceCounts: {},
      kindCounts: {},
      verdictCounts: {},
      actionTypeCounts: {},
      processCounts: {},
      namespaceCounts: {},
      hourOfDayCounts: {},
    };

    for (const event of events) {
      increment(data.sourceCounts, event.source);
      increment(data.kindCounts, event.kind);
      increment(data.verdictCounts, event.verdict);
      if (event.actionType) increment(data.actionTypeCounts, event.actionType);
      if (event.process) increment(data.processCounts, event.process);
      if (event.namespace) increment(data.namespaceCounts, event.namespace);
      const hour = event.timestamp.getUTCHours();
      increment(data.hourOfDayCounts, String(hour));
    }

    return new Baseline(data);
  }

  score(event: TimelineEvent): number {
    return this.scoreDetailed(event).anomalyScore;
  }

  scoreDetailed(event: TimelineEvent): ScoredEvent {
    const featureScores: Record<string, number> = {};
    const total = this.data.totalEvents;

    if (total === 0) {
      return { event, anomalyScore: 1.0, featureScores: {} };
    }

    featureScores.source = 1 - (this.data.sourceCounts[event.source] ?? 0) / total;
    featureScores.kind = 1 - (this.data.kindCounts[event.kind] ?? 0) / total;
    featureScores.verdict = 1 - (this.data.verdictCounts[event.verdict] ?? 0) / total;

    if (event.actionType) {
      featureScores.actionType = 1 - (this.data.actionTypeCounts[event.actionType] ?? 0) / total;
    }
    if (event.process) {
      featureScores.process = 1 - (this.data.processCounts[event.process] ?? 0) / total;
    }
    if (event.namespace) {
      featureScores.namespace = 1 - (this.data.namespaceCounts[event.namespace] ?? 0) / total;
    }

    const hour = event.timestamp.getUTCHours();
    featureScores.hourOfDay = 1 - (this.data.hourOfDayCounts[hour] ?? 0) / total;

    const values = Object.values(featureScores);
    const anomalyScore = values.length > 0
      ? values.reduce((a, b) => a + b, 0) / values.length
      : 1.0;

    return { event, anomalyScore, featureScores };
  }

  toJSON(): BaselineData {
    return { ...this.data };
  }

  static fromJSON(data: BaselineData): Baseline {
    return new Baseline({ ...data });
  }
}

export function scoreAnomalies(
  events: TimelineEvent[],
  baseline: Baseline,
  threshold: number = 0.5
): ScoredEvent[] {
  return events
    .map(e => baseline.scoreDetailed(e))
    .filter(s => s.anomalyScore >= threshold)
    .sort((a, b) => b.anomalyScore - a.anomalyScore);
}

function increment(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}
