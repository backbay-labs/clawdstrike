import type { SecurityEvent, SecurityEventType, SecuritySeverity } from "./types";

export interface EventFilter {
  min_severity?: SecuritySeverity;
  include_types?: SecurityEventType[];
  exclude_types?: SecurityEventType[];
  include_guards?: string[];
  exclude_guards?: string[];
}

export function eventMatchesFilter(event: SecurityEvent, filter: EventFilter): boolean {
  if (filter.min_severity && severityOrd(event.decision.severity) < severityOrd(filter.min_severity)) {
    return false;
  }

  if (filter.include_types?.length && !filter.include_types.includes(event.event_type)) {
    return false;
  }
  if (filter.exclude_types?.includes(event.event_type)) {
    return false;
  }

  if (filter.include_guards?.length && !filter.include_guards.includes(event.decision.guard)) {
    return false;
  }
  if (filter.exclude_guards?.includes(event.decision.guard)) {
    return false;
  }

  return true;
}

function severityOrd(sev: SecuritySeverity): number {
  switch (sev) {
    case "info":
      return 0;
    case "low":
      return 1;
    case "medium":
      return 2;
    case "high":
      return 3;
    case "critical":
      return 4;
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

