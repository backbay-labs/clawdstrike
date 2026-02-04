import type { SecurityEvent } from "../types";

function ocsfSeverity(sev: SecurityEvent["decision"]["severity"]): { severity_id: number; severity: string } {
  switch (sev) {
    case "info":
      return { severity_id: 1, severity: "informational" };
    case "low":
      return { severity_id: 2, severity: "low" };
    case "medium":
      return { severity_id: 3, severity: "medium" };
    case "high":
      return { severity_id: 4, severity: "high" };
    case "critical":
      return { severity_id: 6, severity: "critical" };
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

export function toOcsf(event: SecurityEvent): Record<string, unknown> {
  const { severity_id, severity } = ocsfSeverity(event.decision.severity);

  const out: Record<string, unknown> = {
    time: event.timestamp,
    severity_id,
    severity,
    status: event.outcome,
    activity_name: event.event_type,
    category_name: event.event_category,
    message: event.decision.reason,
    metadata: {
      version: event.schema_version,
      product: {
        name: "clawdstrike",
        version: event.agent.version,
      },
    },
    actor: {
      id: event.agent.id,
      name: event.agent.name,
      type: event.agent.type,
    },
    session: {
      id: event.session.id,
      tenant_id: event.session.tenant_id,
      environment: event.session.environment,
    },
    decision: {
      allowed: event.decision.allowed,
      guard: event.decision.guard,
      severity: event.decision.severity,
    },
  };

  switch (event.resource.type) {
    case "file": {
      out.file = {
        path: event.resource.path,
        name: event.resource.name,
      };
      break;
    }
    case "network": {
      out.network = {
        host: event.resource.host,
        port: event.resource.port,
      };
      break;
    }
    case "process": {
      out.process = { command_line: event.resource.name };
      break;
    }
    case "tool": {
      out.tool = { name: event.resource.name };
      break;
    }
    case "configuration":
      break;
    default: {
      const exhaustive: never = event.resource.type;
      void exhaustive;
    }
  }

  return out;
}

