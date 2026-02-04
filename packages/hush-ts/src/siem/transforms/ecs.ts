import type { SecurityEvent } from "../types";

function ecsSeverity(sev: SecurityEvent["decision"]["severity"]): number {
  switch (sev) {
    case "info":
      return 1;
    case "low":
      return 2;
    case "medium":
      return 3;
    case "high":
      return 4;
    case "critical":
      return 5;
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

function ecsCategoryAndType(eventType: SecurityEvent["event_type"]): { category: string; type: string } {
  switch (eventType) {
    case "session_start":
      return { category: "session", type: "start" };
    case "session_end":
      return { category: "session", type: "end" };
    case "egress_blocked":
      return { category: "network", type: "denied" };
    case "forbidden_path":
    case "patch_rejected":
      return { category: "file", type: "denied" };
    case "secret_detected":
      return { category: "intrusion_detection", type: "indicator" };
    case "guard_warn":
      return { category: "intrusion_detection", type: "info" };
    case "policy_allow":
      return { category: "intrusion_detection", type: "allowed" };
    case "policy_violation":
    case "guard_block":
      return { category: "intrusion_detection", type: "denied" };
    default: {
      const exhaustive: never = eventType;
      return exhaustive;
    }
  }
}

export function toEcs(event: SecurityEvent): Record<string, unknown> {
  const { category, type } = ecsCategoryAndType(event.event_type);

  const ecs: Record<string, unknown> = {
    "@timestamp": event.timestamp,
    event: {
      id: event.event_id,
      kind: "event",
      category: [category],
      type: [type],
      outcome: event.outcome,
      action: event.action,
      severity: ecsSeverity(event.decision.severity),
    },
    agent: {
      id: event.agent.id,
      name: event.agent.name,
      version: event.agent.version,
      type: event.agent.type,
    },
    session: {
      id: event.session.id,
    },
    message: event.decision.reason,
    rule: {
      name: event.decision.guard,
      id: event.decision.policy_hash,
      ruleset: event.decision.ruleset,
    },
    clawdstrike: {
      schema_version: event.schema_version,
      session_id: event.session.id,
      environment: event.session.environment,
      guard: event.decision.guard,
      policy_hash: event.decision.policy_hash,
      ruleset: event.decision.ruleset,
      metadata: event.metadata,
    },
  };

  if (event.session.tenant_id) {
    ecs.organization = { id: event.session.tenant_id };
  }
  if (event.session.user_id) {
    ecs.user = { id: event.session.user_id };
  }

  if (Object.keys(event.labels).length > 0) {
    ecs.labels = event.labels;
  }

  switch (event.resource.type) {
    case "file": {
      if (event.resource.path) {
        ecs.file = {
          path: event.resource.path,
          name: event.resource.path.split("/").pop() ?? event.resource.path,
        };
      }
      break;
    }
    case "network": {
      if (event.resource.host) {
        ecs.destination = {
          domain: event.resource.host,
          port: event.resource.port,
        };
      }
      break;
    }
    case "process": {
      ecs.process = { command_line: event.resource.name };
      break;
    }
    case "tool": {
      ecs.process = { name: event.resource.name };
      break;
    }
    case "configuration":
      break;
    default: {
      const exhaustive: never = event.resource.type;
      void exhaustive;
    }
  }

  if (event.threat.indicator) {
    ecs.threat = {
      indicator: {
        type: event.threat.indicator.type,
        name: event.threat.indicator.value,
      },
    };
  }

  if (event.threat.tactic) {
    ecs.threat = {
      ...(ecs.threat as Record<string, unknown> | undefined),
      tactic: { name: [event.threat.tactic] },
    };
  }

  if (event.threat.technique) {
    ecs.threat = {
      ...(ecs.threat as Record<string, unknown> | undefined),
      technique: { id: [event.threat.technique] },
    };
  }

  return ecs;
}
