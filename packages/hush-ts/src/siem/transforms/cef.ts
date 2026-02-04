import type { SecurityEvent } from "../types";

function cefSeverity(sev: SecurityEvent["decision"]["severity"]): number {
  switch (sev) {
    case "info":
      return 1;
    case "low":
      return 3;
    case "medium":
      return 5;
    case "high":
      return 8;
    case "critical":
      return 10;
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

function kv(key: string, value: string): string {
  const v = value.replace(/\\/g, "\\\\").replace(/=/g, "\\=");
  return `${key}=${v}`;
}

export function toCef(event: SecurityEvent): string {
  const version = "0";
  const deviceVendor = "Clawdstrike";
  const deviceProduct = event.agent.name;
  const deviceVersion = event.agent.version;
  const signatureId = event.event_type;
  const name = event.decision.guard;
  const severity = cefSeverity(event.decision.severity);

  const ext: string[] = [];
  ext.push(kv("eventId", event.event_id));
  ext.push(kv("sessionId", event.session.id));
  ext.push(kv("outcome", event.outcome));
  ext.push(kv("action", event.action));
  ext.push(kv("guard", event.decision.guard));
  ext.push(kv("reason", event.decision.reason));

  switch (event.resource.type) {
    case "file": {
      if (event.resource.path) {
        ext.push(kv("filePath", event.resource.path));
      }
      break;
    }
    case "network": {
      if (event.resource.host) {
        ext.push(kv("dst", event.resource.host));
      }
      if (typeof event.resource.port === "number") {
        ext.push(kv("dpt", String(event.resource.port)));
      }
      break;
    }
    case "process": {
      ext.push(kv("process", event.resource.name));
      break;
    }
    case "tool": {
      ext.push(kv("tool", event.resource.name));
      break;
    }
    case "configuration":
      break;
    default: {
      const exhaustive: never = event.resource.type;
      void exhaustive;
    }
  }

  return `CEF:${version}|${deviceVendor}|${deviceProduct}|${deviceVersion}|${signatureId}|${name}|${severity}|${ext.join(" ")}`;
}

