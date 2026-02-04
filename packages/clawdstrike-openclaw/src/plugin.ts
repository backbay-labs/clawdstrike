/**
 * OpenClaw plugin entry point for Clawdstrike
 *
 * Follows the OpenClaw plugin API: https://docs.openclaw.ai/plugin
 */

import { PolicyEngine } from "./policy/engine.js";
import type { ClawdstrikeConfig } from "./types.js";

// Re-export existing utilities for external use
export * from "./index.js";

/**
 * Plugin registration function (function format per OpenClaw docs)
 */
export default function clawdstrikePlugin(api: any) {
  const logger = api.logger ?? console;

  // Load config from plugin settings
  const getConfig = (): ClawdstrikeConfig => {
    const pluginConfig = api.config?.plugins?.entries?.["clawdstrike-security"]?.config ?? {};
    return {
      policy: pluginConfig.policy,
      mode: pluginConfig.mode ?? "deterministic",
      logLevel: pluginConfig.logLevel ?? "info",
      guards: pluginConfig.guards ?? {
        forbidden_path: true,
        egress: true,
        secret_leak: true,
        patch_integrity: true,
      },
    };
  };

  // Register the policy_check tool
  api.registerTool({
    name: "policy_check",
    description:
      "Check if an action is allowed by the security policy. Use this BEFORE attempting potentially restricted operations like file access, network requests, or command execution.",
    parameters: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["file_read", "file_write", "network", "command", "tool_call"],
          description: "The type of action to check",
        },
        resource: {
          type: "string",
          description:
            "The resource to check (file path, domain/URL, command string, or tool name)",
        },
      },
      required: ["action", "resource"],
    },
    async execute(_id: string, params: { action: string; resource: string }) {
      try {
        const config = getConfig();
        const engine = new PolicyEngine(config);

        const action = (params.action as PolicyCheckAction) ?? "tool_call";
        const resource = params.resource ?? "";

        const event = buildEvent(action, resource);
        const decision = await engine.evaluate(event as any);

        const isDenied = decision.status === 'deny' || decision.denied;
        const isWarn = decision.status === 'warn' || decision.warn;
        const result = {
          allowed: !isDenied,
          denied: isDenied,
          warn: isWarn,
          guard: decision.guard,
          reason: decision.reason,
          message: formatDecision(decision),
          suggestion: isDenied ? getSuggestion(action, resource) : undefined,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: true, message }, null, 2),
            },
          ],
        };
      }
    },
  });

  // Register CLI commands
  api.registerCli(
    ({ program }: { program: any }) => {
      const clawdstrike = program
        .command("clawdstrike")
        .description("Clawdstrike security management");

      clawdstrike
        .command("status")
        .description("Show Clawdstrike plugin status")
        .action(() => {
          const config = getConfig();
          console.log("Clawdstrike Security Plugin");
          console.log("---------------------------");
          console.log(`Mode: ${config.mode}`);
          console.log(`Policy: ${config.policy ?? "(default)"}`);
          console.log(`Log Level: ${config.logLevel}`);
          console.log("Guards:");
          Object.entries(config.guards ?? {}).forEach(([name, enabled]) => {
            console.log(`  ${name}: ${enabled ? "enabled" : "disabled"}`);
          });
        });

      clawdstrike
        .command("check <action> <resource>")
        .description("Check if an action is allowed")
        .action(async (action: string, resource: string) => {
          const config = getConfig();
          const engine = new PolicyEngine(config);
          const event = buildEvent(action as PolicyCheckAction, resource);
          const decision = await engine.evaluate(event as any);
          console.log(formatDecision(decision));
          if (decision.status === 'deny' || decision.denied) {
            console.log(`Suggestion: ${getSuggestion(action, resource)}`);
            process.exitCode = 1;
          }
        });
    },
    { commands: ["clawdstrike"] }
  );

  logger.info?.("[clawdstrike] Plugin registered");
}

// Helper functions and types

type PolicyCheckAction =
  | "file_read"
  | "file_write"
  | "network"
  | "network_egress"
  | "command"
  | "command_exec"
  | "tool_call";

type EventType =
  | "file_read"
  | "file_write"
  | "command_exec"
  | "network_egress"
  | "tool_call"
  | "patch_apply"
  | "secret_access";

interface LocalPolicyEvent {
  eventId: string;
  eventType: EventType;
  timestamp: string;
  data: Record<string, unknown>;
}

interface Decision {
  status?: 'allow' | 'warn' | 'deny';
  denied?: boolean;
  warn?: boolean;
  guard?: string;
  reason?: string;
  message?: string;
}

function buildEvent(action: PolicyCheckAction, resource: string): LocalPolicyEvent {
  const now = new Date();
  const eventId = `policy-check-${now.getTime()}-${Math.random().toString(36).slice(2, 8)}`;
  const timestamp = now.toISOString();

  switch (action) {
    case "file_read":
      return {
        eventId,
        eventType: "file_read",
        timestamp,
        data: { type: "file", path: resource, operation: "read" },
      };
    case "file_write":
      return {
        eventId,
        eventType: "file_write",
        timestamp,
        data: { type: "file", path: resource, operation: "write" },
      };
    case "network":
    case "network_egress": {
      const { host, port, url } = parseNetworkTarget(resource);
      return {
        eventId,
        eventType: "network_egress",
        timestamp,
        data: { type: "network", host, port, url },
      };
    }
    case "command":
    case "command_exec": {
      const parts = resource.trim().split(/\s+/).filter(Boolean);
      const [command, ...args] = parts;
      return {
        eventId,
        eventType: "command_exec",
        timestamp,
        data: { type: "command", command: command ?? "", args },
      };
    }
    case "tool_call":
    default:
      return {
        eventId,
        eventType: "tool_call",
        timestamp,
        data: { type: "tool", toolName: resource, parameters: {} },
      };
  }
}

function parseNetworkTarget(target: string): { host: string; port: number; url?: string } {
  const trimmed = (target ?? "").trim();
  if (!trimmed) return { host: "", port: 0 };

  try {
    const parsed = new URL(trimmed);
    const port = parsed.port
      ? Number.parseInt(parsed.port, 10)
      : parsed.protocol === "http:"
        ? 80
        : 443;
    return { host: parsed.hostname, port, url: trimmed };
  } catch {
    try {
      const parsed = new URL(`https://${trimmed}`);
      const port = parsed.port ? Number.parseInt(parsed.port, 10) : 443;
      return { host: parsed.hostname, port, url: `https://${trimmed}` };
    } catch {
      return { host: trimmed.split("/")[0] ?? trimmed, port: 443 };
    }
  }
}

function formatDecision(decision: Decision): string {
  const isDenied = decision.status === 'deny' || decision.denied;
  const isWarn = decision.status === 'warn' || decision.warn;
  if (isDenied) {
    const guard = decision.guard ? ` by ${decision.guard}` : "";
    const reason = decision.reason ? `: ${decision.reason}` : "";
    return `Denied${guard}${reason}`;
  }
  if (isWarn) {
    const msg = decision.message ?? decision.reason ?? "Policy warning";
    return `Warning: ${msg}`;
  }
  return "Action allowed";
}

function getSuggestion(action: string, resource: string): string {
  if ((action === "file_write" || action === "file_read") && resource.includes(".ssh")) {
    return "SSH keys are protected. Consider using a different credential storage method.";
  }
  if ((action === "file_write" || action === "file_read") && resource.includes(".aws")) {
    return "AWS credentials are protected. Use environment variables or IAM roles instead.";
  }
  if (action === "network_egress" || action === "network") {
    return "Try using an allowed domain like api.github.com or pypi.org.";
  }
  if (
    (action === "command_exec" || action === "command") &&
    resource.includes("sudo")
  ) {
    return "Privileged commands are restricted. Try running without sudo.";
  }
  if (
    (action === "command_exec" || action === "command") &&
    (resource.includes("rm -rf") || resource.includes("dd if="))
  ) {
    return "Destructive commands are blocked. Consider safer alternatives.";
  }
  return "Consider an alternative approach that works within the security policy.";
}
