/**
 * OpenClaw plugin entry point for Clawdstrike
 *
 * Follows the OpenClaw plugin API: https://docs.openclaw.ai/plugin
 */

import { PolicyEngine } from "./policy/engine.js";
import type { ClawdstrikeConfig, CommandBuilder, HookHandler, PolicyEvent } from "./types.js";
import toolPreflightHandler, { initialize as initPreflight } from "./hooks/tool-preflight/handler.js";
import toolGuardHandler, { initialize as initToolGuard } from "./hooks/tool-guard/handler.js";
import agentBootstrapHandler, { initialize as initBootstrap } from "./hooks/agent-bootstrap/handler.js";
import cuaBridgeHandler, { initialize as initCuaBridge } from "./hooks/cua-bridge/handler.js";

// Re-export existing utilities for external use
export * from "./index.js";

/** Minimal OpenClaw plugin API surface used by this plugin. */
interface OpenClawPluginAPI {
  logger?: { info?(...args: unknown[]): void; warn?(...args: unknown[]): void; error?(...args: unknown[]): void };
  config?: { plugins?: { entries?: Record<string, { config?: Record<string, unknown> }> } };
  registerTool(tool: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    execute: (id: string, params: Record<string, unknown>) => Promise<unknown>;
  }): void;
  registerCli(callback: (ctx: { program: { command(name: string): CommandBuilder } }) => void, opts?: { commands?: string[] }): void;
  registerHook?(event: string, handler: HookHandler): void;
  on?(event: string, handler: HookHandler): void;
}

/**
 * Plugin registration function (function format per OpenClaw docs)
 */
export default function clawdstrikePlugin(api: OpenClawPluginAPI) {
  const logger = api.logger ?? console;

  // Load config from plugin settings
  const getConfig = (): ClawdstrikeConfig => {
    const pluginConfig = api.config?.plugins?.entries?.["clawdstrike-security"]?.config ?? {};
    const policy = typeof pluginConfig.policy === 'string' ? pluginConfig.policy : undefined;
    const mode = typeof pluginConfig.mode === 'string' ? pluginConfig.mode : 'deterministic';
    const logLevel = typeof pluginConfig.logLevel === 'string' ? pluginConfig.logLevel : 'info';
    const guards = pluginConfig.guards && typeof pluginConfig.guards === 'object'
      ? pluginConfig.guards as ClawdstrikeConfig['guards']
      : { forbidden_path: true, egress: true, secret_leak: true, patch_integrity: true };
    return {
      policy,
      mode: mode as ClawdstrikeConfig['mode'],
      logLevel: logLevel as ClawdstrikeConfig['logLevel'],
      guards,
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
    async execute(_id: string, params: Record<string, unknown>) {
      try {
        const config = getConfig();
        const engine = new PolicyEngine(config);

        const action = (typeof params.action === 'string' ? params.action : 'tool_call') as PolicyCheckAction;
        const resource = typeof params.resource === 'string' ? params.resource : '';

        const event = buildEvent(action, resource);
        const decision = await engine.evaluate(event);

        const result = {
          status: decision.status,
          guard: decision.guard,
          reason: decision.reason,
          message: formatDecision(decision),
          suggestion: decision.status === 'deny' ? getSuggestion(action, resource) : undefined,
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
    ({ program }) => {
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
        .action(async (...args: unknown[]) => {
          const action = typeof args[0] === 'string' ? args[0] : '';
          const resource = typeof args[1] === 'string' ? args[1] : '';
          const config = getConfig();
          const engine = new PolicyEngine(config);
          const event = buildEvent(action as PolicyCheckAction, resource);
          const decision = await engine.evaluate(event);
          console.log(formatDecision(decision));
          if (decision.status === 'deny') {
            console.log(`Suggestion: ${getSuggestion(action, resource)}`);
            process.exitCode = 1;
          }
        });
    },
    { commands: ["clawdstrike"] }
  );

  // Initialize and register hooks
  const config = getConfig();
  initPreflight(config);
  initToolGuard(config);
  initBootstrap(config);
  initCuaBridge(config);

  if (typeof api.registerHook === 'function') {
    api.registerHook('tool_call', cuaBridgeHandler);
    api.registerHook('tool_call', toolPreflightHandler);
    api.registerHook('tool_result_persist', toolGuardHandler);
    api.registerHook('agent:bootstrap', agentBootstrapHandler);
  } else if (typeof api.on === 'function') {
    api.on('tool_call', cuaBridgeHandler);
    api.on('tool_call', toolPreflightHandler);
    api.on('tool_result_persist', toolGuardHandler);
    api.on('agent:bootstrap', agentBootstrapHandler);
  }

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

interface PluginDecision {
  status: 'allow' | 'warn' | 'deny';
  guard?: string;
  reason?: string;
  message?: string;
}

function buildEvent(action: PolicyCheckAction, resource: string): PolicyEvent {
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

function formatDecision(decision: PluginDecision): string {
  if (decision.status === 'deny') {
    const guard = decision.guard ? ` by ${decision.guard}` : "";
    const reason = decision.reason ? `: ${decision.reason}` : "";
    return `Denied${guard}${reason}`;
  }
  if (decision.status === 'warn') {
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
