import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type {
  AdapterConfig,
  GenericInboundMessage,
  InboundConfig,
  InboundInterceptResult,
} from "@clawdstrike/adapter-core";
import { createSecurityContext, interceptInboundMessage } from "@clawdstrike/adapter-core";

import { getSharedEngine, initializeEngine } from "../../engine-holder.js";
import type {
  BeforeToolCallHookResult,
  ClawdstrikeConfig,
  HookEvent,
  HookHandler,
  InboundMessageEvent,
  OpenClawHookContext,
  PolicyEvent,
} from "../../types.js";

type ModernInboundEvent = {
  message?: {
    id?: unknown;
    text?: unknown;
    senderId?: unknown;
    senderName?: unknown;
    channel?: unknown;
    chatType?: unknown;
    timestamp?: unknown;
    metadata?: unknown;
    blocked?: unknown;
  };
  text?: unknown;
  senderId?: unknown;
  senderName?: unknown;
  channel?: unknown;
  chatType?: unknown;
  timestamp?: unknown;
  sessionId?: unknown;
  messages?: unknown;
};

const DEFAULT_SOURCE = "openclaw.inbound_hook";

type OpenClawInboundRuntimeConfig = ClawdstrikeConfig & { inbound?: InboundConfig };

let currentConfig: OpenClawInboundRuntimeConfig = {};

export function refreshRuntimeConfig(config: ClawdstrikeConfig): void {
  currentConfig = config as OpenClawInboundRuntimeConfig;
}

export function initialize(config: ClawdstrikeConfig): void {
  refreshRuntimeConfig(config);
  initializeEngine(config);
}

function isInboundLegacyEvent(event: HookEvent | ModernInboundEvent): event is InboundMessageEvent {
  return (
    typeof event === "object" &&
    event !== null &&
    "type" in event &&
    ((event as { type?: unknown }).type === "inbound_message" ||
      (event as { type?: unknown }).type === "user_input")
  );
}

function isModernInboundEvent(event: HookEvent | ModernInboundEvent): event is ModernInboundEvent {
  if (typeof event !== "object" || event === null) return false;
  if ("type" in event) return false;

  const text = (event as ModernInboundEvent).text;
  const nestedText = (event as ModernInboundEvent).message?.text;
  return typeof text === "string" || typeof nestedText === "string";
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function normalizeChatType(value: unknown): "dm" | "group" | "channel" | undefined {
  if (value === "dm" || value === "group" || value === "channel") {
    return value;
  }
  return undefined;
}

function resolveInboundConfig(config: OpenClawInboundRuntimeConfig): InboundConfig {
  return {
    enabled: false,
    failMode: "open",
    customType: "untrusted_text",
    auditContentMode: "hash",
    ...(config.inbound ?? {}),
  };
}

function extractMessageList(event: HookEvent | ModernInboundEvent): string[] | null {
  if (isInboundLegacyEvent(event)) return event.messages;

  const maybeMessages = (event as ModernInboundEvent).messages;
  if (Array.isArray(maybeMessages) && maybeMessages.every((entry) => typeof entry === "string")) {
    return maybeMessages as string[];
  }

  return null;
}

function normalizeInboundMessage(
  event: HookEvent | ModernInboundEvent,
  hookCtx?: OpenClawHookContext,
): { sessionId: string; message: GenericInboundMessage } | null {
  if (isInboundLegacyEvent(event)) {
    const raw = event.context.message;
    const text = asString(raw.text);
    if (!text) return null;

    const timestamp = asString(raw.timestamp) ?? event.timestamp;
    const parsedTimestamp = new Date(timestamp);
    const sessionId =
      event.context.sessionId || hookCtx?.sessionKey || hookCtx?.agentId || "openclaw-runtime";

    return {
      sessionId,
      message: {
        id: asString(raw.id) ?? `inbound-${sessionId}-${Date.now()}`,
        text,
        timestamp: Number.isNaN(parsedTimestamp.getTime()) ? new Date() : parsedTimestamp,
        source: DEFAULT_SOURCE,
        senderId: asString(raw.senderId),
        senderName: asString(raw.senderName),
        channel: asString(raw.channel),
        chatType: normalizeChatType(raw.chatType),
        metadata:
          raw.metadata && typeof raw.metadata === "object" && !Array.isArray(raw.metadata)
            ? (raw.metadata as Record<string, unknown>)
            : undefined,
      },
    };
  }

  if (!isModernInboundEvent(event)) return null;

  const text = asString(event.message?.text) ?? asString(event.text);
  if (!text) return null;

  const sessionId =
    asString(event.sessionId) ?? hookCtx?.sessionKey ?? hookCtx?.agentId ?? "openclaw-runtime";
  const timestampRaw = asString(event.message?.timestamp) ?? asString(event.timestamp);
  const parsedTimestamp = timestampRaw ? new Date(timestampRaw) : new Date();

  const senderId = asString(event.message?.senderId) ?? asString(event.senderId);
  const senderName = asString(event.message?.senderName) ?? asString(event.senderName);
  const channel = asString(event.message?.channel) ?? asString(event.channel);
  const chatType = normalizeChatType(event.message?.chatType ?? event.chatType);

  const metadataSource = event.message?.metadata;
  const metadata =
    metadataSource && typeof metadataSource === "object" && !Array.isArray(metadataSource)
      ? (metadataSource as Record<string, unknown>)
      : undefined;

  return {
    sessionId,
    message: {
      id: asString(event.message?.id) ?? `inbound-${sessionId}-${Date.now()}`,
      text,
      timestamp: Number.isNaN(parsedTimestamp.getTime()) ? new Date() : parsedTimestamp,
      source: DEFAULT_SOURCE,
      senderId,
      senderName,
      channel,
      chatType,
      metadata,
    },
  };
}

function applyDecisionToEvent(
  event: HookEvent | ModernInboundEvent,
  result: InboundInterceptResult,
): void | BeforeToolCallHookResult {
  const modernEvent = event as ModernInboundEvent;
  const modernMessage =
    !isInboundLegacyEvent(event) &&
    modernEvent.message &&
    typeof modernEvent.message === "object" &&
    !Array.isArray(modernEvent.message)
      ? modernEvent.message
      : null;
  const messages = extractMessageList(event);
  const decisionWarning =
    result.decision.status === "warn" || result.decision.status === "sanitize"
      ? (result.decision.message ?? result.decision.reason)
      : undefined;
  const warning = result.warning ?? decisionWarning;

  if (!result.proceed || result.decision.status === "deny") {
    const blockReason =
      result.decision.message ?? result.decision.reason ?? "Inbound message blocked by policy";
    if (messages) {
      messages.push(`[clawdstrike] Inbound blocked: ${blockReason}`);
    }
    if (isInboundLegacyEvent(event)) {
      event.context.message.blocked = true;
    } else if (modernMessage) {
      modernMessage.blocked = true;
    }
    return { block: true, blockReason };
  }

  if (result.modifiedMessage && typeof result.modifiedMessage.text === "string") {
    if (isInboundLegacyEvent(event)) {
      event.context.message.text = result.modifiedMessage.text;
    } else if (modernMessage) {
      modernMessage.text = result.modifiedMessage.text;
    } else {
      modernEvent.text = result.modifiedMessage.text;
    }
  }

  if (warning && messages) {
    messages.push(`[clawdstrike] Inbound warning: ${warning}`);
  }

  return;
}

type InboundTelemetryIdentity = {
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
};

function inboundTelemetryIdentity(
  hookCtx: OpenClawHookContext | undefined,
  sessionId: string,
): InboundTelemetryIdentity {
  return {
    hostId: firstInboundString(
      hookCtx?.hostId,
      process.env.CLAWDSTRIKE_HOST_ID,
      process.env.CLAWDSTRIKE_ENDPOINT_ID,
    ),
    userId: firstInboundString(
      hookCtx?.userId,
      process.env.CLAWDSTRIKE_USER_ID,
      process.env.CLAWDSTRIKE_PRINCIPAL_ID,
    ),
    sessionId: firstInboundString(
      sessionId,
      hookCtx?.sessionKey,
      process.env.CLAWDSTRIKE_SESSION_ID,
    ),
    agentId: firstInboundString(hookCtx?.agentId, process.env.CLAWDSTRIKE_AGENT_ID),
    workloadId:
      firstInboundString(hookCtx?.workloadId, process.env.CLAWDSTRIKE_WORKLOAD_ID) ??
      "openclaw-inbound-message",
    approvalId: firstInboundString(hookCtx?.approvalId, process.env.CLAWDSTRIKE_APPROVAL_ID),
  };
}

function firstInboundString(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
}

export function buildInboundPolicyEventForEdr(
  sessionId: string,
  message: GenericInboundMessage,
  inboundConfig: InboundConfig,
  result: InboundInterceptResult,
  identity: InboundTelemetryIdentity = {},
): PolicyEvent {
  const contentHash = sha256Hex(message.text);
  const modifiedText = result.modifiedMessage?.text;
  const modifiedContentHash =
    typeof modifiedText === "string" && modifiedText !== message.text
      ? sha256Hex(modifiedText)
      : undefined;
  const customType = inboundConfig.customType ?? "untrusted_text";

  return {
    eventId: `inbound-edr-${sessionId}-${message.id}-${contentHash.slice(0, 16)}`,
    eventType: "custom",
    timestamp: message.timestamp.toISOString(),
    sessionId,
    data: {
      type: "custom",
      customType,
      source: message.source,
      messageId: message.id,
      contentHash,
      contentSizeBytes: Buffer.byteLength(message.text, "utf8"),
      contentOmitted: true,
      ...(modifiedContentHash
        ? {
            modifiedContentHash,
            modifiedContentSizeBytes: Buffer.byteLength(modifiedText ?? "", "utf8"),
            modifiedContentOmitted: true,
          }
        : {}),
      ...(message.senderId ? { senderId: message.senderId } : {}),
      ...(message.channel ? { channel: message.channel } : {}),
      ...(message.chatType ? { chatType: message.chatType } : {}),
    },
    metadata: {
      collectorKind: "openclaw_inbound_message",
      inbound: true,
      postEvaluation: true,
      rawContentOmitted: true,
      messageId: message.id,
      messageSource: message.source,
      contentHash,
      contentSizeBytes: Buffer.byteLength(message.text, "utf8"),
      ...(modifiedContentHash ? { modifiedContentHash } : {}),
      ...(message.senderId ? { senderId: message.senderId } : {}),
      ...(message.senderName ? { senderNameHash: sha256Hex(message.senderName) } : {}),
      ...(message.channel ? { channel: message.channel } : {}),
      ...(message.chatType ? { chatType: message.chatType } : {}),
      hostId: identity.hostId,
      userId: identity.userId,
      sessionId: identity.sessionId ?? sessionId,
      agentId: identity.agentId,
      workloadId: identity.workloadId ?? "openclaw-inbound-message",
      approvalId: identity.approvalId,
      policyAllowed: result.decision.status !== "deny",
      policyStatus: result.decision.status,
      policyGuard: result.decision.guard,
      policySeverity: result.decision.severity,
      policyReason: result.decision.reason,
      policyMessage: result.decision.message,
      durationMs: result.duration,
    },
  };
}

async function publishInboundPolicyEvent(policyEvent: PolicyEvent): Promise<void> {
  const endpoint = resolvePolicyEventsEndpoint();
  if (!endpoint) return;

  try {
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(250),
      body: JSON.stringify({ events: [policyEvent] }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // Inbound EDR telemetry is evidence enrichment only. Prompt guard
    // enforcement above remains the authoritative block/sanitize path.
  }
}

function resolvePolicyEventsEndpoint(): { url: string; token: string } | null {
  const token = localAgentToken();
  if (!token) return null;

  const explicitUrl = process.env.CLAWDSTRIKE_POLICY_EVENTS_URL?.trim();
  if (explicitUrl) {
    return { url: explicitUrl, token };
  }

  const baseUrl =
    process.env.CLAWDSTRIKE_AGENT_URL?.trim() ??
    process.env.CLAWDSTRIKE_APPROVAL_URL?.trim() ??
    "http://127.0.0.1:9878";
  return {
    url: `${baseUrl.replace(/\/+$/, "")}/api/v1/agent/edr/policy-events`,
    token,
  };
}

function localAgentToken(): string | null {
  const envToken = process.env.CLAWDSTRIKE_AGENT_TOKEN?.trim();
  if (envToken) return envToken;

  const tokenPath =
    process.env.CLAWDSTRIKE_AGENT_TOKEN_PATH?.trim() ??
    join(
      process.env.XDG_CONFIG_HOME?.trim() || join(homedir(), ".config"),
      "clawdstrike",
      "agent-local-token",
    );
  try {
    const token = readFileSync(tokenPath, "utf8").trim();
    return token || null;
  } catch {
    return null;
  }
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

const handler: HookHandler = async (
  event: HookEvent | ModernInboundEvent,
  hookCtx?: OpenClawHookContext,
): Promise<void | BeforeToolCallHookResult> => {
  const normalized = normalizeInboundMessage(event, hookCtx);
  if (!normalized) return;
  const inboundConfig = resolveInboundConfig(currentConfig);
  if (inboundConfig.enabled === false) return;
  const telemetryIdentity = inboundTelemetryIdentity(hookCtx, normalized.sessionId);

  const engine = getSharedEngine(currentConfig);
  const adapterConfig: AdapterConfig = {
    ...currentConfig,
    inbound: inboundConfig,
  };

  const context = createSecurityContext({
    sessionId: normalized.sessionId,
    metadata: {
      framework: "openclaw",
      hookEvent: isInboundLegacyEvent(event) ? event.type : "inbound_message",
      hostId: telemetryIdentity.hostId,
      userId: telemetryIdentity.userId,
      agentId: telemetryIdentity.agentId,
      workloadId: telemetryIdentity.workloadId,
      approvalId: telemetryIdentity.approvalId,
    },
  });

  const result = await interceptInboundMessage(engine, adapterConfig, context, normalized.message);
  void publishInboundPolicyEvent(
    buildInboundPolicyEventForEdr(
      normalized.sessionId,
      normalized.message,
      inboundConfig,
      result,
      telemetryIdentity,
    ),
  );
  return applyDecisionToEvent(event, result);
};

export default handler;
