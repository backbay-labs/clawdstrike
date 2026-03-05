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
    (((event as { type?: unknown }).type === "inbound_message") ||
      ((event as { type?: unknown }).type === "user_input"))
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
    const sessionId = event.context.sessionId || hookCtx?.sessionKey || hookCtx?.agentId || "openclaw-runtime";

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
      ? result.decision.message ?? result.decision.reason
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

const handler: HookHandler = async (
  event: HookEvent | ModernInboundEvent,
  hookCtx?: OpenClawHookContext,
): Promise<void | BeforeToolCallHookResult> => {
  const normalized = normalizeInboundMessage(event, hookCtx);
  if (!normalized) return;
  const inboundConfig = resolveInboundConfig(currentConfig);
  if (inboundConfig.enabled === false) return;

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
    },
  });

  const result = await interceptInboundMessage(engine, adapterConfig, context, normalized.message);
  return applyDecisionToEvent(event, result);
};

export default handler;
