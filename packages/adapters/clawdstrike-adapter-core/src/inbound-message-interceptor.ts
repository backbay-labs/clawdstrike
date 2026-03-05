import { createHash } from "node:crypto";

import type {
  AdapterConfig,
  GenericInboundMessage,
  InboundInterceptResult,
  InboundMessageTranslationInput,
} from "./adapter.js";
import type { AuditEvent, AuditEventType } from "./audit.js";
import { sanitizeAuditText } from "./audit-sanitizer.js";
import type { SecurityContext } from "./context.js";
import type { PolicyEngineLike } from "./engine.js";
import { allowDecision, denyDecision, warnDecision, type Decision, type PolicyEvent } from "./types.js";

const DEFAULT_CUSTOM_TYPE = "untrusted_text";
const DEFAULT_REDACTED_SNIPPET_LENGTH = 160;

function generateEventId(sessionId: string): string {
  return `inbound-${sessionId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function fingerprintText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function defaultInboundEvent(
  context: SecurityContext,
  message: GenericInboundMessage,
  config: AdapterConfig,
): PolicyEvent {
  const customType = config.inbound?.customType ?? DEFAULT_CUSTOM_TYPE;

  return {
    eventId: generateEventId(context.sessionId),
    eventType: "custom",
    timestamp: message.timestamp.toISOString(),
    sessionId: context.sessionId,
    data: {
      type: "custom",
      customType,
      source: message.source,
      text: message.text,
      ...(message.senderId ? { senderId: message.senderId } : {}),
      ...(message.senderName ? { senderName: message.senderName } : {}),
      ...(message.channel ? { channel: message.channel } : {}),
      ...(message.chatType ? { chatType: message.chatType } : {}),
      ...(message.metadata ? { metadata: message.metadata } : {}),
    },
    metadata: {
      ...(context.metadata ?? {}),
      source: "adapter-core.inbound",
      inbound: true,
      messageId: message.id,
      messageSource: message.source,
      ...(message.senderId ? { senderId: message.senderId } : {}),
      ...(message.senderName ? { senderName: message.senderName } : {}),
      ...(message.channel ? { channel: message.channel } : {}),
      ...(message.chatType ? { chatType: message.chatType } : {}),
    },
  };
}

function buildInboundAuditDetails(
  message: GenericInboundMessage,
  engine: PolicyEngineLike,
  config: AdapterConfig,
): Record<string, unknown> {
  const contentMode = config.inbound?.auditContentMode ?? "hash";
  const details: Record<string, unknown> = {
    messageId: message.id,
    source: message.source,
    senderId: message.senderId,
    senderName: message.senderName,
    channel: message.channel,
    chatType: message.chatType,
    contentHash: fingerprintText(message.text),
  };

  if (contentMode === "raw") {
    details.content = sanitizeAuditText(
      message.text,
      engine.redactSecrets,
      config.audit?.redactPII,
    );
  } else if (contentMode === "redacted_snippet") {
    const length = config.inbound?.redactedSnippetLength ?? DEFAULT_REDACTED_SNIPPET_LENGTH;
    const sanitized = sanitizeAuditText(
      message.text,
      engine.redactSecrets,
      config.audit?.redactPII,
    );
    details.contentSnippet = sanitized.slice(0, Math.max(0, length));
    details.contentSnippetTruncated = sanitized.length > length;
  }

  return details;
}

function extractSanitizedText(decision: Extract<Decision, { status: "sanitize" }>): string | null {
  if (typeof decision.sanitized === "string") return decision.sanitized;

  const details =
    typeof decision.details === "object" && decision.details !== null
      ? (decision.details as Record<string, unknown>)
      : null;

  const fromDetails = details?.sanitized_text;
  return typeof fromDetails === "string" ? fromDetails : null;
}

async function emitAuditEvent(
  context: SecurityContext,
  config: AdapterConfig,
  event: AuditEvent,
  onError: (error: Error) => void,
): Promise<void> {
  if (config.audit?.enabled === false) return;

  const allowedEvents = config.audit?.events;
  if (allowedEvents && !allowedEvents.includes(event.type)) return;

  context.addAuditEvent(event);

  const logger = config.audit?.logger;
  if (!logger) return;

  try {
    await logger.log(event);
  } catch (error) {
    onError(error as Error);
  }
}

function decisionToInboundAuditType(decision: Decision): AuditEventType {
  switch (decision.status) {
    case "deny":
      return "inbound_message_blocked";
    case "warn":
      return "inbound_message_warning";
    case "sanitize":
      return "inbound_message_sanitized";
    default:
      return "inbound_message_allowed";
  }
}

export async function interceptInboundMessage(
  engine: PolicyEngineLike,
  config: AdapterConfig,
  context: SecurityContext,
  message: GenericInboundMessage,
): Promise<InboundInterceptResult> {
  if (!config.inbound?.enabled) {
    return allowInboundBypass();
  }

  const startTime = Date.now();
  const failMode = config.inbound?.failMode ?? "open";

  try {
    const translationInput: InboundMessageTranslationInput = {
      framework: String(context.metadata?.framework ?? message.source ?? "generic"),
      message,
      sessionId: context.sessionId,
      contextMetadata: context.metadata,
    };

    const translated = config.inbound?.translateMessage?.(translationInput) ?? null;
    const event = translated ?? defaultInboundEvent(context, message, config);
    event.metadata = {
      ...(context.metadata ?? {}),
      ...(event.metadata ?? {}),
    };

    const evaluatedDecision = await Promise.resolve(engine.evaluate(event));
    const sanitizedText =
      evaluatedDecision.status === "sanitize" ? extractSanitizedText(evaluatedDecision) : null;
    const decision: Decision =
      evaluatedDecision.status === "sanitize" && sanitizedText === null
        ? denyDecision({
            reason_code: "ADC_POLICY_DENY",
            guard: evaluatedDecision.guard ?? "inbound_message",
            severity: "high",
            message:
              evaluatedDecision.message ??
              evaluatedDecision.reason ??
              "Inbound message sanitize decision missing sanitized replacement text",
          })
        : evaluatedDecision;

    const auditDetails = buildInboundAuditDetails(message, engine, config);
    if (evaluatedDecision.status === "sanitize" && sanitizedText === null) {
      auditDetails.sanitizeFallback = "deny_missing_replacement";
    }
    await emitAuditEvent(
      context,
      config,
      {
        id: `${event.eventId}-${decision.status}`,
        type: decisionToInboundAuditType(decision),
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        decision,
        details: auditDetails,
      },
      (error) => {
        config.handlers?.onError?.(error);
      },
    );

    if (decision.status === "deny") {
      context.violationCount++;
      context.recordBlocked("inbound_message", decision);
      return {
        proceed: false,
        decision,
        duration: Date.now() - startTime,
      };
    }

    if (decision.status === "sanitize") {
      return {
        proceed: true,
        decision,
        modifiedMessage: {
          ...message,
          text: sanitizedText ?? message.text,
        },
        warning: decision.message ?? decision.reason,
        duration: Date.now() - startTime,
      };
    }

    return {
      proceed: true,
      decision,
      warning: decision.status === "warn" ? decision.message ?? decision.reason : undefined,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    const messageText = error instanceof Error ? error.message : String(error);
    const decision =
      failMode === "closed"
        ? denyDecision({
            reason_code: "ADC_GUARD_ERROR",
            guard: "inbound_message",
            severity: "high",
            message: `Inbound evaluation failed: ${messageText}`,
          })
        : warnDecision({
            reason_code: "ADC_GUARD_ERROR",
            guard: "inbound_message",
            severity: "medium",
            message: `Inbound evaluation failed (fail-open): ${messageText}`,
          });

    const auditDetails = {
      ...buildInboundAuditDetails(message, engine, config),
      error: messageText,
      failMode,
    };

    await emitAuditEvent(
      context,
      config,
      {
        id: `${context.id}-${Date.now()}-inbound-error`,
        type: "inbound_message_error",
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        decision,
        details: auditDetails,
      },
      (logError) => {
        config.handlers?.onError?.(logError);
      },
    );

    config.handlers?.onError?.(error as Error);
    if (decision.status === "deny") {
      context.violationCount++;
      context.recordBlocked("inbound_message", decision);
    }

    return {
      proceed: decision.status !== "deny",
      decision,
      warning: decision.status === "warn" ? decision.message ?? decision.reason : undefined,
      duration: Date.now() - startTime,
    };
  }
}

export function allowInboundBypass(message = "Inbound interception disabled"): InboundInterceptResult {
  return {
    proceed: true,
    decision: allowDecision({ guard: "inbound_disabled", message }),
    duration: 0,
  };
}
