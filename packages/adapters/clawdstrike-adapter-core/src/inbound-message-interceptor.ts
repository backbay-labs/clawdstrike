import { createHash } from "node:crypto";

import type {
  AdapterConfig,
  GenericInboundMessage,
  InboundInterceptResult,
  InboundMessageTranslationInput,
} from "./adapter.js";
import type { AuditEventType } from "./audit.js";
import { emitAuditEvent } from "./audit-event-emitter.js";
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
  const redactSecrets = engine.redactSecrets?.bind(engine);
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
      redactSecrets,
      config.audit?.redactPII,
    );
  } else if (contentMode === "redacted_snippet") {
    const length = config.inbound?.redactedSnippetLength ?? DEFAULT_REDACTED_SNIPPET_LENGTH;
    const sanitized = sanitizeAuditText(
      message.text,
      redactSecrets,
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
      const sanitizedReplacement = sanitizedText;
      if (sanitizedReplacement === null) {
        throw new Error("Invariant violation: sanitize decision missing replacement text");
      }
      return {
        proceed: true,
        decision,
        modifiedMessage: {
          ...message,
          text: sanitizedReplacement,
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
    const runtimeError = error instanceof Error ? error : new Error(String(error));
    const messageText = runtimeError.message;
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

    let auditDetails: Record<string, unknown>;
    try {
      auditDetails = {
        ...buildInboundAuditDetails(message, engine, config),
        error: messageText,
        failMode,
      };
    } catch (auditError) {
      const auditBuildError =
        auditError instanceof Error ? auditError : new Error(String(auditError));
      let fallbackContentHash: string | undefined;
      try {
        fallbackContentHash = fingerprintText(message.text);
      } catch (hashError) {
        const fallbackHashError =
          hashError instanceof Error ? hashError : new Error(String(hashError));
        config.handlers?.onError?.(fallbackHashError);
      }
      auditDetails = {
        messageId: message.id,
        source: message.source,
        senderId: message.senderId,
        senderName: message.senderName,
        channel: message.channel,
        chatType: message.chatType,
        ...(fallbackContentHash ? { contentHash: fallbackContentHash } : {}),
        error: messageText,
        failMode,
        auditDetailsError: auditBuildError.message,
      };
      config.handlers?.onError?.(auditBuildError);
    }

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

    config.handlers?.onError?.(runtimeError);
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
