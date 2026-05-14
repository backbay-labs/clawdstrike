import { createHash } from "node:crypto";

import type {
  BrokerExecutionContext,
  BrokerExecutionResult,
  BrokerExecutor,
} from "@clawdstrike/adapter-core";
import type {
  BrokerExecutionIntent,
  BrokerExecutionResponse,
  BrokerExecutionStreamResponse,
} from "@clawdstrike/broker-client";

export interface SecretBrokerClientLike {
  execute(intent: BrokerExecutionIntent): Promise<BrokerExecutionResponse>;
  executeStream?(intent: BrokerExecutionIntent): Promise<BrokerExecutionStreamResponse>;
}

export interface OpenAIBrokerOptions {
  client: SecretBrokerClientLike;
  secretRef: string;
  toolName?: string;
  baseUrl?: string;
  path?: string;
}

const DEFAULT_TOOL_NAME = "responses.create";
const DEFAULT_BASE_URL = "https://api.openai.com";
const DEFAULT_PATH = "/v1/responses";

export function createOpenAIBrokerExecutor(options: OpenAIBrokerOptions): BrokerExecutor {
  const toolName = options.toolName ?? DEFAULT_TOOL_NAME;
  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  const path = options.path ?? DEFAULT_PATH;

  return {
    execute: async (context: BrokerExecutionContext): Promise<BrokerExecutionResult | null> => {
      if (context.toolName !== toolName) {
        return null;
      }

      const requestPayload = normalizeOpenAIRequestBody(context.dispatchInput);
      const body = JSON.stringify(requestPayload);
      const intent: BrokerExecutionIntent = {
        provider: "openai",
        secretRef: options.secretRef,
        request: {
          url: `${baseUrl}${path}`,
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body,
          bodySha256: sha256Hex(body),
        },
        sessionId: context.securityContext.sessionId,
        endpointAgentId: stringMetadata(context, "endpointAgentId"),
        runtimeAgentId: stringMetadata(context, "runtimeAgentId"),
        runtimeAgentKind: stringMetadata(context, "runtimeAgentKind"),
        originFingerprint: stringMetadata(context, "originFingerprint"),
      };

      if (wantsStreamingOpenAIRequest(requestPayload)) {
        if (!options.client.executeStream) {
          throw new Error("BROKER_OPENAI_STREAM_UNAVAILABLE");
        }
        const response = await options.client.executeStream(intent);
        return {
          replacementResult: response.body,
          metadata: {
            executionId: response.executionId,
            capabilityId: response.capabilityId,
            brokerStatus: response.status,
            brokerContentType: response.contentType,
          },
        };
      }

      const response = await options.client.execute(intent);

      if (!response.body) {
        throw new Error("BROKER_OPENAI_EMPTY_BODY");
      }

      return {
        replacementResult: JSON.parse(response.body),
        metadata: {
          executionId: response.executionId,
          capabilityId: response.capabilityId,
          brokerStatus: response.status,
        },
      };
    },
  };
}

function normalizeOpenAIRequestBody(input: unknown): unknown {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("BROKER_OPENAI_INPUT_INVALID");
  }

  const record = input as Record<string, unknown>;
  if (record.body !== undefined) {
    return record.body;
  }
  return record;
}

function wantsStreamingOpenAIRequest(input: unknown): boolean {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return false;
  }

  const stream = (input as Record<string, unknown>).stream;
  return stream === true;
}

function stringMetadata(
  context: BrokerExecutionContext,
  key: string,
): string | undefined {
  const value = context.securityContext.metadata?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}
