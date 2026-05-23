import { useChat } from "@ai-sdk/react";
import type { Decision, PolicyEngineLike, SecurityContext } from "@clawdstrike/adapter-core";
import { BaseToolInterceptor, createSecurityContext } from "@clawdstrike/adapter-core";
import type { ChatInit, ChatOnToolCallCallback, UIMessage } from "ai";
import { useCallback, useMemo, useState } from "react";

import { ClawdstrikeBlockedError } from "../errors.js";
import type { VercelAiClawdstrikeConfig } from "../middleware.js";

export interface SecurityStatus {
  blocked: boolean;
  warning?: string;
  lastDecision?: Decision;
  blockedTools: string[];
  checkCount: number;
  violationCount: number;
}

type UseChatInitOptions<UI_MESSAGE extends UIMessage> = ChatInit<UI_MESSAGE> & {
  experimental_throttle?: number;
  resume?: boolean;
};

/**
 * Shape of the `toolCall` argument delivered to `ChatOnToolCallCallback`
 * in `@ai-sdk/react@3+`. The exported `ChatOnToolCallCallback` type is
 * parameterized over a `UI_MESSAGE`'s tools generic that the wrapper
 * cannot see at compile time (the engine is opaque), so we narrow at
 * runtime to the structural slice we actually consume — matching
 * `BaseToolCall & { toolName: string; input: unknown }` from `ai`'s
 * `DynamicToolCall` (the always-permitted shape).
 */
type SecureToolCallArg = {
  toolCall: { toolCallId: string; toolName: string; input: unknown };
};

export type UseSecureChatOptions<UI_MESSAGE extends UIMessage = UIMessage> =
  UseChatInitOptions<UI_MESSAGE> & {
    engine: PolicyEngineLike;
    securityConfig?: VercelAiClawdstrikeConfig;
    context?: SecurityContext;
    createContext?: () => SecurityContext;
  };

export function useSecureChat<UI_MESSAGE extends UIMessage = UIMessage>(
  options: UseSecureChatOptions<UI_MESSAGE>,
) {
  const {
    engine,
    securityConfig,
    context: providedContext,
    createContext,
    onToolCall,
    ...chatOptions
  } = options;

  const interceptor = useMemo(
    () => new BaseToolInterceptor(engine, securityConfig ?? {}),
    [engine, securityConfig],
  );

  const context = useMemo(() => {
    if (providedContext) {
      return providedContext;
    }
    if (createContext) {
      return createContext();
    }
    return createSecurityContext({ metadata: { framework: "vercel-ai", react: true } });
  }, [createContext, providedContext]);

  const [securityStatus, setSecurityStatus] = useState<SecurityStatus>({
    blocked: false,
    blockedTools: [],
    checkCount: 0,
    violationCount: 0,
  });

  const [lastDecision, setLastDecision] = useState<Decision | null>(null);

  const secureToolCall = useCallback(
    async ({ toolCall }: SecureToolCallArg) => {
      const result = await interceptor.beforeExecute(toolCall.toolName, toolCall.input, context);
      const decision = result.decision;

      setLastDecision(decision);
      const isWarn = decision.status === "warn";
      setSecurityStatus((prev) => ({
        ...prev,
        checkCount: prev.checkCount + 1,
        blocked: !result.proceed,
        warning: isWarn ? (decision.message ?? decision.reason) : undefined,
        lastDecision: decision,
        violationCount: prev.violationCount + (!result.proceed ? 1 : 0),
        blockedTools: !result.proceed
          ? Array.from(new Set([...prev.blockedTools, toolCall.toolName]))
          : prev.blockedTools,
      }));

      if (!result.proceed) {
        throw new ClawdstrikeBlockedError(toolCall.toolName, decision);
      }

      // The user-supplied `onToolCall` from `ChatInit<UI_MESSAGE>` is
      // parameterized on the chat's tools generic; forward through the
      // exported `ChatOnToolCallCallback` type by structural cast.
      return (onToolCall as ChatOnToolCallCallback | undefined)?.({ toolCall });
    },
    [context, interceptor, onToolCall],
  );

  const chatHelpers = useChat({
    ...chatOptions,
    onToolCall: secureToolCall as ChatOnToolCallCallback<UI_MESSAGE>,
  });

  const clearBlockedTools = useCallback(() => {
    setSecurityStatus((prev) => ({
      ...prev,
      blockedTools: [],
    }));
  }, []);

  const preflightCheck = useCallback(
    async (toolName: string, params: unknown): Promise<Decision> => {
      const result = await interceptor.beforeExecute(toolName, params, context);
      return result.decision;
    },
    [context, interceptor],
  );

  return {
    ...chatHelpers,
    securityStatus,
    blockedTools: securityStatus.blockedTools,
    lastDecision,
    clearBlockedTools,
    preflightCheck,
  };
}
