import { useChat } from '@ai-sdk/react';
import type { ChatInit, UIMessage } from 'ai';
import { useCallback, useMemo, useState } from 'react';

import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type { Decision, PolicyEngineLike, SecurityContext } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from '../errors.js';
import type { VercelAiClawdstrikeConfig } from '../middleware.js';

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

export type UseSecureChatOptions<UI_MESSAGE extends UIMessage = UIMessage> = UseChatInitOptions<UI_MESSAGE> & {
  engine: PolicyEngineLike;
  securityConfig?: VercelAiClawdstrikeConfig;
  context?: SecurityContext;
  createContext?: () => SecurityContext;
};

export function useSecureChat<UI_MESSAGE extends UIMessage = UIMessage>(
  options: UseSecureChatOptions<UI_MESSAGE>,
) {
  const { engine, securityConfig, context: providedContext, createContext, onToolCall, ...chatOptions } = options;

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
    return createSecurityContext({ metadata: { framework: 'vercel-ai', react: true } });
  }, [createContext, providedContext]);

  const [securityStatus, setSecurityStatus] = useState<SecurityStatus>({
    blocked: false,
    blockedTools: [],
    checkCount: 0,
    violationCount: 0,
  });

  const [lastDecision, setLastDecision] = useState<Decision | null>(null);

  const secureToolCall = useCallback(
    async ({ toolCall }: { toolCall: { toolName: string; args: unknown } }) => {
      const result = await interceptor.beforeExecute(toolCall.toolName, toolCall.args, context);
      const decision = result.decision;

      setLastDecision(decision);
      const isWarn = decision.status === 'warn';
      setSecurityStatus(prev => ({
        ...prev,
        checkCount: prev.checkCount + 1,
        blocked: !result.proceed,
        warning: isWarn ? decision.message ?? decision.reason : undefined,
        lastDecision: decision,
        violationCount: prev.violationCount + (!result.proceed ? 1 : 0),
        blockedTools: !result.proceed
          ? Array.from(new Set([...prev.blockedTools, toolCall.toolName]))
          : prev.blockedTools,
      }));

      if (!result.proceed) {
        throw new ClawdstrikeBlockedError(toolCall.toolName, decision);
      }

      return onToolCall?.({ toolCall } as any);
    },
    [context, interceptor, onToolCall],
  );

  const chatHelpers = useChat({
    ...chatOptions,
    onToolCall: secureToolCall as any,
  });

  const clearBlockedTools = useCallback(() => {
    setSecurityStatus(prev => ({
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
