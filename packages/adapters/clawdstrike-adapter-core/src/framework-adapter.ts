import type {
  AdapterConfig,
  FrameworkAdapter,
  FrameworkHooks,
  GenericInboundMessage,
  GenericToolCall,
  SessionSummary,
} from "./adapter.js";
import { BaseToolInterceptor } from "./base-tool-interceptor.js";
import { createSecurityContext, type SecurityContext } from "./context.js";
import type { PolicyEngineLike } from "./engine.js";
import { createSessionSummary } from "./finalize-context.js";
import { FrameworkToolBoundary } from "./framework-tool-boundary.js";
import { allowInboundBypass, interceptInboundMessage } from "./inbound-message-interceptor.js";
import type { ProcessedOutput } from "./interceptor.js";

export function createFrameworkAdapter(
  framework: string,
  engine: PolicyEngineLike,
  config?: AdapterConfig,
): FrameworkAdapter {
  let currentConfig: AdapterConfig = config ?? {};
  let interceptor = new BaseToolInterceptor(engine, currentConfig);

  return {
    name: framework,
    version: "0.1.1", // TODO: derive from package.json at build time

    async initialize(newConfig: AdapterConfig): Promise<void> {
      currentConfig = newConfig;
      interceptor = new BaseToolInterceptor(engine, currentConfig);
    },

    createContext(metadata: Record<string, unknown> = {}): SecurityContext {
      return createSecurityContext({
        metadata: { framework, ...metadata },
      });
    },

    async interceptToolCall(context: SecurityContext, toolCall: GenericToolCall) {
      return await interceptor.beforeExecute(toolCall.name, toolCall.parameters, context);
    },

    async processOutput(
      context: SecurityContext,
      toolCall: GenericToolCall,
      output: unknown,
    ): Promise<ProcessedOutput> {
      return await interceptor.afterExecute(toolCall.name, toolCall.parameters, output, context);
    },

    async interceptInboundMessage(context: SecurityContext, message: GenericInboundMessage) {
      if (!currentConfig.inbound?.enabled) {
        return allowInboundBypass();
      }

      return interceptInboundMessage(engine, currentConfig, context, message);
    },

    async finalizeContext(context: SecurityContext): Promise<SessionSummary> {
      return createSessionSummary(context, currentConfig);
    },

    getEngine(): PolicyEngineLike {
      return engine;
    },

    getHooks(): FrameworkHooks {
      return {
        createCallbackHandler: () =>
          new FrameworkToolBoundary(framework, { interceptor, config: currentConfig }),
        wrapTool: (tool) => tool,
        injectIntoContext: (ctx) => ctx,
        extractFromContext: () => ({}),
      };
    },
  };
}
