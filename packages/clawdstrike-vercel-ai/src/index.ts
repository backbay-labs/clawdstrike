export type { VercelAiToolLike, VercelAiToolSet } from './tools.js';
export { secureTools } from './tools.js';

export type { VercelAiInterceptorConfig } from './vercel-ai-interceptor.js';
export { createVercelAiInterceptor } from './vercel-ai-interceptor.js';

export { ClawdstrikeBlockedError, ClawdstrikePromptSecurityError, type PromptSecurityBlockKind } from './errors.js';

export type {
  ClawdstrikeMiddleware,
  CreateClawdstrikeMiddlewareOptions,
  PromptSecurityMode,
  SecureToolsOptions,
  VercelAiClawdstrikeConfig,
  VercelAiPromptSecurityConfig,
} from './middleware.js';
export { createClawdstrikeMiddleware } from './middleware.js';

export type { StreamChunk, StreamingToolGuardOptions } from './streaming-tool-guard.js';
export { StreamingToolGuard } from './streaming-tool-guard.js';

export { VercelAIAdapter } from './vercel-ai-adapter.js';
