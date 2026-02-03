export type { VercelAiToolLike, VercelAiToolSet } from './tools.js';
export { secureTools } from './tools.js';

export type { VercelAiInterceptorConfig } from './vercel-ai-interceptor.js';
export { createVercelAiInterceptor } from './vercel-ai-interceptor.js';

export { ClawdstrikeBlockedError } from './errors.js';

export type {
  ClawdstrikeMiddleware,
  CreateClawdstrikeMiddlewareOptions,
  SecureToolsOptions,
  VercelAiClawdstrikeConfig,
} from './middleware.js';
export { createClawdstrikeMiddleware } from './middleware.js';

export { VercelAIAdapter } from './vercel-ai-adapter.js';
