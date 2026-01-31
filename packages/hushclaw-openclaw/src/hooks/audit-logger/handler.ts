/**
 * @hushclaw/openclaw - Audit Logger Hook Handler
 *
 * Logs security events for audit and compliance.
 */

import type {
  HookHandler,
  HookEvent,
  ToolResultPersistEvent,
  HushClawConfig,
  Logger,
} from '../../types.js';
import { mergeConfig } from '../../config.js';

/** Logger instance */
let logger: Logger | null = null;

/**
 * Initialize the hook with configuration
 */
export function initialize(config: HushClawConfig): void {
  const mergedConfig = mergeConfig(config);
  logger = createAuditLogger(mergedConfig.logLevel);
}

/**
 * Hook handler for audit logging
 */
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'tool_result_persist') {
    return;
  }

  const toolEvent = event as ToolResultPersistEvent;
  const log = logger ?? createAuditLogger('info');

  const auditEntry = {
    timestamp: new Date().toISOString(),
    eventType: 'tool_result_persist',
    sessionId: toolEvent.context.sessionId,
    toolName: toolEvent.context.toolResult.toolName,
    hasError: !!toolEvent.context.toolResult.error,
    messageCount: toolEvent.messages.length,
  };

  // Log based on outcome
  if (toolEvent.context.toolResult.error) {
    log.warn('[AUDIT] Tool blocked', auditEntry);
  } else if (toolEvent.messages.some((m) => m.includes('Warning'))) {
    log.info('[AUDIT] Tool executed with warnings', auditEntry);
  } else {
    log.debug('[AUDIT] Tool executed', auditEntry);
  }
};

/**
 * Create audit logger with appropriate level filtering
 */
function createAuditLogger(level: string): Logger {
  const levels = ['debug', 'info', 'warn', 'error'];
  const minLevel = levels.indexOf(level);

  return {
    debug: (...args) => {
      if (minLevel <= 0) console.debug(...args);
    },
    info: (...args) => {
      if (minLevel <= 1) console.info(...args);
    },
    warn: (...args) => {
      if (minLevel <= 2) console.warn(...args);
    },
    error: (...args) => {
      if (minLevel <= 3) console.error(...args);
    },
  };
}

export default handler;
