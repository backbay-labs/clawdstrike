import type { AdapterConfig } from "./adapter.js";
import type { AuditEvent } from "./audit.js";
import type { SecurityContext } from "./context.js";

export async function emitAuditEvent(
  context: SecurityContext,
  config: AdapterConfig,
  event: AuditEvent,
  onError?: (error: Error) => void,
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
    onError?.(error as Error);
  }
}
