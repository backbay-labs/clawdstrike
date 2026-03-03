/**
 * Watch mode — subscribe to NATS for live envelope events,
 * feed them through the CorrelationEngine, and emit alerts.
 *
 * Requires the optional `nats` peer dependency.
 */

import { parseEnvelope } from "./timeline.js";
import { CorrelationEngine } from "./correlate/engine.js";
import { WatchError } from "./errors.js";
import { buildNatsConnectOptions } from "./nats.js";
import type {
  Alert,
  TimelineEvent,
  WatchConfig,
  WatchStats,
} from "./types.js";

const NATS_SUBJECT = "clawdstrike.sdr.fact.>";

/**
 * Run a live watch session against a NATS server.
 *
 * Subscribes to the `clawdstrike.sdr.fact.>` subject, parses spine envelopes
 * into timeline events, feeds them through a CorrelationEngine, and invokes
 * the `onAlert` callback whenever a correlation rule fires.
 *
 * @param config - Watch configuration (NATS url, rules, etc.)
 * @param onAlert - Called for every fired alert.
 * @param onEvent - Optional callback for every parsed event.
 * @param signal - AbortSignal to stop watching.
 * @returns Final watch statistics.
 */
export async function runWatch(
  config: WatchConfig,
  onAlert: (alert: Alert) => void,
  onEvent?: (event: TimelineEvent) => void,
  signal?: AbortSignal,
): Promise<WatchStats> {
  // Dynamic import — gives a clear error if nats is not installed.
  // Use a variable to prevent TypeScript from resolving the module at compile time.
  const natsModuleName = "nats";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let natsModule: any;
  try {
    natsModule = await import(natsModuleName);
  } catch {
    throw new WatchError(
      "The 'nats' package is required for watch mode. Install it with: npm install nats",
    );
  }

  const engine = new CorrelationEngine(config.rules);
  const stats = {
    eventsProcessed: 0,
    alertsTriggered: 0,
  };
  const startTime = new Date();

  // Connect to NATS.
  const nc = await natsModule.connect(
    await buildNatsConnectOptions(natsModule, config.natsUrl, config.natsCreds),
  );

  const sub = nc.subscribe(NATS_SUBJECT);

  // If an AbortSignal is provided, drain subscription on abort.
  if (signal) {
    const onAbort = () => {
      sub.unsubscribe();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  }

  try {
    for await (const msg of sub) {
      if (signal?.aborted) break;

      let envelope: unknown;
      try {
        envelope = JSON.parse(new TextDecoder().decode(msg.data));
      } catch {
        continue; // skip unparseable messages
      }

      const event = parseEnvelope(envelope);
      if (!event) continue;

      stats.eventsProcessed++;
      onEvent?.(event);

      // Feed to the correlation engine.
      const alerts = engine.processEvent(event, config.maxWindow);
      for (const alert of alerts) {
        stats.alertsTriggered++;
        onAlert(alert);
      }
    }

    // Flush remaining partial windows on shutdown.
    const remaining = engine.flush();
    for (const alert of remaining) {
      stats.alertsTriggered++;
      onAlert(alert);
    }
  } finally {
    await nc.drain();
  }

  return {
    eventsProcessed: stats.eventsProcessed,
    alertsTriggered: stats.alertsTriggered,
    startTime,
  };
}
