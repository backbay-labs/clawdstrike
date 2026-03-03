/**
 * Async generator streaming — subscribe to NATS for live envelope events,
 * feed them through the CorrelationEngine, and yield alerts/events.
 *
 * Requires the optional `nats` peer dependency.
 */

import { parseEnvelope } from './timeline.js';
import { CorrelationEngine } from './correlate/engine.js';
import { WatchError } from './errors.js';
import { buildNatsConnectOptions } from './nats.js';
import type { Alert, TimelineEvent, WatchConfig } from './types.js';

const NATS_SUBJECT = 'clawdstrike.sdr.fact.>';

export interface StreamOptions extends WatchConfig {
  signal?: AbortSignal;
}

export type StreamItem =
  | { type: 'alert'; alert: Alert }
  | { type: 'event'; event: TimelineEvent };

/**
 * Stream alerts as an async iterable. Yields only alerts.
 */
export async function* stream(
  options: StreamOptions,
): AsyncGenerator<Alert, void, undefined> {
  const natsModuleName = 'nats';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let natsModule: any;
  try {
    natsModule = await import(natsModuleName);
  } catch {
    throw new WatchError(
      "The 'nats' package is required for streaming. Install it with: npm install nats",
    );
  }

  const engine = new CorrelationEngine(options.rules);
  const nc = await natsModule.connect(
    await buildNatsConnectOptions(natsModule, options.natsUrl, options.natsCreds),
  );
  const sub = nc.subscribe(NATS_SUBJECT);

  if (options.signal) {
    const onAbort = () => sub.unsubscribe();
    options.signal.addEventListener('abort', onAbort, { once: true });
  }

  try {
    for await (const msg of sub) {
      if (options.signal?.aborted) break;

      let envelope: unknown;
      try {
        envelope = JSON.parse(new TextDecoder().decode(msg.data));
      } catch {
        continue;
      }

      const event = parseEnvelope(envelope);
      if (!event) continue;

      const alerts = engine.processEvent(event, options.maxWindow);
      for (const alert of alerts) {
        yield alert;
      }
    }

    // Flush remaining partial windows on shutdown.
    const remaining = engine.flush();
    for (const alert of remaining) {
      yield alert;
    }
  } finally {
    await nc.drain();
  }
}

/**
 * Stream all items (events and alerts) as an async iterable.
 */
export async function* streamAll(
  options: StreamOptions,
): AsyncGenerator<StreamItem, void, undefined> {
  const natsModuleName = 'nats';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let natsModule: any;
  try {
    natsModule = await import(natsModuleName);
  } catch {
    throw new WatchError(
      "The 'nats' package is required for streaming. Install it with: npm install nats",
    );
  }

  const engine = new CorrelationEngine(options.rules);
  const nc = await natsModule.connect(
    await buildNatsConnectOptions(natsModule, options.natsUrl, options.natsCreds),
  );
  const sub = nc.subscribe(NATS_SUBJECT);

  if (options.signal) {
    const onAbort = () => sub.unsubscribe();
    options.signal.addEventListener('abort', onAbort, { once: true });
  }

  try {
    for await (const msg of sub) {
      if (options.signal?.aborted) break;

      let envelope: unknown;
      try {
        envelope = JSON.parse(new TextDecoder().decode(msg.data));
      } catch {
        continue;
      }

      const event = parseEnvelope(envelope);
      if (!event) continue;

      yield { type: 'event' as const, event };

      const alerts = engine.processEvent(event, options.maxWindow);
      for (const alert of alerts) {
        yield { type: 'alert' as const, alert };
      }
    }

    const remaining = engine.flush();
    for (const alert of remaining) {
      yield { type: 'alert' as const, alert };
    }
  } finally {
    await nc.drain();
  }
}
