import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';
import { failClosed } from '@clawdstrike/adapter-core';
import { createModeMachine } from './mode-machine.js';
import { probeRemoteEngine } from './probe.js';
import { createReceiptQueue } from './receipt-queue.js';
import type { AdaptiveEngineOptions, EnrichedProvenance } from './types.js';

export interface AdaptiveEngine extends PolicyEngineLike {
  /** Stop the background health probe and release resources. */
  dispose(): void;
}

/**
 * Determines whether an error is a connectivity problem (as opposed to a
 * server-side logic error). Connectivity errors trigger fallback to local
 * instead of an immediate fail-closed deny.
 */
function isConnectivityError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const msg = error.message.toLowerCase();
  return (
    msg.includes('econnrefused') ||
    msg.includes('econnreset') ||
    msg.includes('enotfound') ||
    msg.includes('fetch failed') ||
    msg.includes('network') ||
    msg.includes('abort') ||
    msg.includes('timeout') ||
    msg.includes('etimedout')
  );
}

function enrichDecision(decision: Decision, provenance: EnrichedProvenance): Decision {
  return {
    ...decision,
    details: {
      ...(typeof decision.details === 'object' && decision.details !== null
        ? (decision.details as Record<string, unknown>)
        : {}),
      provenance,
    },
  };
}

export function createAdaptiveEngine(options: AdaptiveEngineOptions): AdaptiveEngine {
  const { local, remote } = options;
  const initialMode = options.initialMode ?? 'standalone';

  const machine = createModeMachine(initialMode);
  const queue = createReceiptQueue({
    maxSize: options.receiptQueue?.maxSize,
    persistPath: options.receiptQueue?.persistPath,
  });

  // Load any persisted receipts from a previous session.
  if (options.receiptQueue?.persistPath) {
    queue.loadFromDisk(options.receiptQueue.persistPath);
  }

  if (options.onModeChange) {
    machine.onModeChange(options.onModeChange);
  }

  const probeUrl = options.probe?.remoteHealthUrl;
  const probeIntervalMs = options.probe?.intervalMs ?? 30_000;
  const probeTimeoutMs = options.probe?.timeoutMs ?? 5_000;

  const abortController = new AbortController();

  /** Run a single health probe and update mode accordingly. */
  async function runProbe(): Promise<void> {
    if (!probeUrl || !remote) return;

    const healthy = await probeRemoteEngine(probeUrl, probeTimeoutMs);
    const current = machine.current();

    if (healthy && (current === 'standalone' || current === 'degraded')) {
      let drainedReceipts: ReturnType<typeof queue.drain> = [];
      if (current === 'degraded') {
        drainedReceipts = queue.drain();
      }

      const promoted = await machine.transition(
        'connected',
        'remote health probe succeeded',
        drainedReceipts.length > 0 ? { drainedReceipts } : undefined
      );

      // Transition could be rejected if another concurrent transition already
      // updated state; restore drained receipts in that case.
      if (!promoted && drainedReceipts.length > 0) {
        for (const receipt of drainedReceipts) {
          queue.enqueue(receipt);
        }
      }
    } else if (!healthy && current === 'connected') {
      await machine.transition('degraded', 'remote health probe failed');
    }
  }

  // Kick off an initial probe if remote is configured.
  if (remote && probeUrl) {
    runProbe().catch(() => {
      // Initial probe failure is non-fatal.
    });
  }

  // Start periodic background probing.
  let probeTimer: ReturnType<typeof setInterval> | undefined;
  if (remote && probeUrl) {
    probeTimer = setInterval(() => {
      if (abortController.signal.aborted) return;
      runProbe().catch(() => {
        // Background probe errors are swallowed.
      });
    }, probeIntervalMs);

    // Prevent the interval from keeping the process alive.
    if (typeof probeTimer === 'object' && 'unref' in probeTimer) {
      (probeTimer as NodeJS.Timeout).unref();
    }
  }

  function dispose(): void {
    abortController.abort();
    if (probeTimer !== undefined) {
      clearInterval(probeTimer);
      probeTimer = undefined;
    }
  }

  async function evaluate(event: PolicyEvent): Promise<Decision> {
    const mode = machine.current();

    // Connected mode: try remote first.
    if (mode === 'connected' && remote) {
      try {
        const decision = await remote.evaluate(event);
        const provenance: EnrichedProvenance = {
          mode: 'connected',
          engine: 'remote',
          timestamp: new Date().toISOString(),
        };
        return enrichDecision(decision, provenance);
      } catch (error: unknown) {
        if (isConnectivityError(error)) {
          // Transition to degraded and fall through to local evaluation.
          await machine.transition('degraded', 'remote evaluation connectivity error');
        } else {
          // Non-connectivity error from remote — fail closed.
          return failClosed(error);
        }
      }
    }

    // Standalone or degraded: use local engine.
    try {
      const decision = await local.evaluate(event);
      const currentMode = machine.current();
      const provenance: EnrichedProvenance = {
        mode: currentMode,
        engine: 'local',
        timestamp: new Date().toISOString(),
      };
      const enriched = enrichDecision(decision, provenance);

      // In degraded mode, queue the receipt for later sync.
      if (currentMode === 'degraded') {
        queue.enqueue({
          event,
          decision: enriched,
          provenance,
          enqueuedAt: new Date().toISOString(),
        });
      }

      return enriched;
    } catch (error: unknown) {
      return failClosed(error);
    }
  }

  function redactSecrets(value: string): string {
    const mode = machine.current();

    // Prefer the currently active engine's redaction.
    if (mode === 'connected' && remote?.redactSecrets) {
      return remote.redactSecrets(value);
    }

    if (local.redactSecrets) {
      return local.redactSecrets(value);
    }

    return value;
  }

  return {
    evaluate,
    redactSecrets,
    dispose,
  };
}
