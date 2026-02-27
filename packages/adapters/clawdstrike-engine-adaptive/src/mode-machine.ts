import type { EngineMode, ModeChangeEvent } from './types.js';

/**
 * Valid mode transitions. Each key maps to the set of modes it can transition to.
 */
const VALID_TRANSITIONS: Record<EngineMode, Set<EngineMode>> = {
  standalone: new Set(['connected']),
  connected: new Set(['degraded']),
  degraded: new Set(['connected', 'standalone']),
};

export type ModeChangeListener = (event: ModeChangeEvent) => void;

export interface ModeMachine {
  /** Current mode. */
  current(): EngineMode;

  /**
   * Request a transition to a new mode with a reason string.
   * Returns true if the transition was valid and applied, false if rejected.
   * Transitions are serialized — concurrent calls queue behind in-progress ones.
   */
  transition(
    to: EngineMode,
    reason: string,
    extras?: Pick<ModeChangeEvent, 'drainedReceipts'>
  ): Promise<boolean>;

  /** Register a listener for mode changes. */
  onModeChange(listener: ModeChangeListener): void;
}

export function createModeMachine(initial: EngineMode): ModeMachine {
  let mode: EngineMode = initial;
  const listeners: ModeChangeListener[] = [];

  // Promise chain used as a serialization mutex. Each transition awaits the
  // previous one before proceeding, preventing concurrent state corruption.
  let chain: Promise<void> = Promise.resolve();

  function emitChange(event: ModeChangeEvent): void {
    for (const listener of listeners) {
      try {
        listener(event);
      } catch {
        // Listener errors must not break the machine.
      }
    }
  }

  return {
    current(): EngineMode {
      return mode;
    },

    transition(
      to: EngineMode,
      reason: string,
      extras?: Pick<ModeChangeEvent, 'drainedReceipts'>
    ): Promise<boolean> {
      const result = new Promise<boolean>((resolve) => {
        chain = chain.then(() => {
          if (mode === to) {
            resolve(false);
            return;
          }

          if (!VALID_TRANSITIONS[mode].has(to)) {
            resolve(false);
            return;
          }

          const event: ModeChangeEvent = {
            from: mode,
            to,
            reason,
            timestamp: new Date().toISOString(),
            ...(extras?.drainedReceipts ? { drainedReceipts: extras.drainedReceipts } : {}),
          };

          mode = to;
          emitChange(event);
          resolve(true);
        });
      });

      return result;
    },

    onModeChange(listener: ModeChangeListener): void {
      listeners.push(listener);
    },
  };
}
