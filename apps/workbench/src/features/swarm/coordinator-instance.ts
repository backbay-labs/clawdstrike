/**
 * Singleton SwarmCoordinator instance for the workbench.
 *
 * Uses an InProcessEventBus for local-only (personal swarm) coordination.
 * The coordinator is lazily created on first access and reused across the app.
 *
 * Future: when networked swarms are supported, this module can be extended
 * to swap in a Gossipsub-backed TransportAdapter.
 */

import { SwarmCoordinator, InProcessEventBus } from "@/features/swarm/swarm-coordinator";

let instance: SwarmCoordinator | null = null;

/**
 * Get (or lazily create) the singleton SwarmCoordinator.
 *
 * The coordinator is backed by an InProcessEventBus for same-process
 * message delivery. This is suitable for personal swarms where all
 * sentinels run in the same browser tab.
 */
export function getCoordinator(): SwarmCoordinator {
  if (!instance) {
    const bus = new InProcessEventBus();
    instance = new SwarmCoordinator(bus);
  }
  return instance;
}

/**
 * Destroy the singleton coordinator and reset. Used in tests.
 */
export function resetCoordinator(): void {
  if (instance) {
    instance.destroy();
    instance = null;
  }
}
