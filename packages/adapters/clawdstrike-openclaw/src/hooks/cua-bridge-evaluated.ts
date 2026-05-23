/**
 * Shared WeakSet that records which hook events have already been evaluated
 * by the CUA bridge handler, so the general tool-preflight handler can skip
 * them and avoid double policy evaluation.
 *
 * Using a WeakSet (keyed on the event object) avoids mutating the event with
 * an unstable marker property and keeps the typing clean across both modules.
 *
 * @module
 */

const evaluatedEvents = new WeakSet<object>();

/** Mark the given event as already evaluated by the CUA bridge. */
export function markCuaBridgeEvaluated(event: object): void {
  evaluatedEvents.add(event);
}

/** Returns true if the CUA bridge has already evaluated this event. */
export function isCuaBridgeEvaluated(event: object): boolean {
  return evaluatedEvents.has(event);
}
