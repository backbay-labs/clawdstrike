import { useSyncExternalStore } from 'react';
import type { DevLifecycleEvent } from './types';
import { onDevLifecycleEvent } from './hmr-handler';
import { pluginRegistry } from '../plugin-registry';

// Constants

const MAX_EVENTS = 500;

// Module-level state

let events: DevLifecycleEvent[] = [];
const EMPTY_EVENTS: DevLifecycleEvent[] = [];
Object.freeze(EMPTY_EVENTS);
let snapshot: DevLifecycleEvent[] = EMPTY_EVENTS;
const listeners = new Set<() => void>();

// Internal helpers

function rebuildSnapshot(): void {
  snapshot = Object.freeze([...events]) as DevLifecycleEvent[];
}

function notify(): void {
  rebuildSnapshot();
  for (const listener of listeners) {
    listener();
  }
}

// Public API

function push(event: DevLifecycleEvent): void {
  events.push(event);
  if (events.length > MAX_EVENTS) {
    events = events.slice(events.length - MAX_EVENTS);
  }
  notify();
}

function getEvents(): DevLifecycleEvent[] {
  return events;
}

function clear(): void {
  events = [];
  notify();
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function getSnapshot(): DevLifecycleEvent[] {
  return snapshot;
}

export const devConsoleStore = {
  push,
  getEvents,
  clear,
  subscribe,
  getSnapshot,
};

// React hooks

export function useDevConsoleEvents(): DevLifecycleEvent[] {
  return useSyncExternalStore(subscribe, getSnapshot);
}

export function useDevConsoleFilter(pluginId?: string): DevLifecycleEvent[] {
  const allEvents = useDevConsoleEvents();
  if (!pluginId) return allEvents;
  return allEvents.filter((e) => e.pluginId === pluginId);
}

// Auto-wire: subscribe to HMR lifecycle events

onDevLifecycleEvent((event) => {
  devConsoleStore.push(event);
});

// Auto-wire: subscribe to plugin registry state changes

pluginRegistry.subscribe('stateChanged', (event) => {
  const { pluginId, oldState, newState } = event;

  if (newState === 'activated') {
    devConsoleStore.push({
      type: 'activated',
      pluginId,
      timestamp: Date.now(),
      message: `Plugin ${pluginId} activated (was ${oldState ?? 'unknown'})`,
    });
  } else if (newState === 'error') {
    devConsoleStore.push({
      type: 'error',
      pluginId,
      timestamp: Date.now(),
      message: `Plugin ${pluginId} entered error state (was ${oldState ?? 'unknown'})`,
    });
  } else if (newState === 'deactivated') {
    devConsoleStore.push({
      type: 'deactivated',
      pluginId,
      timestamp: Date.now(),
      message: `Plugin ${pluginId} deactivated (was ${oldState ?? 'unknown'})`,
    });
  }
});
