import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

// Mock the hmr-handler to prevent auto-wiring side effects during import
vi.mock('../dev/hmr-handler', () => ({
  onDevLifecycleEvent: vi.fn().mockReturnValue(() => {}),
}));

// Mock the plugin-registry to prevent auto-wiring side effects during import
vi.mock('../plugin-registry', () => ({
  pluginRegistry: {
    subscribe: vi.fn().mockReturnValue(() => {}),
    get: vi.fn(),
    register: vi.fn(),
    unregister: vi.fn(),
  },
}));

import {
  devConsoleStore,
  useDevConsoleEvents,
  useDevConsoleFilter,
} from '../dev/dev-console-store';
import type { DevLifecycleEvent } from '../dev/types';

function makeEvent(
  overrides: Partial<DevLifecycleEvent> & { pluginId?: string },
): DevLifecycleEvent {
  return {
    type: 'console:log',
    pluginId: overrides.pluginId ?? 'test.plugin',
    timestamp: Date.now(),
    message: 'test message',
    ...overrides,
  };
}

describe('dev-console-store', () => {
  beforeEach(() => {
    devConsoleStore.clear();
  });

  describe('push()', () => {
    it('adds events to the store', () => {
      const event = makeEvent({ message: 'hello' });
      devConsoleStore.push(event);

      const events = devConsoleStore.getEvents();
      expect(events).toHaveLength(1);
      expect(events[0].message).toBe('hello');
    });

    it('adds events in order', () => {
      devConsoleStore.push(makeEvent({ message: 'first' }));
      devConsoleStore.push(makeEvent({ message: 'second' }));
      devConsoleStore.push(makeEvent({ message: 'third' }));

      const events = devConsoleStore.getEvents();
      expect(events).toHaveLength(3);
      expect(events[0].message).toBe('first');
      expect(events[1].message).toBe('second');
      expect(events[2].message).toBe('third');
    });
  });

  describe('getEvents()', () => {
    it('returns all pushed events in order', () => {
      for (let i = 0; i < 5; i++) {
        devConsoleStore.push(makeEvent({ message: `event-${i}` }));
      }

      const events = devConsoleStore.getEvents();
      expect(events).toHaveLength(5);
      for (let i = 0; i < 5; i++) {
        expect(events[i].message).toBe(`event-${i}`);
      }
    });
  });

  describe('clear()', () => {
    it('empties all events from the store', () => {
      devConsoleStore.push(makeEvent({}));
      devConsoleStore.push(makeEvent({}));
      expect(devConsoleStore.getEvents()).toHaveLength(2);

      devConsoleStore.clear();
      expect(devConsoleStore.getEvents()).toHaveLength(0);
    });

    it('notifies subscribers on clear', () => {
      const listener = vi.fn();
      const unsub = devConsoleStore.subscribe(listener);

      devConsoleStore.push(makeEvent({}));
      const callsBefore = listener.mock.calls.length;

      devConsoleStore.clear();
      expect(listener.mock.calls.length).toBeGreaterThan(callsBefore);

      unsub();
    });
  });

  describe('cap at 500 entries', () => {
    it('drops oldest events when exceeding 500', () => {
      for (let i = 0; i < 501; i++) {
        devConsoleStore.push(makeEvent({ message: `event-${i}` }));
      }

      const events = devConsoleStore.getEvents();
      expect(events).toHaveLength(500);
      // The first event (event-0) should be dropped
      expect(events[0].message).toBe('event-1');
      // The last event should be the most recent
      expect(events[499].message).toBe('event-500');
    });
  });

  describe('subscribe()', () => {
    it('notifies listeners when events are pushed', () => {
      const listener = vi.fn();
      const unsub = devConsoleStore.subscribe(listener);

      devConsoleStore.push(makeEvent({}));
      expect(listener).toHaveBeenCalledTimes(1);

      devConsoleStore.push(makeEvent({}));
      expect(listener).toHaveBeenCalledTimes(2);

      unsub();
    });

    it('unsubscribe stops notifications', () => {
      const listener = vi.fn();
      const unsub = devConsoleStore.subscribe(listener);
      unsub();

      devConsoleStore.push(makeEvent({}));
      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe('getSnapshot()', () => {
    it('returns a frozen array', () => {
      devConsoleStore.push(makeEvent({}));
      const snap = devConsoleStore.getSnapshot();
      expect(Object.isFrozen(snap)).toBe(true);
    });

    it('returns a new reference after push', () => {
      devConsoleStore.push(makeEvent({ message: 'a' }));
      const snap1 = devConsoleStore.getSnapshot();

      devConsoleStore.push(makeEvent({ message: 'b' }));
      const snap2 = devConsoleStore.getSnapshot();

      expect(snap1).not.toBe(snap2);
    });
  });

  describe('useDevConsoleEvents()', () => {
    it('returns reactive snapshot via renderHook', () => {
      const { result } = renderHook(() => useDevConsoleEvents());
      expect(result.current).toHaveLength(0);

      act(() => {
        devConsoleStore.push(makeEvent({ message: 'hook-test' }));
      });

      expect(result.current).toHaveLength(1);
      expect(result.current[0].message).toBe('hook-test');
    });
  });

  describe('useDevConsoleFilter()', () => {
    it('returns only events for specified pluginId', () => {
      devConsoleStore.push(makeEvent({ pluginId: 'alpha', message: 'a' }));
      devConsoleStore.push(makeEvent({ pluginId: 'beta', message: 'b' }));
      devConsoleStore.push(makeEvent({ pluginId: 'alpha', message: 'c' }));

      const { result } = renderHook(() => useDevConsoleFilter('alpha'));

      expect(result.current).toHaveLength(2);
      expect(result.current[0].message).toBe('a');
      expect(result.current[1].message).toBe('c');
    });

    it('returns all events when pluginId is undefined', () => {
      devConsoleStore.push(makeEvent({ pluginId: 'alpha', message: 'a' }));
      devConsoleStore.push(makeEvent({ pluginId: 'beta', message: 'b' }));

      const { result } = renderHook(() => useDevConsoleFilter());

      expect(result.current).toHaveLength(2);
    });
  });
});
