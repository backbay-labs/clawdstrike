import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

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

import { interceptConsole, stopIntercepting } from '../dev/console-interceptor';
import { devConsoleStore } from '../dev/dev-console-store';

describe('console-interceptor', () => {
  // Store original console methods to verify restoration
  const realLog = console.log;
  const realWarn = console.warn;
  const realError = console.error;

  beforeEach(() => {
    devConsoleStore.clear();
    // Ensure we start with clean state
    stopIntercepting();
    // Reset console to originals before each test
    console.log = realLog;
    console.warn = realWarn;
    console.error = realError;
  });

  afterEach(() => {
    stopIntercepting();
    // Always restore originals
    console.log = realLog;
    console.warn = realWarn;
    console.error = realError;
  });

  describe('interceptConsole()', () => {
    it('wraps console.log, console.warn, and console.error', () => {
      const dispose = interceptConsole('test.plugin');

      expect(console.log).not.toBe(realLog);
      expect(console.warn).not.toBe(realWarn);
      expect(console.error).not.toBe(realError);

      dispose();
    });

    it('intercepted calls still invoke original console methods', () => {
      const spyLog = vi.fn();
      const spyWarn = vi.fn();
      const spyError = vi.fn();
      console.log = spyLog;
      console.warn = spyWarn;
      console.error = spyError;

      const dispose = interceptConsole('test.plugin');

      console.log('hello');
      console.warn('warning');
      console.error('bad');

      expect(spyLog).toHaveBeenCalledWith('hello');
      expect(spyWarn).toHaveBeenCalledWith('warning');
      expect(spyError).toHaveBeenCalledWith('bad');

      dispose();
    });

    it('intercepted calls push DevLifecycleEvent to devConsoleStore', () => {
      const dispose = interceptConsole('test.plugin');

      // Suppress actual console output during test
      const origLog = console.log;
      console.log('test message');

      const events = devConsoleStore.getEvents();
      expect(events.length).toBeGreaterThanOrEqual(1);

      const logEvent = events.find(
        (e) => e.type === 'console:log' && e.message === 'test message',
      );
      expect(logEvent).toBeDefined();
      expect(logEvent!.pluginId).toBe('test.plugin');

      dispose();
    });

    it('pushes console:warn events for console.warn calls', () => {
      const dispose = interceptConsole('test.plugin');

      console.warn('warning msg');

      const events = devConsoleStore.getEvents();
      const warnEvent = events.find(
        (e) => e.type === 'console:warn' && e.message === 'warning msg',
      );
      expect(warnEvent).toBeDefined();
      expect(warnEvent!.pluginId).toBe('test.plugin');

      dispose();
    });

    it('pushes console:error events for console.error calls', () => {
      const dispose = interceptConsole('test.plugin');

      console.error('error msg');

      const events = devConsoleStore.getEvents();
      const errorEvent = events.find(
        (e) => e.type === 'console:error' && e.message === 'error msg',
      );
      expect(errorEvent).toBeDefined();
      expect(errorEvent!.pluginId).toBe('test.plugin');

      dispose();
    });

    it('formats multiple arguments', () => {
      const dispose = interceptConsole('test.plugin');

      console.log('hello', 42, true);

      const events = devConsoleStore.getEvents();
      const logEvent = events.find((e) => e.type === 'console:log');
      expect(logEvent).toBeDefined();
      expect(logEvent!.message).toBe('hello 42 true');

      dispose();
    });

    it('formats objects via JSON.stringify', () => {
      const dispose = interceptConsole('test.plugin');

      console.log({ key: 'value' });

      const events = devConsoleStore.getEvents();
      const logEvent = events.find((e) => e.type === 'console:log');
      expect(logEvent).toBeDefined();
      expect(logEvent!.message).toBe('{"key":"value"}');

      dispose();
    });
  });

  describe('dispose function', () => {
    it('restores original console methods', () => {
      const origLogRef = console.log;
      const origWarnRef = console.warn;
      const origErrorRef = console.error;

      const dispose = interceptConsole('test.plugin');

      // Methods should be wrapped
      expect(console.log).not.toBe(origLogRef);

      dispose();

      // Methods should be restored
      expect(console.log).toBe(origLogRef);
      expect(console.warn).toBe(origWarnRef);
      expect(console.error).toBe(origErrorRef);
    });
  });

  describe('no infinite loop', () => {
    it('interceptor does not re-intercept its own console calls', () => {
      const dispose = interceptConsole('test.plugin');

      // If re-entrancy guard fails, this would cause a stack overflow
      console.log('first');
      console.warn('second');
      console.error('third');

      const events = devConsoleStore.getEvents();
      // Should have exactly 3 events, not infinite
      const consoleEvents = events.filter(
        (e) =>
          e.type === 'console:log' ||
          e.type === 'console:warn' ||
          e.type === 'console:error',
      );
      expect(consoleEvents).toHaveLength(3);

      dispose();
    });
  });

  describe('stopIntercepting()', () => {
    it('restores all original console methods', () => {
      interceptConsole('test.plugin');
      expect(console.log).not.toBe(realLog);

      stopIntercepting();

      expect(console.log).toBe(realLog);
      expect(console.warn).toBe(realWarn);
      expect(console.error).toBe(realError);
    });

    it('is safe to call when not intercepting', () => {
      // Should not throw
      stopIntercepting();
    });
  });
});
