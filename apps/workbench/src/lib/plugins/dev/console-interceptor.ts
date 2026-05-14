import { devConsoleStore } from './dev-console-store';
import type { DevLifecycleEventType } from './types';

// State

let origLog: typeof console.log | null = null;
let origWarn: typeof console.warn | null = null;
let origError: typeof console.error | null = null;

let isIntercepting = false;

const activePluginStack: string[] = [];

// Internal helpers

function formatArgs(args: unknown[]): string {
  return args
    .map((arg) => {
      if (arg === null) return 'null';
      if (arg === undefined) return 'undefined';
      if (typeof arg === 'string') return arg;
      if (typeof arg === 'number' || typeof arg === 'boolean') return String(arg);
      try {
        return JSON.stringify(arg);
      } catch {
        return String(arg);
      }
    })
    .join(' ');
}

function makeWrapper(
  original: (...args: unknown[]) => void,
  eventType: DevLifecycleEventType,
): (...args: unknown[]) => void {
  return (...args: unknown[]) => {
    original.apply(console, args);

    if (isIntercepting) return;
    const currentPluginId = activePluginStack[activePluginStack.length - 1] ?? null;
    if (!currentPluginId) return;

    isIntercepting = true;
    try {
      devConsoleStore.push({
        type: eventType,
        pluginId: currentPluginId,
        timestamp: Date.now(),
        message: formatArgs(args),
      });
    } finally {
      isIntercepting = false;
    }
  };
}

// Public API

/** Returns a dispose function that restores originals when no interceptors remain. */
export function interceptConsole(pluginId: string): () => void {
  if (!origLog) {
    origLog = console.log;
    origWarn = console.warn;
    origError = console.error;
  }

  activePluginStack.push(pluginId);

  console.log = makeWrapper(origLog!, 'console:log');
  console.warn = makeWrapper(origWarn!, 'console:warn');
  console.error = makeWrapper(origError!, 'console:error');

  return () => {
    const idx = activePluginStack.lastIndexOf(pluginId);
    if (idx !== -1) {
      activePluginStack.splice(idx, 1);
    }

    if (activePluginStack.length === 0) {
      if (origLog) console.log = origLog;
      if (origWarn) console.warn = origWarn;
      if (origError) console.error = origError;
    }
  };
}

/** Safety valve: immediately restore all original console methods. */
export function stopIntercepting(): void {
  if (origLog) console.log = origLog;
  if (origWarn) console.warn = origWarn;
  if (origError) console.error = origError;
  origLog = null;
  origWarn = null;
  origError = null;
  activePluginStack.length = 0;
  isIntercepting = false;
}
