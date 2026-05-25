import { devConsoleStore } from './dev-console-store';
import type { DevLifecycleEventType } from './types';
import { logger } from "@/lib/logger";

// State

let origLog: typeof logger.info | null = null;
let origWarn: typeof logger.warn | null = null;
let origError: typeof logger.error | null = null;

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
    origLog = logger.info;
    origWarn = logger.warn;
    origError = logger.error;
  }

  activePluginStack.push(pluginId);

  logger.info = makeWrapper(origLog!, 'console:log');
  logger.warn = makeWrapper(origWarn!, 'console:warn');
  logger.error = makeWrapper(origError!, 'console:error');

  return () => {
    const idx = activePluginStack.lastIndexOf(pluginId);
    if (idx !== -1) {
      activePluginStack.splice(idx, 1);
    }

    if (activePluginStack.length === 0) {
      if (origLog) logger.info = origLog;
      if (origWarn) logger.warn = origWarn;
      if (origError) logger.error = origError;
    }
  };
}

/** Safety valve: immediately restore all original console methods. */
export function stopIntercepting(): void {
  if (origLog) logger.info = origLog;
  if (origWarn) logger.warn = origWarn;
  if (origError) logger.error = origError;
  origLog = null;
  origWarn = null;
  origError = null;
  activePluginStack.length = 0;
  isIntercepting = false;
}
