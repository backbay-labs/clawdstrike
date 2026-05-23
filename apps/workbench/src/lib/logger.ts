// Tiny dev-vs-prod logger. In production builds we want zero noise unless
// an explicit log level is enabled via VITE_LOG_LEVEL.

type Level = "debug" | "info" | "warn" | "error";
const LEVEL_PRIORITY: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

const envLevel = ((import.meta.env?.VITE_LOG_LEVEL as Level | undefined) ?? "warn") as Level;
const threshold = LEVEL_PRIORITY[envLevel] ?? 2;

function shouldLog(level: Level): boolean {
  return LEVEL_PRIORITY[level] >= threshold;
}

export const logger = {
  debug: (...args: unknown[]) => {
    if (shouldLog("debug")) {
      // eslint-disable-next-line no-console
      console.debug("[workbench]", ...args);
    }
  },
  info: (...args: unknown[]) => {
    if (shouldLog("info")) {
      // eslint-disable-next-line no-console
      console.info("[workbench]", ...args);
    }
  },
  warn: (...args: unknown[]) => {
    if (shouldLog("warn")) {
      // eslint-disable-next-line no-console
      console.warn("[workbench]", ...args);
    }
  },
  error: (...args: unknown[]) => {
    if (shouldLog("error")) {
      // eslint-disable-next-line no-console
      console.error("[workbench]", ...args);
    }
  },
};
