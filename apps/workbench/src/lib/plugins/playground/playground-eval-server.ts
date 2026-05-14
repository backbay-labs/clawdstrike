/**
 * Plugin Eval Server Middleware
 *
 * Vite dev server middleware that serves transpiled playground plugin code
 * from /__plugin-eval/ routes. This avoids CSP blob URL violations in Tauri
 * by serving from 'self' origin.
 *
 * POST /__plugin-eval/ - Store transpiled code, return serving URL
 * GET  /__plugin-eval/:runId.js - Serve stored code as JavaScript
 */
import type { IncomingMessage, ServerResponse } from "http";

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/** Stored transpiled code keyed by runId. */
const codeStore = new Map<number, string>();

/** Active cleanup timers keyed by runId. */
const cleanupTimers = new Map<number, ReturnType<typeof setTimeout>>();

/** Track runIds with an active fetch in progress (don't evict). */
const activeFetches = new Set<number>();

/** Duration after which stored code is evicted (5 minutes). */
const EVICTION_MS = 300_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function sendJson(
  res: ServerResponse,
  status: number,
  data: Record<string, unknown>,
): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(JSON.stringify(data));
}

function sendJs(res: ServerResponse, code: string): void {
  res.writeHead(200, {
    "Content-Type": "application/javascript; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-cache, no-store, must-revalidate",
  });
  res.end(code);
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Vite middleware handler for the /__plugin-eval/ route.
 *
 * Compatible with Vite's `configureServer` middleware API:
 * `server.middlewares.use("/__plugin-eval", pluginEvalMiddleware)`
 *
 * Note: When mounted with a prefix via `.use("/__plugin-eval", handler)`,
 * Vite strips the prefix from `req.url`, so we see "/" for POST and
 * "/:runId.js" for GET.
 */
export function pluginEvalMiddleware(
  req: IncomingMessage,
  res: ServerResponse,
  next: () => void,
): void {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";

  // POST / - Store transpiled code
  if (method === "POST" && (url === "/" || url === "")) {
    void (async () => {
      try {
        const body = await readBody(req);
        const { code, runId } = JSON.parse(body) as {
          code: string;
          runId: number;
        };

        if (typeof code !== "string" || typeof runId !== "number") {
          sendJson(res, 400, { error: "Invalid body: need code (string) and runId (number)" });
          return;
        }

        // Clear any previous timer for this runId
        const existingTimer = cleanupTimers.get(runId);
        if (existingTimer !== undefined) {
          clearTimeout(existingTimer);
        }

        // Store the code
        codeStore.set(runId, code);

        // Schedule eviction after timeout (skip if a fetch is active)
        const timer = setTimeout(() => {
          if (!activeFetches.has(runId)) {
            codeStore.delete(runId);
          }
          cleanupTimers.delete(runId);
        }, EVICTION_MS);
        cleanupTimers.set(runId, timer);

        sendJson(res, 200, { url: `/__plugin-eval/${runId}.js` });
      } catch (err) {
        sendJson(res, 500, {
          error: err instanceof Error ? err.message : "Internal error",
        });
      }
    })();
    return;
  }

  // GET /:runId.js - Serve stored code
  const jsMatch = url.match(/^\/(\d+)\.js$/);
  if (method === "GET" && jsMatch) {
    const runId = parseInt(jsMatch[1], 10);
    const code = codeStore.get(runId);

    if (code === undefined) {
      sendJson(res, 404, { error: `No code stored for runId ${runId}` });
      return;
    }

    // Keep-alive: reset eviction timer on fetch
    const existingTimer = cleanupTimers.get(runId);
    if (existingTimer !== undefined) {
      clearTimeout(existingTimer);
    }
    activeFetches.add(runId);
    const timer = setTimeout(() => {
      if (!activeFetches.has(runId)) {
        codeStore.delete(runId);
      }
      cleanupTimers.delete(runId);
    }, EVICTION_MS);
    cleanupTimers.set(runId, timer);

    sendJs(res, code);
    activeFetches.delete(runId);
    return;
  }

  // Not handled -- pass to next middleware
  next();
}
