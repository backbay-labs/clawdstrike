import { describe, it, expect, vi, beforeEach } from "vitest";
import { Readable } from "node:stream";
import type { IncomingMessage, ServerResponse } from "node:http";
import { pluginEvalMiddleware } from "../playground-eval-server";

// ---------------------------------------------------------------------------
// Helpers to build mock request / response pairs
// ---------------------------------------------------------------------------

function makeReq(
  method: string,
  url: string,
  body?: string,
): IncomingMessage {
  const readable = new Readable();
  readable.push(body ?? null);
  readable.push(null);
  return Object.assign(readable, { method, url }) as unknown as IncomingMessage;
}

interface MockRes {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  writeHead: (status: number, headers: Record<string, string>) => void;
  end: (data?: string) => void;
}

function makeRes(): MockRes {
  const res: MockRes = {
    statusCode: 0,
    headers: {},
    body: "",
    writeHead(status: number, headers: Record<string, string>) {
      res.statusCode = status;
      res.headers = headers;
    },
    end(data?: string) {
      res.body = data ?? "";
    },
  };
  return res;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("pluginEvalMiddleware", () => {
  // Generate unique run IDs to avoid cross-test state collisions
  let nextRunId = 9000;
  function uniqueRunId(): number {
    return nextRunId++;
  }

  describe("EVICTION_MS constant", () => {
    it("is 300_000 (5 minutes)", async () => {
      // We verify this structurally by reading the source module.
      // The constant is not exported, so we grep for it in the source.
      const { readFileSync } = await import("node:fs");
      const { resolve } = await import("node:path");
      const source = readFileSync(
        resolve(__dirname, "../playground-eval-server.ts"),
        "utf-8",
      );
      expect(source).toContain("const EVICTION_MS = 300_000;");
    });
  });

  describe("POST / - storeTranspiledCode", () => {
    it("returns a URL containing the run ID", async () => {
      const runId = uniqueRunId();
      const req = makeReq(
        "POST",
        "/",
        JSON.stringify({ code: "console.log(1);", runId }),
      );
      const res = makeRes();
      const next = vi.fn();

      pluginEvalMiddleware(
        req,
        res as unknown as ServerResponse,
        next,
      );

      // POST handler is async, wait for microtasks to flush
      await vi.waitFor(() => {
        expect(res.statusCode).toBe(200);
      });

      const body = JSON.parse(res.body) as { url: string };
      expect(body.url).toContain(String(runId));
      expect(body.url).toContain("/__plugin-eval/");
      expect(body.url).toMatch(/\.js$/);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("GET /:runId.js - serve stored code", () => {
    it("returns stored code as JavaScript", async () => {
      const runId = uniqueRunId();
      const codeContent = "const x = 42;";

      // First store the code
      const postReq = makeReq(
        "POST",
        "/",
        JSON.stringify({ code: codeContent, runId }),
      );
      const postRes = makeRes();
      pluginEvalMiddleware(
        postReq,
        postRes as unknown as ServerResponse,
        vi.fn(),
      );
      await vi.waitFor(() => {
        expect(postRes.statusCode).toBe(200);
      });

      // Now fetch it
      const getReq = makeReq("GET", `/${runId}.js`);
      const getRes = makeRes();
      const next = vi.fn();
      pluginEvalMiddleware(
        getReq,
        getRes as unknown as ServerResponse,
        next,
      );

      expect(getRes.statusCode).toBe(200);
      expect(getRes.body).toBe(codeContent);
      expect(getRes.headers["Content-Type"]).toContain("application/javascript");
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("GET /:runId.js - non-existent run ID", () => {
    it("returns 404 for a run ID that was never stored", () => {
      const req = makeReq("GET", "/99999.js");
      const res = makeRes();
      const next = vi.fn();

      pluginEvalMiddleware(
        req,
        res as unknown as ServerResponse,
        next,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body) as { error: string };
      expect(body.error).toContain("99999");
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("unmatched routes", () => {
    it("calls next() for unrecognised paths", () => {
      const req = makeReq("GET", "/other");
      const res = makeRes();
      const next = vi.fn();

      pluginEvalMiddleware(
        req,
        res as unknown as ServerResponse,
        next,
      );

      expect(next).toHaveBeenCalled();
    });
  });
});
