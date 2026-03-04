import { expect, test } from "@playwright/test";
import { createServer, type ServerResponse } from "node:http";

test("agent explorer groups runtime agents under endpoint agents", async ({ page }) => {
  const apiKey = "test-api-key";
  const openResponses = new Set<ServerResponse>();

  const server = createServer((req, res) => {
    const method = req.method ?? "GET";
    const path = (req.url ?? "").split("?")[0];

    if (path !== "/api/v1/events") {
      res.writeHead(404).end();
      return;
    }

    if (method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization",
      });
      res.end();
      return;
    }

    if (req.headers.authorization !== `Bearer ${apiKey}`) {
      res.writeHead(401, {
        "Access-Control-Allow-Origin": "*",
      });
      res.end("unauthorized");
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
    });
    openResponses.add(res);
    res.on("close", () => openResponses.delete(res));

    const baseEvent = {
      action_type: "mcp_tool",
      session_id: "s-1",
      agent_id: "desktop-1",
      runtime_agent_id: "claude-1",
      runtime_agent_kind: "claude_code",
      timestamp: new Date().toISOString(),
    };

    setTimeout(() => {
      const payload = {
        ...baseEvent,
        target: "openclaw.search",
        allowed: true,
        guard: "mcp_allow",
      };
      res.write(`event: check\ndata: ${JSON.stringify(payload)}\n\n`);
    }, 50);

    setTimeout(() => {
      const payload = {
        ...baseEvent,
        target: "openclaw.exec",
        allowed: false,
        guard: "mcp_policy",
        timestamp: new Date().toISOString(),
      };
      res.write(`event: violation\ndata: ${JSON.stringify(payload)}\n\n`);
    }, 120);
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("failed to get mock SSE server address");
  }
  const hushdUrl = `http://127.0.0.1:${address.port}`;

  try {
    await page.addInitScript(
      ({ base, key }) => {
        localStorage.setItem("hushd_url", base);
        localStorage.setItem("hushd_api_key", key);
      },
      { base: hushdUrl, key: apiKey },
    );

    await page.goto("/");
    await page.getByRole("button", { name: "Agent Explorer" }).first().dblclick();

    await expect(page.getByText("1 endpoint agents · 1 runtime agents")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText("desktop-1")).toBeVisible();
    await expect(page.getByText("claude-1")).toBeVisible();
    await expect(page.getByText("claude_code")).toBeVisible();

    await page.getByRole("button", { name: /s-1/i }).first().click();
    await expect(page.getByText("Runtime session s-1")).toBeVisible();
    await expect(page.getByRole("row", { name: /claude_code/i }).first()).toBeVisible();
  } finally {
    for (const response of openResponses) {
      if (!response.writableEnded) {
        response.end();
      }
    }
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  }
});
