import { expect, test } from "@playwright/test";
import { createServer, type ServerResponse } from "node:http";

test("authenticated SSE reconnects and resumes events", async ({ page }) => {
  const apiKey = "test-api-key";
  const openResponses = new Set<ServerResponse>();
  let connectionCount = 0;

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

    connectionCount += 1;
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
    });

    openResponses.add(res);
    res.on("close", () => {
      openResponses.delete(res);
    });

    const isFirstConnection = connectionCount === 1;
    const sendEvent = () => {
      const payload = {
        action_type: "file_access",
        target: isFirstConnection ? "/tmp/first" : "/tmp/second",
        allowed: false,
        guard: "fs_blocklist",
        timestamp: new Date().toISOString(),
      };
      res.write(`event: check\ndata: ${JSON.stringify(payload)}\n\n`);
    };
    setTimeout(sendEvent, 50);

    if (isFirstConnection) {
      setTimeout(() => {
        if (!res.writableEnded) {
          res.end();
        }
      }, 300);
    }
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
      { base: hushdUrl, key: apiKey }
    );

    // Navigate to root and open Event Stream via desktop icon
    await page.goto("/");
    await page.getByText("Event Stream").dblclick();

    // Wait for events to appear in the event stream table
    await expect(page.getByText("/tmp/first")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("/tmp/second")).toBeVisible({ timeout: 20_000 });
    expect(connectionCount).toBeGreaterThanOrEqual(2);
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
