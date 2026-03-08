import { afterEach, describe, expect, it, vi } from "vitest";

import { HushdClient } from "./hushdClient";

describe("HushdClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("wraps eval requests under an event key", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        version: 1,
        command: "policy_eval",
        decision: { allowed: true, denied: false, warn: false },
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const client = new HushdClient("http://localhost:9876");
    const event = { eventId: "evt-1", eventType: "file_read" };

    await client.eval(event);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:9876/api/v1/eval",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ event }),
      }),
    );
  });
});
