import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildPresenceTicketUrl,
  buildPresenceWebSocketUrl,
  issuePresenceWebSocketTicket,
} from "../presence-socket";

describe("presence-socket urls", () => {
  it("routes local hushd ticket requests through the dev proxy", () => {
    expect(
      buildPresenceTicketUrl(
        "http://localhost:9876",
        "http://127.0.0.1:1421",
        true,
      ),
    ).toBe("http://127.0.0.1:1421/_proxy/hushd/api/v1/presence/tickets");
  });

  it("routes local hushd websocket traffic through the dev websocket proxy", () => {
    expect(
      buildPresenceWebSocketUrl(
        "http://localhost:9876",
        "ticket secret",
        "http://127.0.0.1:1421",
        true,
      ),
    ).toBe("ws://127.0.0.1:1421/_proxy/hushd/api/v1/presence?ticket=ticket+secret");
  });

  it("keeps non-proxied endpoints on their direct websocket origin", () => {
    expect(
      buildPresenceWebSocketUrl(
        "https://hushd.example.com",
        "ticket-123",
        "http://127.0.0.1:1421",
        true,
      ),
    ).toBe("wss://hushd.example.com/api/v1/presence?ticket=ticket-123");
  });
});

describe("issuePresenceWebSocketTicket", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("uses bearer auth to mint a short-lived websocket ticket", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ticket: "short-lived-ticket" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock;

    const ticket = await issuePresenceWebSocketTicket(
      "http://localhost:9876",
      "raw-api-key",
      "http://127.0.0.1:1421",
      undefined,
      true,
    );

    expect(ticket).toBe("short-lived-ticket");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:1421/_proxy/hushd/api/v1/presence/tickets",
      expect.objectContaining({
        method: "POST",
        headers: {
          Authorization: "Bearer raw-api-key",
        },
      }),
    );
  });
});
