import { describe, expect, it, vi } from "vitest";
import { createHttpTransport } from "../http-transport";

function textResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/plain" },
  });
}

describe("createHttpTransport", () => {
  it("prefers the Tauri HTTP transport outside dev when Tauri internals are present", async () => {
    const fallbackFetch = vi.fn(async () => textResponse("fallback"));
    const tauriFetch = vi.fn(async () => textResponse("tauri"));
    const loadTauriFetch = vi.fn(async () => tauriFetch as unknown as typeof fetch);

    const transport = createHttpTransport({
      dev: false,
      hasTauriInternals: true,
      fallbackFetch: fallbackFetch as unknown as typeof fetch,
      loadTauriFetch,
    });

    const response = await transport("https://fleet.example/health");

    expect(await response.text()).toBe("tauri");
    expect(loadTauriFetch).toHaveBeenCalledTimes(1);
    expect(tauriFetch).toHaveBeenCalledTimes(1);
    expect(fallbackFetch).not.toHaveBeenCalled();
  });

  it("uses the fallback fetch when not running in Tauri", async () => {
    const fallbackFetch = vi.fn(async () => textResponse("fallback"));
    const loadTauriFetch = vi.fn(async () => textResponse("tauri"));

    const transport = createHttpTransport({
      dev: false,
      hasTauriInternals: false,
      fallbackFetch: fallbackFetch as unknown as typeof fetch,
      loadTauriFetch: loadTauriFetch as unknown as () => Promise<typeof fetch>,
    });

    const response = await transport("https://fleet.example/health");

    expect(await response.text()).toBe("fallback");
    expect(fallbackFetch).toHaveBeenCalledTimes(1);
    expect(loadTauriFetch).not.toHaveBeenCalled();
  });

  it("falls back to the default fetch when the Tauri transport loader fails", async () => {
    const fallbackFetch = vi.fn(async () => textResponse("fallback"));
    const loadTauriFetch = vi.fn(async () => {
      throw new Error("tauri loader failed");
    });

    const transport = createHttpTransport({
      dev: false,
      hasTauriInternals: true,
      fallbackFetch: fallbackFetch as unknown as typeof fetch,
      loadTauriFetch,
    });

    const response = await transport("https://fleet.example/health");

    expect(await response.text()).toBe("fallback");
    expect(loadTauriFetch).toHaveBeenCalledTimes(1);
    expect(fallbackFetch).toHaveBeenCalledTimes(1);
  });
});
