import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

vi.mock("@/features/settings/secure-store", () => ({
  secureStore: {
    init: vi.fn().mockResolvedValue(undefined),
  },
  migrateCredentialsToStronghold: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/lib/workbench/http-transport", () => ({
  createHttpTransport: vi.fn(() => vi.fn().mockResolvedValue(new Response())),
  httpFetch: vi.fn().mockResolvedValue(new Response()),
}));

vi.mock("@/components/workbench/identity/identity-prompt", () => ({
  IdentityPrompt: () => null,
}));

describe("App error boundary", () => {
  afterEach(() => {
    cleanup();
    vi.resetModules();
    vi.clearAllMocks();
    window.location.hash = "";
  });

  it("catches provider initialization errors before the route tree mounts", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    vi.doMock("@/features/fleet/use-fleet-connection", () => ({
      useFleetConnection: () => {
        throw new Error("fleet init failed");
      },
    }));

    try {
      const { App } = await import("../App");
      render(<App />);

      expect(await screen.findByText("Something went wrong")).toBeInTheDocument();
      expect(screen.getByText("fleet init failed")).toBeInTheDocument();
    } finally {
      consoleError.mockRestore();
    }
  });
});
