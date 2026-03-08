// @vitest-environment jsdom

import type { ReactNode } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ShellApp } from "./ShellApp";

vi.mock("@backbay/glia/theme", () => ({
  UiThemeProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./ShellLayout", async () => {
  const { Outlet } = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ShellLayout: () => (
      <div>
        <Outlet />
      </div>
    ),
  };
});

vi.mock("./plugins", () => ({
  getPlugins: () => [
    {
      id: "nexus",
      name: "Nexus",
      icon: "nexus",
      description: "Nexus test route",
      order: 1,
      routes: [{ path: "", index: true, element: <div>Nexus View</div> }],
    },
  ],
}));

vi.mock("@/context/ConnectionContext", () => ({
  ConnectionProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/context/OpenClawContext", () => ({
  OpenClawProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/context/PolicyContext", () => ({
  PolicyProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/context/SwarmContext", () => ({
  SwarmProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("./MarketplaceDiscoveryBootstrap", () => ({
  MarketplaceDiscoveryBootstrap: () => null,
}));

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

describe("ShellApp routing", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    window.location.hash = "";
  });

  it("redirects root hash route to /nexus", async () => {
    window.location.hash = "#/";

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    await act(async () => {
      root.render(<ShellApp />);
      await Promise.resolve();
    });

    expect(window.location.hash).toContain("#/nexus");
  });
});
