// @vitest-environment jsdom

import type { ButtonHTMLAttributes, ReactNode } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OperationsHubView } from "./OperationsHubView";

vi.mock("@backbay/glia/primitives", () => ({
  GlassPanel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  GlassHeader: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  GlowButton: ({ children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button type="button" {...props}>
      {children}
    </button>
  ),
}));

vi.mock("@/features/openclaw/OpenClawFleetView", () => ({
  OpenClawFleetView: () => <div data-testid="fleet-view">Fleet Tab</div>,
}));

vi.mock("@/features/settings/SettingsView", () => ({
  SettingsView: ({ scope }: { scope?: string }) => (
    <div data-testid="settings-view">Settings Scope: {scope}</div>
  ),
}));

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

describe("OperationsHubView", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("loads the connection tab from query params", () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <MemoryRouter initialEntries={["/operations?tab=connection"]}>
          <Routes>
            <Route path="/operations" element={<OperationsHubView />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    expect(container.textContent).toContain("Settings Scope: connection");
  });

  it("switches tabs and updates rendered content", () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <MemoryRouter initialEntries={["/operations?tab=fleet"]}>
          <Routes>
            <Route path="/operations" element={<OperationsHubView />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    expect(container.textContent).toContain("Fleet Tab");

    const preferencesButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Preferences",
    ) as HTMLButtonElement;

    act(() => {
      preferencesButton.click();
    });

    expect(container.textContent).toContain("Settings Scope: preferences");
  });
});
