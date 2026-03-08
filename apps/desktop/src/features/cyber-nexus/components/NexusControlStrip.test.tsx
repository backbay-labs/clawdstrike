// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Strikecell } from "../types";
import { NexusControlStrip } from "./NexusControlStrip";

vi.mock("@/services/tauri", () => ({
  isTauri: () => false,
}));

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

const STRIKECELL: Strikecell = {
  id: "forensics-river",
  name: "Nexus",
  routeId: "nexus",
  description: "",
  status: "healthy",
  activityCount: 0,
  nodeCount: 0,
  nodes: [],
  tags: [],
};

describe("NexusControlStrip", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("renders beta tag, mono search input, and profile menu actions", () => {
    const onOpenOperations = vi.fn();

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <NexusControlStrip
          connectionStatus="connected"
          layoutMode="radial"
          activeStrikecell={STRIKECELL}
          brandSubline="Nexus Labs"
          commandQuery=""
          layoutDropdownOpen={false}
          onOpenSearch={vi.fn()}
          onCommandQueryChange={vi.fn()}
          onOpenCommandPalette={vi.fn()}
          onToggleLayoutDropdown={vi.fn()}
          onCloseLayoutDropdown={vi.fn()}
          onSelectLayout={vi.fn()}
          onOpenOperations={onOpenOperations}
          onOpenConnectionSettings={vi.fn()}
        />,
      );
    });

    expect(container.textContent).toContain("BETA");

    const input = container.querySelector(
      "input[placeholder*='Search strikecells']",
    ) as HTMLInputElement;
    expect(input).toBeTruthy();
    expect(input.className.includes("font-mono")).toBe(true);

    const profileButton = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Ops"),
    ) as HTMLButtonElement;

    act(() => {
      profileButton.click();
    });

    const operationsMenuButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Open Operations",
    ) as HTMLButtonElement;

    act(() => {
      operationsMenuButton.click();
    });

    expect(onOpenOperations).toHaveBeenCalledTimes(1);
  });
});
