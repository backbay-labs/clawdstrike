// @vitest-environment jsdom

import type { ReactNode } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const restoreCapsule = vi.fn();
const closeCapsule = vi.fn();
const openShelf = vi.fn();
const closeShelf = vi.fn();
const request = vi.fn();

const dockValue = {
  sessions: [],
  capsules: [],
  minimizedCapsules: [],
  shelf: { isOpen: false, mode: null as null },
  openShelf,
  restoreCapsule,
  closeCapsule,
  closeShelf,
};

const openClawValue = {
  activeGatewayId: "gw-1",
  runtimeByGatewayId: {
    "gw-1": {
      status: "disconnected",
      presence: [],
      nodes: [],
      execApprovalQueue: [],
    },
  },
  request,
};

vi.mock("./DockContext", () => ({
  useDock: () => dockValue,
}));

vi.mock("motion/react", () => ({
  AnimatePresence: ({ children }: { children: ReactNode }) => <>{children}</>,
  motion: {
    div: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  },
}));

vi.mock("@/context/OpenClawContext", () => ({
  useOpenClaw: () => openClawValue,
}));

import { SessionRail } from "./SessionRail";

class MemoryStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

describe("SessionRail commands dial", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    (globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();
    openShelf.mockReset();
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("shows Commands menu title and default command entries", () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(<SessionRail />);
    });

    const commandsButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.getAttribute("title") === "Commands - Hot command launcher",
    ) as HTMLButtonElement;

    act(() => {
      commandsButton.click();
    });

    expect(container.textContent).toContain("Commands");
    expect(container.textContent).toContain("Open Fleet");
  });

  it("opens events shelf from right rail button", () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(<SessionRail />);
    });

    const policyButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.getAttribute("title") === "Policy Workbench",
    ) as HTMLButtonElement;

    act(() => {
      policyButton.click();
    });

    expect(openShelf).toHaveBeenCalledWith("events");
  });

  it("opens echoes shelf from right rail button", () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(<SessionRail />);
    });

    const echoesButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.getAttribute("title") === "Echoes - Output Log",
    ) as HTMLButtonElement;

    act(() => {
      echoesButton.click();
    });

    expect(openShelf).toHaveBeenCalledWith("output");
  });

  it("opens relics shelf from right rail button", () => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(<SessionRail />);
    });

    const relicsButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.getAttribute("title") === "Relics - Artifacts",
    ) as HTMLButtonElement;

    act(() => {
      relicsButton.click();
    });

    expect(openShelf).toHaveBeenCalledWith("artifacts");
  });
});
