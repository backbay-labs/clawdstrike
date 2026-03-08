// @vitest-environment jsdom

import type { ReactNode } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DockProvider } from "./DockContext";
import { DockSystem } from "./DockSystem";

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
  request: vi.fn(),
};

vi.mock("motion/react", () => ({
  AnimatePresence: ({ children }: { children: ReactNode }) => <>{children}</>,
  motion: {
    div: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  },
}));

vi.mock("@/context/OpenClawContext", () => ({
  useOpenClaw: () => openClawValue,
}));

vi.mock("@/services/tauri", () => ({
  isTauri: () => false,
  openclawGatewayProbe: vi.fn(),
}));

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

describe("DockSystem shelf", () => {
  let container: HTMLDivElement;
  let root: Root;

  const mountDock = () => {
    (globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <DockProvider>
          <DockSystem demoMode={false} />
        </DockProvider>,
      );
    });
  };

  const clickShelfButton = (title: string) => {
    const button = Array.from(container.querySelectorAll("button")).find(
      (candidate) => candidate.getAttribute("title") === title,
    ) as HTMLButtonElement | undefined;
    expect(button).toBeTruthy();
    act(() => {
      button?.click();
    });
  };

  afterEach(() => {
    if (root) {
      act(() => root.unmount());
    }
    if (container?.isConnected) {
      container.remove();
    }
  });

  it("renders the events shelf panel when policy button is clicked", () => {
    mountDock();
    clickShelfButton("Policy Workbench");

    const panel = document.body.querySelector("[data-testid='dock-shelf-panel-events']");
    expect(panel).toBeTruthy();
  });

  it("renders the echoes shelf panel when echoes button is clicked", () => {
    mountDock();
    clickShelfButton("Echoes - Output Log");
    const panel = document.body.querySelector("[data-testid='dock-shelf-panel-output']");
    expect(panel).toBeTruthy();
  });

  it("renders the relics shelf panel when relics button is clicked", () => {
    mountDock();
    clickShelfButton("Relics - Artifacts");
    const panel = document.body.querySelector("[data-testid='dock-shelf-panel-artifacts']");
    expect(panel).toBeTruthy();
  });
});
