// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sessionStore } from "@/shell/sessions";
import { NavRail } from "./NavRail";

const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("./CyberNexusOrb", () => ({
  CyberNexusOrb: () => <div data-testid="nexus-orb" />,
}));

vi.mock("@/context/ConnectionContext", () => ({
  useConnectionStatus: () => "connected",
}));

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

describe("NavRail", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    navigateMock.mockReset();
    for (const session of sessionStore.getSessions()) {
      sessionStore.deleteSession(session.id);
    }
    sessionStore.setActiveSession(null);
    sessionStore.setActiveApp("nexus");
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("renders strikecell sessions and routes LIVE button to operations", () => {
    sessionStore.createSession("nexus", "Strikecell Alpha", null, {
      strikecellId: "nexus",
      strikecellKind: "chat",
    });

    const onSelectApp = vi.fn();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(<NavRail activeAppId="nexus" onSelectApp={onSelectApp} />);
    });

    expect(container.textContent).toContain("Strikecell Alpha");
    expect(container.textContent).not.toContain("Settings");

    const liveButton = container.querySelector(
      "button[aria-label*='Open operations']",
    ) as HTMLButtonElement;
    expect(liveButton).toBeTruthy();

    act(() => {
      liveButton.click();
    });

    expect(onSelectApp).toHaveBeenCalledWith("operations");
  });

  it("creates and navigates to a strikecell session route", () => {
    const onSelectApp = vi.fn();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(<NavRail activeAppId="nexus" onSelectApp={onSelectApp} />);
    });

    const addButton = Array.from(container.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "+",
    ) as HTMLButtonElement;
    expect(addButton).toBeTruthy();

    act(() => {
      addButton.click();
    });

    expect(navigateMock).toHaveBeenCalledTimes(1);
    const pathArg = navigateMock.mock.calls[0]?.[0] as string;
    expect(pathArg.startsWith("/nexus/sess_")).toBe(true);

    const sessions = sessionStore.getSessions({ appId: "nexus", archived: false });
    expect(sessions.length).toBe(1);
    expect(["chat", "experiment", "red-team"]).toContain(sessions[0].strikecellKind);
  });
});
