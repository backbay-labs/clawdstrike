import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mutable OS state shared across tests — declared before the vi.mock factory.
const focusedId = { current: null as string | null };
const instances = { current: [] as Array<{ windowId: string; processId: string }> };
const windowIds = { current: [] as string[] };

vi.mock("@backbay/glia-desktop", () => {
  const Taskbar = ({ children }: { children?: ReactNode }) => (
    <div data-testid="taskbar">{children}</div>
  );
  Taskbar.RunningApps = ({ children }: { children?: ReactNode }) => (
    <div data-testid="running-apps">{children}</div>
  );
  Taskbar.SystemTray = () => <div data-testid="system-tray" />;
  Taskbar.StartButton = () => <div data-testid="start-button" />;
  Taskbar.Divider = () => <div />;
  Taskbar.Section = ({ children }: { children?: ReactNode }) => <div>{children}</div>;
  Taskbar.PinnedApps = ({ children }: { children?: ReactNode }) => <div>{children}</div>;
  Taskbar.CenterSection = ({ children }: { children?: ReactNode }) => <div>{children}</div>;
  Taskbar.Clock = () => <div data-testid="clock" />;

  return {
    Taskbar,
    Window: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
    useWindow: () => ({ isMinimized: false }),
    useWindowIds: () => windowIds.current,
    useDesktopOS: () => ({
      processes: {
        instances: instances.current,
        launch: vi.fn(),
        getDefinition: (processId: string) => ({
          name: processId,
          description: `desc:${processId}`,
        }),
      },
      windows: {
        focusedId: focusedId.current,
        focus: vi.fn(),
        minimize: vi.fn(),
      },
    }),
    useSystemTray: () => ({
      registerItem: vi.fn(),
      updateItem: vi.fn(),
      unregisterItem: vi.fn(),
    }),
  };
});

// SSE context — avoid the real EventSource connection.
const sseValue = {
  events: [],
  connected: true,
  status: "connected",
  error: null,
  reconnect: vi.fn(),
  paused: false,
  setPaused: vi.fn(),
  maxEvents: 500,
  setMaxEvents: vi.fn(),
  droppedEvents: 0,
  clearEvents: vi.fn(),
};

vi.mock("../../context/SSEContext", () => ({
  useSharedSSE: () => sseValue,
}));

// Import after mock registration.
import { ClawdStrikeDesktop } from "./ClawdStrikeDesktop";

beforeEach(() => {
  focusedId.current = null;
  instances.current = [];
  windowIds.current = [];
  localStorage.clear();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("ClawdStrikeDesktop — shell composition", () => {
  it("renders the sidebar launcher (replaces the start menu)", () => {
    render(<ClawdStrikeDesktop />);
    expect(screen.getByRole("navigation", { name: /primary navigation/i })).toBeTruthy();
  });

  it("renders the header breadcrumb", () => {
    render(<ClawdStrikeDesktop />);
    expect(screen.getByText("CLAWDSTRIKE")).toBeTruthy();
  });

  it("renders a slim taskbar with a Console online crest", () => {
    render(<ClawdStrikeDesktop />);
    expect(screen.getByTestId("taskbar")).toBeTruthy();
    expect(screen.getByText("Console online")).toBeTruthy();
  });

  it("does NOT render the old StartMenu launcher button", () => {
    render(<ClawdStrikeDesktop />);
    expect(document.querySelector(".start-menu-btn")).toBeNull();
    expect(screen.queryByTestId("start-button")).toBeNull();
  });

  it("does NOT render the floating draggable desktop widgets", () => {
    const { container } = render(<ClawdStrikeDesktop />);
    // The deleted DesktopWidgets were the only draggable (cursor: grab) plates;
    // their status data now lives in the sidebar/header instead.
    const grabbable = Array.from(container.querySelectorAll<HTMLElement>("[style]")).filter(
      (el) => el.style.cursor === "grab",
    );
    expect(grabbable).toHaveLength(0);
  });

  it("shows the canvas empty state when no window is open", () => {
    windowIds.current = [];
    render(<ClawdStrikeDesktop />);
    expect(screen.getByText("No window open")).toBeTruthy();
    expect(screen.getByRole("button", { name: /launch monitor/i })).toBeTruthy();
  });

  it("hides the canvas empty state when a window is open", () => {
    windowIds.current = ["w1"];
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(<ClawdStrikeDesktop />);
    expect(screen.queryByText("No window open")).toBeNull();
  });
});
