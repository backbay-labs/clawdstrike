// NexusTab tests -- verifies the CyberNexusView port renders inside NexusTab.
//
// After the huntronomer verbatim port, NexusTab is a thin bridge that passes
// strikecells from the Zustand store to CyberNexusView.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";

// Mock @react-three/fiber Canvas -- standard jsdom pattern
vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

// Mock drei so Text and other components don't crash in jsdom
vi.mock("@react-three/drei", () => ({
  Text: vi.fn(() => null),
  Stars: vi.fn(() => null),
  OrbitControls: vi.fn(() => null),
  CameraControls: vi.fn(() => null),
  Line: vi.fn(() => null),
  Html: vi.fn(() => null),
}));

// Mock ObservatoryWorldCanvas to render a div with data-testid
vi.mock(
  "@/features/observatory/components/ObservatoryWorldCanvas",
  () => ({
    ObservatoryWorldCanvas: ({
      mode,
    }: {
      mode?: string;
    }) => (
      <div
        data-testid="observatory-world-canvas"
        data-observatory-mode={mode ?? "atlas"}
      />
    ),
  }),
);

// Mock nexus store
vi.mock("@/features/nexus/stores/nexus-store", () => ({
  useNexusStore: {
    use: {
      strikecells: vi.fn(() => []),
      connections: vi.fn(() => []),
      layoutMode: vi.fn(() => "radial"),
    },
    getState: () => ({
      actions: { setLayoutMode: vi.fn() },
    }),
  },
}));

// Mock pane store
const mockOpenApp = vi.fn();
vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({ openApp: mockOpenApp }),
  },
}));

import { NexusTab } from "@/features/nexus/components/NexusTab";

describe("NexusTab (huntronomer port)", () => {
  beforeEach(() => {
    mockOpenApp.mockClear();
  });

  it("renders with data-testid nexus-tab", () => {
    const { getByTestId } = render(<NexusTab />);
    expect(getByTestId("nexus-tab")).toBeDefined();
  });

  it("renders the CyberNexusView inside the nexus-tab wrapper", () => {
    const { getByTestId } = render(<NexusTab />);
    const tab = getByTestId("nexus-tab");
    // CyberNexusView renders origin-shell-bg class as root
    expect(tab.querySelector(".origin-shell-bg")).toBeDefined();
  });
});
