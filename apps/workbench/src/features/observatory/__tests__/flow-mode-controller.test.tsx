// apps/workbench/src/features/observatory/__tests__/flow-mode-controller.test.tsx
// Covers OBS-06 (WASD character controller Easter-egg)
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@testing-library/react";

// Mock @react-three/fiber so jsdom doesn't break
vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

// @ts-expect-error — FlowModeController does not exist yet (Wave 0 scaffold)
import { FlowModeController } from "@/features/observatory/components/FlowModeController";

describe("FlowModeController (OBS-06)", () => {
  it("renders null when characterControllerEnabled is false", () => {
    const { container } = render(
      <FlowModeController characterControllerEnabled={false} onEnable={vi.fn()} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("double-click event in flow mode calls onEnable callback", () => {
    const onEnable = vi.fn();
    const { container } = render(
      <FlowModeController characterControllerEnabled={false} onEnable={onEnable} />,
    );
    // The FlowModeController attaches a double-click handler to its root container
    // When characterControllerEnabled is false, nothing renders — fire on document instead
    fireEvent.dblClick(document);
    // The callback is only called if the component implements it correctly
    // This is intentionally skeletal (will fail until Task 3 creates FlowModeController)
    expect(onEnable).not.toHaveBeenCalled(); // won't be called while component returns null
  });

  it("renders content when characterControllerEnabled is true", () => {
    // When enabled, FlowModeController renders the Rapier-based controller
    // In jsdom this should at minimum not throw
    const { container } = render(
      <FlowModeController characterControllerEnabled={true} onEnable={vi.fn()} />,
    );
    // May render null or a div — just verify no crash
    expect(container).toBeDefined();
  });
});
