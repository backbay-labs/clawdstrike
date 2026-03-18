// apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { SpiritCompanionCanvas } from "../components/spirit-companion-canvas";
import { useSpiritStore } from "../stores/spirit-store";

vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

describe("SpiritCompanionCanvas", () => {
  beforeEach(() => {
    useSpiritStore.getState().actions.unbindSpirit();
  });

  it("renders null when no spirit is bound (accentColor is null)", () => {
    const { container } = render(<SpiritCompanionCanvas />);
    expect(container.firstChild).toBeNull();
  });

  it("renders a 150x150 wrapper when a spirit is bound", () => {
    useSpiritStore.getState().actions.bindSpirit("sentinel");
    const { container } = render(<SpiritCompanionCanvas />);
    const wrapper = container.firstChild as HTMLElement;
    expect(wrapper).not.toBeNull();
    expect(wrapper.style.width).toBe("150px");
    expect(wrapper.style.height).toBe("150px");
  });

  it("renders the R3F Canvas when a spirit is bound", () => {
    useSpiritStore.getState().actions.bindSpirit("oracle");
    const { getByTestId } = render(<SpiritCompanionCanvas />);
    expect(getByTestId("r3f-canvas")).toBeDefined();
  });
});
