// apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { SpiritCompanionCanvas } from "../components/spirit-companion-canvas";
import { useSpiritStore } from "../stores/spirit-store";
import { useSpiritEvolutionStore } from "../stores/spirit-evolution-store";

vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

vi.mock("@react-three/drei", () => ({
  Trail: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe("SpiritCompanionCanvas", () => {
  beforeEach(() => {
    useSpiritStore.getState().actions.unbindSpirit();
    useSpiritEvolutionStore.getState().actions._reset();
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

  describe("level-gated geometry", () => {
    beforeEach(() => {
      useSpiritStore.getState().actions.bindSpirit("sentinel");
    });

    it("level 1 shows no additional geometry", () => {
      const { queryByTestId } = render(<SpiritCompanionCanvas />);
      expect(queryByTestId("shadow-ring")).toBeNull();
      expect(queryByTestId("orbit-torus")).toBeNull();
      expect(queryByTestId("pulse-ring")).toBeNull();
      expect(queryByTestId("orbit-shards")).toBeNull();
    });

    it("level 2 renders shadow-ring", () => {
      useSpiritEvolutionStore.getState().actions.grantXp("sentinel", 50);
      const { queryByTestId } = render(<SpiritCompanionCanvas />);
      expect(queryByTestId("shadow-ring")).not.toBeNull();
      expect(queryByTestId("orbit-torus")).toBeNull();
    });

    it("level 3 renders shadow-ring and orbit-torus", () => {
      useSpiritEvolutionStore.getState().actions.grantXp("sentinel", 150);
      const { queryByTestId } = render(<SpiritCompanionCanvas />);
      expect(queryByTestId("shadow-ring")).not.toBeNull();
      expect(queryByTestId("orbit-torus")).not.toBeNull();
      expect(queryByTestId("pulse-ring")).toBeNull();
    });

    it("level 4 renders shadow-ring, orbit-torus, and pulse-ring", () => {
      useSpiritEvolutionStore.getState().actions.grantXp("sentinel", 350);
      const { queryByTestId } = render(<SpiritCompanionCanvas />);
      expect(queryByTestId("pulse-ring")).not.toBeNull();
      expect(queryByTestId("orbit-shards")).toBeNull();
    });

    it("level 5 renders all layers including orbit-shards", () => {
      useSpiritEvolutionStore.getState().actions.grantXp("sentinel", 700);
      const { queryByTestId } = render(<SpiritCompanionCanvas />);
      expect(queryByTestId("orbit-shards")).not.toBeNull();
    });
  });
});
