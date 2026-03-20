import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ObservatoryNebulaClouds } from "@/features/observatory/components/world-canvas/ObservatoryNebulaClouds";

vi.mock("@react-three/drei", () => ({
  Billboard: ({ children }: { children?: ReactNode }) => (
    <div data-testid="nebula-billboard">{children}</div>
  ),
}));

vi.mock("three", async () => {
  const actual = await vi.importActual<typeof import("three")>("three");
  return {
    ...actual,
    AdditiveBlending: 2,
    CanvasTexture: class {
      needsUpdate = false;
    },
  };
});

describe("ObservatoryNebulaClouds", () => {
  it("exports a named React component", () => {
    expect(typeof ObservatoryNebulaClouds).toBe("function");
  });

  it("renders without crashing in a test environment", () => {
    const { container } = render(<ObservatoryNebulaClouds />);
    expect(container).toBeDefined();
  });
});
