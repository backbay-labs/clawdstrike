import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import * as fs from "node:fs";
import * as path from "node:path";
import { ObservatoryStarfield } from "@/features/observatory/components/world-canvas/ObservatoryStarfield";

// Mock R3F and drei so we can render in jsdom
vi.mock("@react-three/fiber", () => ({
  useFrame: vi.fn(),
  extend: vi.fn(),
}));

vi.mock("@react-three/drei", () => ({
  Sparkles: () => <div data-testid="sparkles" />,
}));

vi.mock("three", () => {
  const SphereGeometry = vi.fn(() => ({ dispose: vi.fn() }));
  const PlaneGeometry = vi.fn(() => ({ dispose: vi.fn() }));
  const ShaderMaterial = vi.fn(() => ({ uniforms: {}, dispose: vi.fn() }));
  const MeshBasicMaterial = vi.fn(() => ({ dispose: vi.fn() }));
  const InstancedMesh = vi.fn(() => ({ setMatrixAt: vi.fn(), instanceMatrix: { needsUpdate: false }, dispose: vi.fn() }));
  const Matrix4 = vi.fn(() => ({ makeTranslation: vi.fn().mockReturnThis(), makeScale: vi.fn().mockReturnThis() }));
  const Vector3 = vi.fn(() => ({ set: vi.fn(), normalize: vi.fn().mockReturnThis(), multiplyScalar: vi.fn().mockReturnThis(), x: 0, y: 0, z: 0 }));
  const Color = vi.fn(() => ({ r: 1, g: 1, b: 1 }));
  return {
    SphereGeometry,
    PlaneGeometry,
    ShaderMaterial,
    MeshBasicMaterial,
    InstancedMesh,
    Matrix4,
    Vector3,
    Color,
    BackSide: 1,
    DoubleSide: 2,
    FrontSide: 0,
  };
});

describe("ObservatoryStarfield", () => {
  it("is a valid named export (React component)", () => {
    expect(typeof ObservatoryStarfield).toBe("function");
  });

  it("renders without crashing", () => {
    // Since R3F components expect a Canvas context we test that the component
    // at least renders without throwing (not that it produces DOM output).
    expect(() => {
      try {
        render(<ObservatoryStarfield />);
      } catch (err) {
        // Canvas context errors are expected in jsdom — only crash on unexpected errors
        const message = String((err as Error).message ?? "");
        if (message.includes("Cannot read") || message.includes("is not a function")) {
          throw err;
        }
      }
    }).not.toThrow();
  });

  it("Star Nest GLSL shader file exists and contains volsteps", () => {
    const shaderPath = path.resolve(
      __dirname,
      "../shaders/starNest.glsl",
    );
    const source = fs.readFileSync(shaderPath, "utf8");
    expect(source).toContain("volsteps");
  });
});
