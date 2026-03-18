// apps/workbench/src/features/spirit/__tests__/spirit-orb-icon.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SpiritOrbIcon } from "../components/spirit-orb-icon";

describe("SpiritOrbIcon", () => {
  it("renders a span with aria-hidden", () => {
    const { container } = render(<SpiritOrbIcon accentColor="#3dbf84" />);
    const span = container.querySelector("span[aria-hidden]");
    expect(span).not.toBeNull();
  });

  it("applies radial-gradient using the accentColor", () => {
    const { container } = render(<SpiritOrbIcon accentColor="#3dbf84" />);
    const span = container.querySelector("span") as HTMLElement;
    expect(span.style.background).toContain("radial-gradient");
    expect(span.style.background).toContain("3dbf84");
  });

  it("uses default size 16 when size prop omitted", () => {
    const { container } = render(<SpiritOrbIcon accentColor="#7b68ee" />);
    const span = container.querySelector("span") as HTMLElement;
    expect(span.style.width).toBe("16px");
    expect(span.style.height).toBe("16px");
  });

  it("accepts custom size prop", () => {
    const { container } = render(<SpiritOrbIcon accentColor="#c45c5c" size={24} />);
    const span = container.querySelector("span") as HTMLElement;
    expect(span.style.width).toBe("24px");
    expect(span.style.height).toBe("24px");
  });
});
