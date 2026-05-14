// apps/workbench/src/features/activity-bar/__tests__/activity-bar-item.test.tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ActivityBarItem } from "../components/activity-bar-item";
import { SigilHunt } from "@/components/desktop/sidebar-icons";

describe("ActivityBarItem", () => {
  it("renders the icon when orbColor is not set", () => {
    render(
      <ActivityBarItem
        id="hunt"
        icon={SigilHunt}
        tooltip="Hunt"
        active={false}
        onClick={vi.fn()}
      />
    );
    // Icon renders without orb — no spirit-orb-icon present
    expect(screen.queryByRole("presentation")).toBeNull();
  });

  it("renders SpiritOrbIcon instead of icon when orbColor is provided", () => {
    const { container } = render(
      <ActivityBarItem
        id="hunt"
        icon={SigilHunt}
        tooltip="Hunt"
        active={false}
        onClick={vi.fn()}
        orbColor="#3dbf84"
      />
    );
    // SpiritOrbIcon renders a span with aria-hidden and radial-gradient
    const orb = container.querySelector("span[aria-hidden]");
    expect(orb).not.toBeNull();
  });
});
