// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { StrikecellCarousel } from "./StrikecellCarousel";
import type { Strikecell } from "../types";

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

const STRIKECELLS: Strikecell[] = [
  {
    id: "events",
    name: "Event Stream",
    routeId: "events",
    description: "Event stream",
    status: "warning",
    activityCount: 10,
    nodeCount: 3,
    nodes: [],
    tags: ["events"],
  },
  {
    id: "policies",
    name: "Policies",
    routeId: "policies",
    description: "Policy view",
    status: "healthy",
    activityCount: 4,
    nodeCount: 2,
    nodes: [],
    tags: ["policy"],
  },
];

describe("StrikecellCarousel", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("activates highlighted strikecell on Enter", () => {
    const onActivate = vi.fn();

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <StrikecellCarousel
          strikecells={STRIKECELLS}
          strikecellOrder={["events", "policies"]}
          activeStrikecellId={"events"}
          keyboardHighlightedId={"policies"}
          carouselFocused={true}
          pinned={{}}
          onFocusChange={vi.fn()}
          onNavigate={vi.fn()}
          onActivate={onActivate}
          onHighlight={vi.fn()}
          onToggleExpanded={vi.fn()}
          onPin={vi.fn()}
          onReorder={vi.fn()}
        />
      );
    });

    const listbox = container.querySelector('[role="listbox"]') as HTMLDivElement;
    expect(listbox).toBeTruthy();

    act(() => {
      listbox.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });

    expect(onActivate).toHaveBeenCalledWith("policies");
  });

  it("navigates with arrow keys", () => {
    const onNavigate = vi.fn();

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <StrikecellCarousel
          strikecells={STRIKECELLS}
          strikecellOrder={["events", "policies"]}
          activeStrikecellId={"events"}
          keyboardHighlightedId={"events"}
          carouselFocused={true}
          pinned={{}}
          onFocusChange={vi.fn()}
          onNavigate={onNavigate}
          onActivate={vi.fn()}
          onHighlight={vi.fn()}
          onToggleExpanded={vi.fn()}
          onPin={vi.fn()}
          onReorder={vi.fn()}
        />
      );
    });

    const listbox = container.querySelector('[role="listbox"]') as HTMLDivElement;

    act(() => {
      listbox.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
      listbox.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
    });

    expect(onNavigate).toHaveBeenNthCalledWith(1, "next");
    expect(onNavigate).toHaveBeenNthCalledWith(2, "prev");
  });
});
