/**
 * observatory-left-drawer.test.tsx
 *
 * Unit tests for ObservatoryLeftDrawer:
 *   a. renders drawer container (data-testid present)
 *   b. drawer is hidden (translateX -100%) when activePanel is null
 *   c. drawer is visible (translateX 0) when activePanel is set
 *   d. renders ExplainabilityDrawerPanel when activePanel is 'explainability'
 *   e. renders MissionDrawerPanel when activePanel is 'mission'
 *   f. renders ReplayDrawerPanel when activePanel is 'replay'
 *   g. renders GhostMemoryDrawerPanel when activePanel is 'ghost'
 *   h. renders nothing in content area when activePanel is null
 *   i. drawer uses drawer-specific bg token (GLS-01)
 */

import { describe, expect, it, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import { ObservatoryLeftDrawer } from "../components/hud/ObservatoryLeftDrawer";
import { useObservatoryStore } from "../stores/observatory-store";

const initialState = useObservatoryStore.getState();

describe("ObservatoryLeftDrawer", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      activePanel: null,
    });
  });

  it("a. renders drawer container", () => {
    const { container } = render(<ObservatoryLeftDrawer />);
    const drawer = container.querySelector("[data-testid='observatory-left-drawer']");
    expect(drawer).not.toBeNull();
  });

  it("b. drawer is hidden (translateX -100%) when activePanel is null", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: null });
    const { container } = render(<ObservatoryLeftDrawer />);
    const drawer = container.querySelector(
      "[data-testid='observatory-left-drawer']",
    ) as HTMLElement;
    expect(drawer).not.toBeNull();
    expect(drawer.style.transform).toBe("translateX(-100%)");
  });

  it("c. drawer is visible (translateX 0) when activePanel is set", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "explainability",
    });
    const { container } = render(<ObservatoryLeftDrawer />);
    const drawer = container.querySelector(
      "[data-testid='observatory-left-drawer']",
    ) as HTMLElement;
    expect(drawer).not.toBeNull();
    expect(drawer.style.transform).toBe("translateX(0)");
  });

  it("d. renders ExplainabilityDrawerPanel when activePanel is 'explainability'", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "explainability",
      selectedStationId: null,
    });
    const { container } = render(<ObservatoryLeftDrawer />);
    const panel = container.querySelector("[data-testid='explainability-drawer-panel']");
    const emptyState = container.querySelector("[data-testid='explainability-empty-state']");
    // Either the full panel or its empty state must be present
    expect(panel !== null || emptyState !== null).toBe(true);
  });

  it("e. renders MissionDrawerPanel when activePanel is 'mission'", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "mission",
      mission: null,
    });
    const { container } = render(<ObservatoryLeftDrawer />);
    const panel = container.querySelector("[data-testid='mission-drawer-panel']");
    const emptyState = container.querySelector("[data-testid='mission-empty-state']");
    expect(panel !== null || emptyState !== null).toBe(true);
  });

  it("f. renders ReplayDrawerPanel when activePanel is 'replay'", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "replay",
    });
    const { container } = render(<ObservatoryLeftDrawer />);
    const panel = container.querySelector("[data-testid='replay-drawer-panel']");
    expect(panel).not.toBeNull();
  });

  it("g. renders GhostMemoryDrawerPanel when activePanel is 'ghost'", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "ghost",
    });
    const { container } = render(<ObservatoryLeftDrawer />);
    const panel = container.querySelector("[data-testid='ghost-memory-drawer-panel']");
    const emptyState = container.querySelector("[data-testid='ghost-memory-empty-state']");
    expect(panel !== null || emptyState !== null).toBe(true);
  });

  it("h. renders nothing in content area when activePanel is null", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: null });
    const { container } = render(<ObservatoryLeftDrawer />);

    // None of the four panel testids should be present
    expect(container.querySelector("[data-testid='explainability-drawer-panel']")).toBeNull();
    expect(container.querySelector("[data-testid='explainability-empty-state']")).toBeNull();
    expect(container.querySelector("[data-testid='mission-drawer-panel']")).toBeNull();
    expect(container.querySelector("[data-testid='mission-empty-state']")).toBeNull();
    expect(container.querySelector("[data-testid='replay-drawer-panel']")).toBeNull();
    expect(container.querySelector("[data-testid='ghost-memory-drawer-panel']")).toBeNull();
    expect(container.querySelector("[data-testid='ghost-memory-empty-state']")).toBeNull();
  });

  it("i. drawer uses drawer-specific bg token (GLS-01)", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: "explainability" });
    const { container } = render(<ObservatoryLeftDrawer />);
    const drawer = container.querySelector("[data-testid='observatory-left-drawer']") as HTMLElement;
    expect(drawer.style.background).toContain("hud-drawer-bg");
  });

  it("i. shows drawer header with panel label when activePanel is set (DRW-01)", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: "explainability", selectedStationId: null });
    const { container } = render(<ObservatoryLeftDrawer />);
    const label = container.querySelector("[data-testid='drawer-header-label']");
    expect(label).not.toBeNull();
    expect(label!.textContent).toBe("EXPLAINABILITY");
  });

  it("j. shows GHOST MEMORY label when activePanel is ghost (DRW-01)", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: "ghost" });
    const { container } = render(<ObservatoryLeftDrawer />);
    const label = container.querySelector("[data-testid='drawer-header-label']");
    expect(label).not.toBeNull();
    expect(label!.textContent).toBe("GHOST MEMORY");
  });

  it("k. close button is present when drawer is open (DRW-02)", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: "mission", mission: null });
    const { container } = render(<ObservatoryLeftDrawer />);
    const closeBtn = container.querySelector("[data-testid='drawer-close-button']");
    expect(closeBtn).not.toBeNull();
  });

  it("l. no header when activePanel is null", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: null });
    const { container } = render(<ObservatoryLeftDrawer />);
    expect(container.querySelector("[data-testid='drawer-header']")).toBeNull();
  });
});
