/**
 * observatory-left-drawer.test.tsx
 *
 * Unit tests for ObservatoryLeftDrawer:
 *   a. renders drawer container (data-testid present)
 *   b. drawer is hidden (translateX -100%) when activePanel is null
 *   c. drawer is visible (translateX 0) when activePanel is set
 *   d. shows active panel name as placeholder text (uppercase)
 *   e. switching panels updates placeholder text
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

  it("d. shows active panel name as placeholder", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "mission",
    });
    const { container } = render(<ObservatoryLeftDrawer />);
    const panelName = container.querySelector(
      "[data-testid='observatory-left-drawer-panel-name']",
    );
    expect(panelName).not.toBeNull();
    // textContent is the raw value ("mission"); CSS textTransform: uppercase is visual-only
    expect(panelName?.textContent?.toUpperCase()).toContain("MISSION");
  });

  it("e. switching panels updates placeholder text", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      activePanel: "explainability",
    });
    const { container, rerender } = render(<ObservatoryLeftDrawer />);

    // Initial state: explainability
    const panelName = container.querySelector(
      "[data-testid='observatory-left-drawer-panel-name']",
    );
    expect(panelName?.textContent?.toUpperCase()).toContain("EXPLAINABILITY");

    // Switch to ghost
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), activePanel: "ghost" });
    rerender(<ObservatoryLeftDrawer />);

    const updatedPanelName = container.querySelector(
      "[data-testid='observatory-left-drawer-panel-name']",
    );
    expect(updatedPanelName?.textContent?.toUpperCase()).toContain("GHOST");
  });
});
