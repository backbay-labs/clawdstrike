/**
 * replay-drawer-annotations.test.tsx — Phase 42 ANNO-04 / ANNO-05
 *
 * Tests for the Annotations section in ReplayDrawerPanel:
 *   1. Renders "Annotations" heading with empty state "No pins yet" when annotationPins is empty
 *   2. Renders one row per pin, sorted by frameIndex ascending
 *   3. Each row shows truncated note text and frame number
 *   4. Clicking a pin row calls setReplayState with pin's frameIndex
 *   5. Clicking delete button calls removeAnnotationPin with pin's id
 *   6. data-testid="annotation-pin-list" exists on the container
 */

import { describe, expect, it, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ReplayDrawerPanel } from "../components/hud/panels/ReplayDrawerPanel";
import { useObservatoryStore } from "../stores/observatory-store";
import type { ObservatoryAnnotationPin } from "../types";

const initialState = useObservatoryStore.getState();

const makePin = (id: string, frameIndex: number, note: string): ObservatoryAnnotationPin => ({
  id,
  frameIndex,
  timestampMs: frameIndex * 33,
  worldPosition: [frameIndex, 0, 0],
  note,
  districtId: "signal",
});

describe("ReplayDrawerPanel — Annotations section", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      annotationPins: [],
      replay: {
        enabled: false,
        frameIndex: 0,
        frameMs: null,
        selectedSpikeTimestampMs: null,
        selectedDistrictId: null,
        bookmarks: [],
        annotations: [],
        markers: [],
      },
    });
    vi.restoreAllMocks();
  });

  it("1. renders 'Annotations' heading and 'No pins yet' when annotationPins is empty", () => {
    const { container } = render(<ReplayDrawerPanel />);
    expect(container.textContent).toContain("Annotations");
    expect(container.textContent).toContain("No pins yet");
  });

  it("2. renders one row per pin, sorted by frameIndex ascending", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      annotationPins: [
        makePin("pin-c", 50, "Third"),
        makePin("pin-a", 10, "First"),
        makePin("pin-b", 30, "Second"),
      ],
    });
    const { container } = render(<ReplayDrawerPanel />);
    const list = container.querySelector("[data-testid='annotation-pin-list']");
    expect(list).not.toBeNull();
    const rows = list!.querySelectorAll("[data-testid^='annotation-pin-']");
    // 3 pin rows (exclude delete buttons)
    const pinRows = Array.from(rows).filter((el) =>
      el.getAttribute("data-testid")?.match(/^annotation-pin-pin-/),
    );
    expect(pinRows).toHaveLength(3);
    // Sorted by frameIndex: First(10), Second(30), Third(50)
    expect(pinRows[0].textContent).toContain("First");
    expect(pinRows[1].textContent).toContain("Second");
    expect(pinRows[2].textContent).toContain("Third");
  });

  it("3. each row shows note text and frame number", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      annotationPins: [makePin("pin-1", 42, "Suspect process spawn")],
    });
    const { container } = render(<ReplayDrawerPanel />);
    expect(container.textContent).toContain("Suspect process spawn");
    expect(container.textContent).toContain("F42");
  });

  it("4. clicking a pin row calls setReplayState with pin's frameIndex", () => {
    const setReplayStateSpy = vi.spyOn(
      useObservatoryStore.getState().actions,
      "setReplayState",
    );
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      annotationPins: [makePin("pin-jump", 77, "Jump target")],
    });
    const { container } = render(<ReplayDrawerPanel />);
    const pinRow = container.querySelector("[data-testid='annotation-pin-pin-jump']");
    expect(pinRow).not.toBeNull();
    fireEvent.click(pinRow!);
    expect(setReplayStateSpy).toHaveBeenCalledWith({ frameIndex: 77 });
  });

  it("5. clicking delete button calls removeAnnotationPin with pin's id", () => {
    const removeAnnotationPinSpy = vi.spyOn(
      useObservatoryStore.getState().actions,
      "removeAnnotationPin",
    );
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      annotationPins: [makePin("pin-del", 15, "Delete me")],
    });
    const { container } = render(<ReplayDrawerPanel />);
    const deleteBtn = container.querySelector("[data-testid='annotation-pin-delete-pin-del']");
    expect(deleteBtn).not.toBeNull();
    fireEvent.click(deleteBtn!);
    expect(removeAnnotationPinSpy).toHaveBeenCalledWith("pin-del");
  });

  it("6. annotation-pin-list test id exists when pins are present", () => {
    useObservatoryStore.setState({
      ...useObservatoryStore.getState(),
      annotationPins: [makePin("pin-x", 5, "Marker")],
    });
    const { container } = render(<ReplayDrawerPanel />);
    const list = container.querySelector("[data-testid='annotation-pin-list']");
    expect(list).not.toBeNull();
  });
});
