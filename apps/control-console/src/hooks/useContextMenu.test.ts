import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useContextMenu } from "./useContextMenu";

describe("useContextMenu", () => {
  it("starts hidden", () => {
    const { result } = renderHook(() => useContextMenu());
    expect(result.current.state.visible).toBe(false);
  });

  it("shows the menu at given position with items", () => {
    const { result } = renderHook(() => useContextMenu());
    const items = [
      { label: "Copy", action: () => {} },
      { label: "Paste", action: () => {} },
    ];

    act(() => result.current.show(100, 200, items));

    expect(result.current.state.visible).toBe(true);
    expect(result.current.state.x).toBe(100);
    expect(result.current.state.y).toBe(200);
    expect(result.current.state.items).toHaveLength(2);
  });

  it("hides the menu", () => {
    const { result } = renderHook(() => useContextMenu());
    act(() => result.current.show(0, 0, [{ label: "Test", action: () => {} }]));
    act(() => result.current.hide());
    expect(result.current.state.visible).toBe(false);
  });
});
