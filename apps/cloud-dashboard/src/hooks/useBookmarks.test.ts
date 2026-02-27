import { describe, it, expect, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useBookmarks } from "./useBookmarks";

beforeEach(() => {
  localStorage.clear();
});

describe("useBookmarks", () => {
  it("starts with empty bookmarks", () => {
    const { result } = renderHook(() => useBookmarks());
    expect(result.current.bookmarks).toEqual({});
  });

  it("toggles a bookmark on", () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.toggleBookmark("evt-1"));
    expect(result.current.isBookmarked("evt-1")).toBe(true);
  });

  it("toggles a bookmark off", () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.toggleBookmark("evt-1"));
    act(() => result.current.toggleBookmark("evt-1"));
    expect(result.current.isBookmarked("evt-1")).toBe(false);
  });

  it("sets a note on a bookmark", () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.toggleBookmark("evt-1"));
    act(() => result.current.setNote("evt-1", "important event"));
    expect(result.current.bookmarks["evt-1"].note).toBe("important event");
  });

  it("persists to localStorage", () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.toggleBookmark("evt-1"));

    const stored = JSON.parse(localStorage.getItem("cs_bookmarks") || "{}");
    expect(stored["evt-1"]).toBeDefined();
    expect(stored["evt-1"].pinned).toBe(true);
  });

  it("loads from localStorage on init", () => {
    localStorage.setItem("cs_bookmarks", JSON.stringify({
      "evt-2": { note: "preloaded", pinned: true, ts: "2026-01-01T00:00:00Z" },
    }));
    const { result } = renderHook(() => useBookmarks());
    expect(result.current.isBookmarked("evt-2")).toBe(true);
    expect(result.current.bookmarks["evt-2"].note).toBe("preloaded");
  });
});
