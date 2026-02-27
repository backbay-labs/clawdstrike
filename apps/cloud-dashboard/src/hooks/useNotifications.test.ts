import { describe, it, expect } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useNotifications } from "./useNotifications";

describe("useNotifications", () => {
  it("starts empty", () => {
    const { result } = renderHook(() => useNotifications());
    expect(result.current.notifications).toHaveLength(0);
    expect(result.current.unreadCount).toBe(0);
  });

  it("adds a notification", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.add("Test notification"));
    expect(result.current.notifications).toHaveLength(1);
    expect(result.current.notifications[0].message).toBe("Test notification");
    expect(result.current.notifications[0].type).toBe("info");
    expect(result.current.notifications[0].read).toBe(false);
  });

  it("adds notifications with custom type", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.add("Error!", "error"));
    expect(result.current.notifications[0].type).toBe("error");
  });

  it("counts unread correctly", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.add("One"));
    act(() => result.current.add("Two"));
    expect(result.current.unreadCount).toBe(2);
  });

  it("marks all as read", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.add("One"));
    act(() => result.current.add("Two"));
    act(() => result.current.markAllRead());
    expect(result.current.unreadCount).toBe(0);
    expect(result.current.notifications.every((n) => n.read)).toBe(true);
  });

  it("clears all notifications", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.add("One"));
    act(() => result.current.clear());
    expect(result.current.notifications).toHaveLength(0);
  });

  it("caps at 100 notifications", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => {
      for (let i = 0; i < 110; i++) {
        result.current.add(`Notif ${i}`);
      }
    });
    expect(result.current.notifications).toHaveLength(100);
  });

  it("newest notification appears first", () => {
    const { result } = renderHook(() => useNotifications());
    act(() => result.current.add("First"));
    act(() => result.current.add("Second"));
    expect(result.current.notifications[0].message).toBe("Second");
  });
});
