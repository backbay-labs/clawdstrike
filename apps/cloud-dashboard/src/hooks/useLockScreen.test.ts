import { describe, it, expect, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useLockScreen } from "./useLockScreen";

beforeEach(() => {
  localStorage.clear();
});

describe("useLockScreen", () => {
  it("starts unlocked by default", () => {
    const { result } = renderHook(() => useLockScreen());
    expect(result.current.locked).toBe(false);
  });

  it("starts locked if localStorage says so", () => {
    localStorage.setItem("cs_locked", "true");
    const { result } = renderHook(() => useLockScreen());
    expect(result.current.locked).toBe(true);
  });

  it("locks the screen", () => {
    const { result } = renderHook(() => useLockScreen());
    act(() => result.current.lock());
    expect(result.current.locked).toBe(true);
    expect(localStorage.getItem("cs_locked")).toBe("true");
  });

  it("unlocks the screen", () => {
    localStorage.setItem("cs_locked", "true");
    const { result } = renderHook(() => useLockScreen());
    act(() => result.current.unlock());
    expect(result.current.locked).toBe(false);
    expect(localStorage.getItem("cs_locked")).toBeNull();
  });

  it("stores API key on unlock when provided", () => {
    const { result } = renderHook(() => useLockScreen());
    act(() => result.current.lock());
    act(() => result.current.unlock("my-api-key"));
    expect(localStorage.getItem("hushd_api_key")).toBe("my-api-key");
  });

  it("does not store API key on unlock when not provided", () => {
    const { result } = renderHook(() => useLockScreen());
    act(() => result.current.lock());
    act(() => result.current.unlock());
    expect(localStorage.getItem("hushd_api_key")).toBeNull();
  });
});
