import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportAsCSV, exportAsJSON } from "./exportData";

let clickSpy: ReturnType<typeof vi.fn>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let appendSpy: any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let removeSpy: any;

beforeEach(() => {
  clickSpy = vi.fn();
  appendSpy = vi.spyOn(document.body, "appendChild").mockImplementation((el) => el);
  removeSpy = vi.spyOn(document.body, "removeChild").mockImplementation((el) => el);
  vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
    if (tag === "a") {
      return { click: clickSpy, href: "", download: "" } as unknown as HTMLElement;
    }
    return document.createElement(tag);
  });
  // jsdom doesn't have URL.createObjectURL — stub it on globalThis
  globalThis.URL.createObjectURL = vi.fn(() => "blob:mock");
  globalThis.URL.revokeObjectURL = vi.fn();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("exportAsCSV", () => {
  it("does nothing for empty array", () => {
    exportAsCSV([], "test");
    expect(clickSpy).not.toHaveBeenCalled();
  });

  it("creates a CSV blob, appends to body, clicks, removes, and revokes URL", () => {
    const data = [
      { name: "Alice", age: 30 },
      { name: "Bob", age: 25 },
    ];
    exportAsCSV(data as Record<string, unknown>[], "people");

    expect(globalThis.URL.createObjectURL).toHaveBeenCalledOnce();
    expect(appendSpy).toHaveBeenCalledOnce();
    expect(clickSpy).toHaveBeenCalledOnce();
    expect(removeSpy).toHaveBeenCalledOnce();

    // Revoke happens after timeout
    vi.advanceTimersByTime(200);
    expect(globalThis.URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock");
  });

  it("handles values with commas and quotes", () => {
    const data = [{ value: 'hello, "world"' }];
    exportAsCSV(data as Record<string, unknown>[], "test");
    expect(globalThis.URL.createObjectURL).toHaveBeenCalledOnce();
  });

  it("handles null/undefined values", () => {
    const data = [{ a: null, b: undefined }];
    exportAsCSV(data as Record<string, unknown>[], "test");
    expect(clickSpy).toHaveBeenCalledOnce();
  });
});

describe("exportAsJSON", () => {
  it("creates a JSON blob and triggers download", () => {
    const data = [{ id: 1 }, { id: 2 }];
    exportAsJSON(data, "events");

    expect(globalThis.URL.createObjectURL).toHaveBeenCalledOnce();
    expect(appendSpy).toHaveBeenCalledOnce();
    expect(clickSpy).toHaveBeenCalledOnce();
    expect(removeSpy).toHaveBeenCalledOnce();
  });
});
