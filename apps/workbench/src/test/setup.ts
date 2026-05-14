import "@testing-library/jest-dom/vitest";
import { beforeEach } from "vitest";

// jsdom does not implement ResizeObserver. Provide a minimal stub so
// components that rely on it (e.g. PaneTabBar overflow detection) don't
// throw and trip the ErrorBoundary during tests.
// jsdom does not implement Element.getAnimations (Web Animations API).
// @base-ui/react ScrollAreaViewport calls it on a deferred timer, causing
// unhandled exceptions that make vitest exit non-zero despite all tests passing.
if (typeof Element.prototype.getAnimations === "undefined") {
  Element.prototype.getAnimations = () => [];
}

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof globalThis.ResizeObserver;
}

if (typeof Element !== "undefined" && !Element.prototype.getAnimations) {
  Element.prototype.getAnimations = () => [];
}
function createStorageMock(): Storage {
  let store: Record<string, string> = {};

  return {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, value: string) => {
      store[key] = String(value);
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
    key: (index: number) => Object.keys(store)[index] ?? null,
    get length() {
      return Object.keys(store).length;
    },
  };
}

Object.defineProperty(globalThis, "localStorage", {
  value: createStorageMock(),
  configurable: true,
});

beforeEach(() => {
  globalThis.localStorage.clear();
});
