import "@testing-library/jest-dom/vitest";
import "fake-indexeddb/auto";
import { beforeEach, expect as vitestExpect } from "vitest";
import * as matchers from "@testing-library/jest-dom/matchers";

const matcherExpect =
  vitestExpect ??
  (globalThis as typeof globalThis & {
    expect?: { extend: (extensions: typeof matchers) => void };
  }).expect;

matcherExpect?.extend(matchers);

// ResizeObserver polyfill for jsdom — prevents "ResizeObserver is not defined"
// crashes in any test that renders components using ResizablePanelGroup.
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

if (typeof URL.createObjectURL !== "function") {
  URL.createObjectURL = () => "blob:mock-url";
}

if (typeof URL.revokeObjectURL !== "function") {
  URL.revokeObjectURL = () => {};
}

if (typeof HTMLAnchorElement !== "undefined") {
  const originalClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
    if (this.hasAttribute("download") || this.href.startsWith("blob:")) {
      return;
    }
    return originalClick.call(this);
  };
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
