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

// jsdom's Blob/File implementations omit the async `text()` / `arrayBuffer()`
// methods that the browser spec defines. Code that calls `file.text()` (e.g.
// EvidencePack import) blows up under jsdom otherwise. Track construction
// parts in a WeakMap so we can lazily decode them when `text()` is called.
{
  const BlobProto = Blob.prototype as Blob & {
    text?: () => Promise<string>;
    arrayBuffer?: () => Promise<ArrayBuffer>;
  };

  if (typeof BlobProto.text !== "function") {
    type AnyPart = string | Uint8Array | ArrayBuffer | Blob | { text?: () => Promise<string> };
    const partsRegistry = new WeakMap<Blob, ReadonlyArray<AnyPart>>();

    const NativeBlob = globalThis.Blob;
    function PatchedBlob(
      this: Blob,
      parts: ReadonlyArray<AnyPart> = [],
      options?: BlobPropertyBag,
    ) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const instance = new (NativeBlob as any)(parts as BlobPart[], options);
      partsRegistry.set(instance, parts);
      return instance;
    }
    PatchedBlob.prototype = NativeBlob.prototype;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).Blob = PatchedBlob;

    if (typeof File !== "undefined") {
      const NativeFile = globalThis.File;
      function PatchedFile(
        this: File,
        parts: ReadonlyArray<AnyPart> = [],
        name: string,
        options?: FilePropertyBag,
      ) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const instance = new (NativeFile as any)(parts as BlobPart[], name, options);
        partsRegistry.set(instance, parts);
        return instance;
      }
      PatchedFile.prototype = NativeFile.prototype;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (globalThis as any).File = PatchedFile;
    }

    async function partsToText(parts: ReadonlyArray<AnyPart>): Promise<string> {
      let out = "";
      const decoder = new TextDecoder();
      for (const part of parts) {
        if (typeof part === "string") {
          out += part;
        } else if (part instanceof Uint8Array) {
          out += decoder.decode(part);
        } else if (part instanceof ArrayBuffer) {
          out += decoder.decode(new Uint8Array(part));
        } else if (part && typeof (part as { text?: () => Promise<string> }).text === "function") {
          out += await (part as { text: () => Promise<string> }).text();
        } else {
          out += String(part);
        }
      }
      return out;
    }

    BlobProto.text = async function text(this: Blob): Promise<string> {
      const parts = partsRegistry.get(this) ?? [];
      return partsToText(parts);
    };

    if (typeof BlobProto.arrayBuffer !== "function") {
      BlobProto.arrayBuffer = async function arrayBuffer(this: Blob): Promise<ArrayBuffer> {
        const text = await this.text();
        return new TextEncoder().encode(text).buffer as ArrayBuffer;
      };
    }
  }
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
