import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the dev-console-store to avoid pulling in React / registry deps
vi.mock("../../plugin-registry", () => ({
  pluginRegistry: {
    subscribe: vi.fn(),
    get: vi.fn(),
    unregister: vi.fn(),
    register: vi.fn(),
  },
}));

vi.mock("../dev-console-store", () => {
  const events: unknown[] = [];
  return {
    devConsoleStore: {
      push: vi.fn((event: unknown) => events.push(event)),
      getEvents: () => events,
      clear: () => {
        events.length = 0;
      },
    },
    __events: events,
  };
});

import { interceptConsole, stopIntercepting } from "../console-interceptor";
import { devConsoleStore } from "../dev-console-store";

// Save real console methods before any interception
const realLog = console.log;
const realWarn = console.warn;
const realError = console.error;

beforeEach(() => {
  // Reset mock call counts
  vi.mocked(devConsoleStore.push).mockClear();
  // Ensure console is in pristine state
  stopIntercepting();
  console.log = realLog;
  console.warn = realWarn;
  console.error = realError;
});

afterEach(() => {
  stopIntercepting();
  console.log = realLog;
  console.warn = realWarn;
  console.error = realError;
});

describe("interceptConsole", () => {
  describe("push/pop stack", () => {
    it("intercepts plugin-a then plugin-b, console.log attributed to plugin-b", () => {
      const disposeA = interceptConsole("plugin-a");
      const disposeB = interceptConsole("plugin-b");

      console.log("hello");

      // The most recent push should be attributed to plugin-b (top of stack)
      expect(devConsoleStore.push).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "console:log",
          pluginId: "plugin-b",
          message: "hello",
        }),
      );

      disposeB();
      disposeA();
    });

    it("after disposing plugin-b, console.log attributed to plugin-a", () => {
      const disposeA = interceptConsole("plugin-a");
      const disposeB = interceptConsole("plugin-b");
      disposeB(); // pop B

      console.log("after-b-disposed");

      expect(devConsoleStore.push).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "console:log",
          pluginId: "plugin-a",
          message: "after-b-disposed",
        }),
      );

      disposeA();
    });
  });

  describe("empty stack", () => {
    it("after disposing all interceptors, console.log calls original without pushing", () => {
      const disposeA = interceptConsole("plugin-a");
      disposeA();

      vi.mocked(devConsoleStore.push).mockClear();
      console.log("no-intercept");

      // No events should have been pushed
      expect(devConsoleStore.push).not.toHaveBeenCalled();
    });
  });

  describe("concurrent plugins", () => {
    it("intercept A and B, verify log attributed to top-of-stack", () => {
      const disposeA = interceptConsole("plugin-a");
      const disposeB = interceptConsole("plugin-b");

      console.log("first");
      expect(devConsoleStore.push).toHaveBeenLastCalledWith(
        expect.objectContaining({ pluginId: "plugin-b" }),
      );

      // Dispose B, now A is on top
      disposeB();
      console.log("second");
      expect(devConsoleStore.push).toHaveBeenLastCalledWith(
        expect.objectContaining({ pluginId: "plugin-a" }),
      );

      disposeA();
    });
  });

  describe("warn and error interception", () => {
    it("intercepts console.warn and attributes to top-of-stack plugin", () => {
      const dispose = interceptConsole("plugin-warn");

      console.warn("warning message");

      expect(devConsoleStore.push).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "console:warn",
          pluginId: "plugin-warn",
          message: "warning message",
        }),
      );

      dispose();
    });

    it("intercepts console.error and attributes to top-of-stack plugin", () => {
      const dispose = interceptConsole("plugin-err");

      console.error("error message");

      expect(devConsoleStore.push).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "console:error",
          pluginId: "plugin-err",
          message: "error message",
        }),
      );

      dispose();
    });
  });

  describe("stopIntercepting", () => {
    it("resets entire stack and restores original console", () => {
      interceptConsole("plugin-a");
      interceptConsole("plugin-b");

      stopIntercepting();

      vi.mocked(devConsoleStore.push).mockClear();
      console.log("after-stop");

      // Should NOT push any events
      expect(devConsoleStore.push).not.toHaveBeenCalled();

      // Console methods should be back to originals
      expect(console.log).toBe(realLog);
      expect(console.warn).toBe(realWarn);
      expect(console.error).toBe(realError);
    });
  });
});
