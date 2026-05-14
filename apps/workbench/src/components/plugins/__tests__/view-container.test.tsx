import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { createElement } from "react";
import type { ViewRegistration } from "@/lib/plugins/view-registry";

// We'll import ViewContainer once it exists
import { ViewContainer } from "../view-container";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function GoodComponent(props: { viewId: string; isActive: boolean; storage: any }) {
  return createElement("div", { "data-testid": "good-component" }, `viewId=${props.viewId} active=${String(props.isActive)}`);
}

let shouldThrow = true;

function CrashingComponent(_props: any): never {
  throw new Error("Component exploded");
}

function makeRegistration(overrides?: Partial<ViewRegistration>): ViewRegistration {
  return {
    id: "test-plugin.my-view",
    slot: "editorTab",
    label: "My View",
    component: GoodComponent,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ViewContainer", () => {
  beforeEach(() => {
    shouldThrow = true;
  });

  it("renders the registration component with correct props", () => {
    const reg = makeRegistration();
    render(createElement(ViewContainer, { registration: reg }));

    const el = screen.getByTestId("good-component");
    expect(el.textContent).toContain("viewId=test-plugin.my-view");
    expect(el.textContent).toContain("active=true");
  });

  it("passes isActive=false when specified", () => {
    const reg = makeRegistration();
    render(createElement(ViewContainer, { registration: reg, isActive: false }));

    const el = screen.getByTestId("good-component");
    expect(el.textContent).toContain("active=false");
  });

  it("renders error fallback when component throws", () => {
    // Suppress React error boundary console noise
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    const reg = makeRegistration({ component: CrashingComponent });
    render(createElement(ViewContainer, { registration: reg }));

    expect(screen.getByText("Plugin view crashed")).toBeDefined();
    expect(screen.getByText("Component exploded")).toBeDefined();
    expect(screen.getByText("Reload View")).toBeDefined();

    spy.mockRestore();
  });

  it("clicking Reload View resets the error boundary", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    // Use module-level flag to control crash behavior.
    // shouldThrow starts true (set in beforeEach). After we see the error
    // fallback, we flip it to false so the re-mount after "Reload View"
    // renders successfully.
    function ConditionalCrash(props: any) {
      if (shouldThrow) {
        throw new Error("First render crash");
      }
      return createElement("div", { "data-testid": "recovered" }, "recovered");
    }

    const reg = makeRegistration({ component: ConditionalCrash });
    render(createElement(ViewContainer, { registration: reg }));

    // Should show error fallback
    expect(screen.getByText("Plugin view crashed")).toBeDefined();

    // Flip the flag so the next mount succeeds
    shouldThrow = false;

    // Click reload
    fireEvent.click(screen.getByText("Reload View"));

    // After reset, component re-renders successfully
    expect(screen.getByTestId("recovered")).toBeDefined();

    spy.mockRestore();
  });

  it("provides default no-op storage when not specified", () => {
    let capturedStorage: any = null;
    function StorageCapture(props: any) {
      capturedStorage = props.storage;
      return createElement("div", { "data-testid": "storage-capture" }, "ok");
    }

    const reg = makeRegistration({ component: StorageCapture });
    render(createElement(ViewContainer, { registration: reg }));

    expect(capturedStorage).toBeDefined();
    expect(capturedStorage.get("any-key")).toBeUndefined();
    // set should not throw
    expect(() => capturedStorage.set("key", "value")).not.toThrow();
  });
});
