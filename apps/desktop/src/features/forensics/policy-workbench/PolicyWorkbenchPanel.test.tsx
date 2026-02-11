// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import * as React from "react";

import {
  POLICY_WORKBENCH_DIRTY_EVENT,
  type PolicyWorkbenchDirtyEventDetail,
} from "./events";

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

const globalWithRegistry = globalThis as typeof globalThis & {
  __sdr_require__?: Record<string, unknown>;
};
const registry =
  globalWithRegistry.__sdr_require__ ??
  (globalWithRegistry.__sdr_require__ = Object.create(null));
registry.react = (React as unknown as { default?: unknown }).default ?? React;

if (typeof (globalThis as Record<string, unknown>).require !== "function") {
  (globalThis as Record<string, unknown>).require = (name: string) => {
    if (name === "react") return (React as unknown as { default?: unknown }).default ?? React;
    throw new Error(`Unsupported dynamic require: ${name}`);
  };
}

const loadPolicyMock = vi.fn();
const validatePolicyMock = vi.fn();
const savePolicyMock = vi.fn();
const evalPolicyEventMock = vi.fn();

vi.mock("@/services/policyWorkbenchClient", () => {
  class MockPolicyWorkbenchClient {
    loadPolicy = loadPolicyMock;
    validatePolicy = validatePolicyMock;
    savePolicy = savePolicyMock;
    evalPolicyEvent = evalPolicyEventMock;
  }

  class MockPolicyWorkbenchClientError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  }

  return {
    PolicyWorkbenchClient: MockPolicyWorkbenchClient,
    PolicyWorkbenchClientError: MockPolicyWorkbenchClientError,
  };
});

vi.mock("@backbay/glia/primitives", () => ({
  Badge: ({
    children,
    ...rest
  }: React.HTMLAttributes<HTMLSpanElement>) => <span {...rest}>{children}</span>,
  GlowButton: ({
    children,
    ...rest
  }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button type={rest.type ?? "button"} {...rest}>
      {children}
    </button>
  ),
  GlowInput: (props: React.InputHTMLAttributes<HTMLInputElement>) => (
    <input {...props} />
  ),
}));

describe("PolicyWorkbenchPanel", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    vi.useFakeTimers();
    loadPolicyMock.mockReset();
    validatePolicyMock.mockReset();
    savePolicyMock.mockReset();
    evalPolicyEventMock.mockReset();

    loadPolicyMock.mockResolvedValue({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc123",
      yaml: 'version: "1.2.0"\nname: "default"\n',
    });
    validatePolicyMock.mockResolvedValue({ valid: true, errors: [], warnings: [] });
    savePolicyMock.mockResolvedValue({ success: true, message: "saved", policy_hash: "def456" });
    evalPolicyEventMock.mockResolvedValue({
      version: 1,
      command: "policy_eval",
      decision: {
        allowed: true,
        denied: false,
        warn: false,
        guard: "forbidden_path",
        severity: "low",
        message: "allowed",
      },
      report: {
        overall: {
          allowed: true,
          guard: "forbidden_path",
          severity: "info",
          message: "allowed",
        },
        per_guard: [],
      },
    });
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.useRealTimers();
  });

  it("supports load/edit/validate/save/test flow and emits dirty events", async () => {
    const dirtyEvents: boolean[] = [];
    const onDirty = (event: Event) => {
      const custom = event as CustomEvent<PolicyWorkbenchDirtyEventDetail>;
      dirtyEvents.push(Boolean(custom.detail?.dirty));
    };
    window.addEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirty as EventListener);

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    const { PolicyWorkbenchPanel } = await import("./PolicyWorkbenchPanel");

    await act(async () => {
      root.render(<PolicyWorkbenchPanel daemonUrl="http://localhost:9876" connected />);
    });

    await act(async () => {
      await Promise.resolve();
      vi.advanceTimersByTime(600);
      await Promise.resolve();
    });

    expect(loadPolicyMock).toHaveBeenCalledTimes(1);
    expect(validatePolicyMock).toHaveBeenCalled();

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]'
    ) as HTMLTextAreaElement;
    expect(editor).toBeTruthy();

    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value"
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "edited"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await act(async () => {
      vi.advanceTimersByTime(600);
      await Promise.resolve();
    });

    expect(validatePolicyMock).toHaveBeenCalled();
    const latestValidationCall =
      validatePolicyMock.mock.calls[validatePolicyMock.mock.calls.length - 1];
    const latestValidationArg = latestValidationCall?.[0];
    expect(String(latestValidationArg)).toContain('name: "edited"');
    expect(dirtyEvents).toContain(true);

    const saveButton = container.querySelector(
      '[data-testid="policy-editor-save"]'
    ) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(false);

    await act(async () => {
      saveButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(savePolicyMock).toHaveBeenCalledWith(
      expect.stringContaining('name: "edited"')
    );

    const testTab = container.querySelector(
      '[data-testid="policy-workbench-tab-test"]'
    ) as HTMLButtonElement;
    await act(async () => {
      testTab.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    const targetInput = container.querySelector(
      '[data-testid="policy-test-target"]'
    ) as HTMLInputElement;
    const inputValueSetter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value"
    )?.set;
    if (!inputValueSetter) throw new Error("Missing input value setter");

    await act(async () => {
      inputValueSetter.call(targetInput, "/tmp/demo.txt");
      targetInput.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const runButton = container.querySelector(
      '[data-testid="policy-test-run"]'
    ) as HTMLButtonElement;
    await act(async () => {
      runButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(evalPolicyEventMock).toHaveBeenCalledTimes(1);
    expect(
      container.querySelectorAll('[data-testid="policy-test-history-item"]').length
    ).toBeGreaterThan(0);

    window.removeEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirty as EventListener);
  });
});
