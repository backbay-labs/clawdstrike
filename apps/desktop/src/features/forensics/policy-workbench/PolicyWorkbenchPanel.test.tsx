// @vitest-environment jsdom

import * as React from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { POLICY_WORKBENCH_DIRTY_EVENT, type PolicyWorkbenchDirtyEventDetail } from "./events";

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

const globalWithRegistry = globalThis as typeof globalThis & {
  __sdr_require__?: Record<string, unknown>;
};
const registry =
  globalWithRegistry.__sdr_require__ ?? (globalWithRegistry.__sdr_require__ = Object.create(null));
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
  GlassPanel: ({ children, ...rest }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...rest}>{children}</div>
  ),
  GlassHeader: ({ children, ...rest }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...rest}>{children}</div>
  ),
  Badge: ({ children, ...rest }: React.HTMLAttributes<HTMLSpanElement>) => (
    <span {...rest}>{children}</span>
  ),
  GlowButton: ({ children, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button type={rest.type ?? "button"} {...rest}>
      {children}
    </button>
  ),
  GlowInput: (props: React.InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
  GlassTextarea: (props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) => (
    <textarea {...props} />
  ),
  CodeBlock: ({
    code,
    showLineNumbers: _showLineNumbers,
    maxHeight: _maxHeight,
    language: _language,
    copyable: _copyable,
    ...rest
  }: {
    code: string;
    language?: string;
    copyable?: boolean;
    showLineNumbers?: boolean;
    maxHeight?: string | number;
  } & React.HTMLAttributes<HTMLPreElement>) => <pre {...rest}>{code}</pre>,
  Tabs: ({
    value,
    onValueChange,
    children,
    ...rest
  }: React.HTMLAttributes<HTMLDivElement> & {
    value?: string;
    onValueChange?: (value: string) => void;
  }) => {
    const TabsContext =
      (
        globalThis as {
          __policyWorkbenchTabsContext?: React.Context<{
            value?: string;
            onValueChange?: (value: string) => void;
          }>;
        }
      ).__policyWorkbenchTabsContext ??
      ((
        globalThis as {
          __policyWorkbenchTabsContext?: React.Context<{
            value?: string;
            onValueChange?: (value: string) => void;
          }>;
        }
      ).__policyWorkbenchTabsContext = React.createContext<{
        value?: string;
        onValueChange?: (value: string) => void;
      }>({}));

    return (
      <TabsContext.Provider value={{ value, onValueChange }}>
        <div {...rest}>{children}</div>
      </TabsContext.Provider>
    );
  },
  TabsList: ({ children, ...rest }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...rest}>{children}</div>
  ),
  TabsTrigger: ({
    value,
    children,
    onClick,
    ...rest
  }: React.ButtonHTMLAttributes<HTMLButtonElement> & { value: string }) => {
    const TabsContext = (
      globalThis as {
        __policyWorkbenchTabsContext?: React.Context<{
          value?: string;
          onValueChange?: (value: string) => void;
        }>;
      }
    ).__policyWorkbenchTabsContext!;
    const ctx = React.useContext(TabsContext);
    const selected = ctx?.value === value;
    return (
      <button
        type="button"
        data-state={selected ? "active" : "inactive"}
        {...rest}
        onClick={(event) => {
          ctx?.onValueChange?.(value);
          onClick?.(event);
        }}
      >
        {children}
      </button>
    );
  },
  TabsContent: ({
    value,
    children,
    ...rest
  }: React.HTMLAttributes<HTMLDivElement> & { value: string }) => {
    const TabsContext = (
      globalThis as {
        __policyWorkbenchTabsContext?: React.Context<{
          value?: string;
        }>;
      }
    ).__policyWorkbenchTabsContext!;
    const ctx = React.useContext(TabsContext);
    if (ctx?.value !== value) return null;
    return <div {...rest}>{children}</div>;
  },
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
    window.addEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirty);

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
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    expect(editor).toBeTruthy();

    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
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
      '[data-testid="policy-editor-save"]',
    ) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(false);

    await act(async () => {
      saveButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(savePolicyMock).toHaveBeenCalledWith(expect.stringContaining('name: "edited"'));

    const testTab = container.querySelector(
      '[data-testid="policy-workbench-tab-test"]',
    ) as HTMLButtonElement;
    await act(async () => {
      testTab.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    const targetInput = container.querySelector(
      '[data-testid="policy-test-target"]',
    ) as HTMLInputElement;
    const inputValueSetter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set;
    if (!inputValueSetter) throw new Error("Missing input value setter");

    await act(async () => {
      inputValueSetter.call(targetInput, "/tmp/demo.txt");
      targetInput.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const runButton = container.querySelector(
      '[data-testid="policy-test-run"]',
    ) as HTMLButtonElement;
    await act(async () => {
      runButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(evalPolicyEventMock).toHaveBeenCalledTimes(1);
    expect(
      container.querySelectorAll('[data-testid="policy-test-history-item"]').length,
    ).toBeGreaterThan(0);

    window.removeEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirty);
  });

  it("does not auto-reload over dirty drafts when connection is restored", async () => {
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc123",
      yaml: 'version: "1.2.0"\nname: "server-a"\n',
    });
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc999",
      yaml: 'version: "1.2.0"\nname: "server-b"\n',
    });

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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "local-dirty"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await act(async () => {
      root.render(<PolicyWorkbenchPanel daemonUrl="http://localhost:9876" connected={false} />);
      await Promise.resolve();
    });

    await act(async () => {
      root.render(<PolicyWorkbenchPanel daemonUrl="http://localhost:9876" connected />);
      await Promise.resolve();
      vi.advanceTimersByTime(600);
      await Promise.resolve();
    });

    expect(loadPolicyMock).toHaveBeenCalledTimes(1);
    expect(editor.value).toContain('name: "local-dirty"');
  });

  it("reloads policy when daemonUrl changes while connected", async () => {
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc123",
      yaml: 'version: "1.2.0"\nname: "server-a"\n',
    });
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "def456",
      yaml: 'version: "1.2.0"\nname: "server-b"\n',
    });

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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    expect(editor.value).toContain('name: "server-a"');

    await act(async () => {
      root.render(<PolicyWorkbenchPanel daemonUrl="http://localhost:9999" connected />);
      await Promise.resolve();
    });

    await act(async () => {
      await Promise.resolve();
    });

    expect(loadPolicyMock).toHaveBeenCalledTimes(2);
    expect(editor.value).toContain('name: "server-b"');
  });

  it("preserves newer draft edits when save response returns for an older snapshot", async () => {
    let resolveSave:
      | ((value: { success: boolean; message: string; policy_hash: string }) => void)
      | undefined;
    savePolicyMock.mockImplementation(
      () =>
        new Promise<{ success: boolean; message: string; policy_hash: string }>((resolve) => {
          resolveSave = resolve;
        }),
    );

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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "save-snapshot"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const saveButton = container.querySelector(
      '[data-testid="policy-editor-save"]',
    ) as HTMLButtonElement;

    await act(async () => {
      saveButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(editor.readOnly).toBe(true);

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "newer-local-edit"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });

    await act(async () => {
      resolveSave?.({ success: true, message: "saved", policy_hash: "zzz123" });
      await Promise.resolve();
    });

    expect(editor.value).toContain('name: "newer-local-edit"');
  });

  it("disables save and prevents save requests when disconnected", async () => {
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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "dirty-while-online"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await act(async () => {
      root.render(<PolicyWorkbenchPanel daemonUrl="http://localhost:9876" connected={false} />);
      await Promise.resolve();
    });

    validatePolicyMock.mockClear();
    savePolicyMock.mockClear();

    const saveButton = container.querySelector(
      '[data-testid="policy-editor-save"]',
    ) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(true);

    await act(async () => {
      saveButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(validatePolicyMock).not.toHaveBeenCalled();
    expect(savePolicyMock).not.toHaveBeenCalled();
  });

  it("asks for confirmation before reload when draft is dirty", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc123",
      yaml: 'version: "1.2.0"\nname: "server-a"\n',
    });
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc999",
      yaml: 'version: "1.2.0"\nname: "server-b"\n',
    });

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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "local-dirty"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const reloadButton = container.querySelector(
      '[data-testid="policy-editor-reload"]',
    ) as HTMLButtonElement;
    await act(async () => {
      reloadButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(loadPolicyMock).toHaveBeenCalledTimes(1);
    expect(editor.value).toContain('name: "local-dirty"');

    confirmSpy.mockRestore();
  });

  it("applies confirmed reload even if draft changes while reload is in-flight", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    loadPolicyMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc123",
      yaml: 'version: "1.2.0"\nname: "server-a"\n',
    });

    let resolveReload:
      | ((value: {
          name: string;
          version: string;
          description: string;
          policy_hash: string;
          yaml: string;
        }) => void)
      | undefined;
    loadPolicyMock.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveReload = resolve as typeof resolveReload;
        }),
    );

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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "local-before-reload"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const reloadButton = container.querySelector(
      '[data-testid="policy-editor-reload"]',
    ) as HTMLButtonElement;
    await act(async () => {
      reloadButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(loadPolicyMock).toHaveBeenCalledTimes(2);

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "typed-after-confirm"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });

    await act(async () => {
      resolveReload?.({
        name: "default",
        version: "1.2.0",
        description: "",
        policy_hash: "abc999",
        yaml: 'version: "1.2.0"\nname: "server-b"\n',
      });
      await Promise.resolve();
    });

    expect(editor.value).toContain('name: "server-b"');
    confirmSpy.mockRestore();
  });

  it("ignores stale load responses that resolve after user starts editing", async () => {
    let resolveLoad:
      | ((value: {
          name: string;
          version: string;
          description: string;
          policy_hash: string;
          yaml: string;
        }) => void)
      | undefined;
    loadPolicyMock.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveLoad = resolve as typeof resolveLoad;
        }),
    );

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    const { PolicyWorkbenchPanel } = await import("./PolicyWorkbenchPanel");

    await act(async () => {
      root.render(<PolicyWorkbenchPanel daemonUrl="http://localhost:9876" connected />);
      await Promise.resolve();
    });

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "local-edits-before-load"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });

    await act(async () => {
      resolveLoad?.({
        name: "default",
        version: "1.2.0",
        description: "",
        policy_hash: "server123",
        yaml: 'version: "1.2.0"\nname: "server-loaded"\n',
      });
      await Promise.resolve();
    });

    expect(loadPolicyMock).toHaveBeenCalledTimes(1);
    expect(editor.value).toContain('name: "local-edits-before-load"');
  });

  it("renders validation warnings when policy validates with warnings", async () => {
    validatePolicyMock.mockResolvedValue({
      valid: true,
      errors: [],
      warnings: [
        {
          path: "guards[0]",
          code: "policy_deprecated_field",
          message: "deprecated field",
        },
      ],
    });

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

    expect(container.textContent).toContain("Validation warnings");
    expect(container.textContent).toContain("[policy_deprecated_field]");
  });

  it("emits dirty false when the panel unmounts", async () => {
    const dirtyEvents: boolean[] = [];
    const onDirty = (event: Event) => {
      const custom = event as CustomEvent<PolicyWorkbenchDirtyEventDetail>;
      dirtyEvents.push(Boolean(custom.detail?.dirty));
    };
    window.addEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirty);

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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "dirty-before-unmount"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });

    expect(dirtyEvents).toContain(true);

    await act(async () => {
      root.render(<div />);
      await Promise.resolve();
    });

    expect(dirtyEvents[dirtyEvents.length - 1]).toBe(false);
    window.removeEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirty);
  });

  it("cancels pending debounced validation while save validation is in-flight", async () => {
    let resolveSave:
      | ((value: { success: boolean; message: string; policy_hash: string }) => void)
      | undefined;
    savePolicyMock.mockImplementation(
      () =>
        new Promise<{ success: boolean; message: string; policy_hash: string }>((resolve) => {
          resolveSave = resolve;
        }),
    );

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

    validatePolicyMock.mockClear();

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "save-race"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });

    const saveButton = container.querySelector(
      '[data-testid="policy-editor-save"]',
    ) as HTMLButtonElement;
    await act(async () => {
      saveButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(validatePolicyMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(650);
      await Promise.resolve();
    });

    expect(validatePolicyMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolveSave?.({ success: true, message: "saved", policy_hash: "save123" });
      await Promise.resolve();
    });
  });

  it("surfaces validation error state when save-time validation request fails", async () => {
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

    const editor = container.querySelector(
      '[data-testid="policy-editor-textarea"]',
    ) as HTMLTextAreaElement;
    const editorValueSetter = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set;
    if (!editorValueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      editorValueSetter.call(editor, 'version: "1.2.0"\nname: "validate-error"\n');
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });

    validatePolicyMock.mockRejectedValueOnce(new Error("daemon disconnected"));

    const saveButton = container.querySelector(
      '[data-testid="policy-editor-save"]',
    ) as HTMLButtonElement;
    await act(async () => {
      saveButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
    });

    expect(savePolicyMock).not.toHaveBeenCalled();
    expect(container.textContent).toContain("Validation Error");
    expect(container.textContent).toContain("daemon disconnected");
  });
});
