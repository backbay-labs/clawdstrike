import React from "react";
import { useEffect } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { ShortcutProvider } from "../shortcut-provider";
import { InitCommands } from "@/lib/commands/init-commands";
import { useBottomPaneStore } from "@/features/bottom-pane/bottom-pane-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { renderWithProviders } from "@/test/test-helpers";
import { useWorkbenchState } from "@/features/policy/hooks/use-policy-actions";
import { isDesktop } from "@/lib/tauri-bridge";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

function PolicyValidateShortcutHarness({
  initialRoute = "/editor/visual",
}: {
  initialRoute?: string;
}) {
  const { dispatch, state } = useWorkbenchState();

  useEffect(() => {
    usePaneStore.getState().syncRoute(initialRoute);
  }, [initialRoute]);

  return (
    <>
      <button
        type="button"
        onClick={() => dispatch({ type: "UPDATE_META", name: "Shortcut Rename" })}
      >
        rename-policy
      </button>
      <pre data-testid="yaml">{state.yaml}</pre>
      <span data-testid="policy-name">{state.activePolicy.name}</span>
      <span data-testid="sync-direction">{state.ui.editorSyncDirection ?? ""}</span>
      <span data-testid="dirty">{String(state.dirty)}</span>
      <div data-testid="terminal-context" data-shortcut-context="terminal" tabIndex={-1} />
      <InitCommands />
      <ShortcutProvider />
    </>
  );
}

beforeEach(() => {
  vi.mocked(isDesktop).mockReturnValue(false);
  usePaneStore.getState()._reset();
  useBottomPaneStore.getState()._reset();
});

describe("ShortcutProvider", () => {
  it("syncs policy YAML before validating on web", async () => {
    renderWithProviders(<PolicyValidateShortcutHarness />);

    fireEvent.click(screen.getByRole("button", { name: "rename-policy" }));

    expect(screen.getByTestId("policy-name").textContent).toBe("Shortcut Rename");
    expect(screen.getByTestId("dirty").textContent).toBe("true");
    expect(screen.getByTestId("sync-direction").textContent).toBe("");

    fireEvent.keyDown(window, { key: "v", metaKey: true, shiftKey: true });

    await waitFor(() => {
      expect(screen.getByTestId("yaml").textContent).toContain('name: "Shortcut Rename"');
    });

    // After the store migration, the validate command calls editStore.setYaml()
    // directly (bypassing the dispatch that previously set editorSyncDirection).
    // Sync direction is no longer updated by the validate shortcut.
    expect(screen.getByTestId("sync-direction").textContent).toBe("");
  });

  it("does not fire editor-only shortcuts while terminal context is focused", () => {
    renderWithProviders(<PolicyValidateShortcutHarness />);

    fireEvent.click(screen.getByRole("button", { name: "rename-policy" }));

    const terminalContext = screen.getByTestId("terminal-context");
    terminalContext.focus();
    fireEvent.keyDown(terminalContext, { key: "v", metaKey: true, shiftKey: true });

    expect(screen.getByTestId("sync-direction").textContent).toBe("");
  });

  it("re-evaluates shortcut availability when a command's when() predicate flips", () => {
    renderWithProviders(<PolicyValidateShortcutHarness />);

    expect(usePaneStore.getState().paneCount()).toBe(1);

    act(() => {
      const { activePaneId, splitPane } = usePaneStore.getState();
      splitPane(activePaneId, "vertical");
    });

    expect(usePaneStore.getState().paneCount()).toBe(2);

    fireEvent.keyDown(window, { key: "w", metaKey: true, shiftKey: true });

    expect(usePaneStore.getState().paneCount()).toBe(1);
  });

  it("matches shifted symbol shortcuts against browser-reported keys", () => {
    renderWithProviders(<PolicyValidateShortcutHarness />);

    expect(usePaneStore.getState().paneCount()).toBe(1);

    fireEvent.keyDown(window, { key: "|", metaKey: true, shiftKey: true });

    expect(usePaneStore.getState().paneCount()).toBe(2);
  });

  it("treats /file panes as editor shortcut context", async () => {
    renderWithProviders(<PolicyValidateShortcutHarness initialRoute="/file/tmp/policy.yaml" />);

    fireEvent.click(screen.getByRole("button", { name: "rename-policy" }));
    fireEvent.keyDown(window, { key: "v", metaKey: true, shiftKey: true });

    await waitFor(() => {
      expect(screen.getByTestId("yaml").textContent).toContain('name: "Shortcut Rename"');
    });
  });
});
