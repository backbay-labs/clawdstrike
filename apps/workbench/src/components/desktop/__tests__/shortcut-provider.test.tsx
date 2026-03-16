import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { ShortcutProvider } from "../shortcut-provider";
import { renderWithProviders } from "@/test/test-helpers";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { isDesktop } from "@/lib/tauri-bridge";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

function PolicyValidateShortcutHarness() {
  const { dispatch, state } = useWorkbench();

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
      <ShortcutProvider />
    </>
  );
}

beforeEach(() => {
  vi.mocked(isDesktop).mockReturnValue(false);
});

describe("ShortcutProvider", () => {
  it("syncs policy YAML before validating on web", () => {
    renderWithProviders(<PolicyValidateShortcutHarness />);

    fireEvent.click(screen.getByRole("button", { name: "rename-policy" }));

    expect(screen.getByTestId("policy-name").textContent).toBe("Shortcut Rename");
    expect(screen.getByTestId("dirty").textContent).toBe("true");
    expect(screen.getByTestId("sync-direction").textContent).toBe("");

    fireEvent.keyDown(window, { key: "v", metaKey: true, shiftKey: true });

    expect(screen.getByTestId("yaml").textContent).toContain('name: "Shortcut Rename"');
    expect(screen.getByTestId("sync-direction").textContent).toBe("yaml");
  });
});
