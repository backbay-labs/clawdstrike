import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { EditorHomeTab } from "../editor-home-tab";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import type { TabMeta } from "@/features/policy/stores/policy-tabs-store";

const getRecentFiles = vi.fn(() => ["/tmp/example.yaml"]);

vi.mock("@/features/policy/stores/policy-store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/policy/stores/policy-store")>();
  return {
    ...actual,
    getRecentFiles: () => getRecentFiles(),
  };
});

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: () => true,
  openDetectionFile: vi.fn(),
  readDetectionFileByPath: vi.fn(),
}));

describe("EditorHomeTab", () => {
  beforeEach(() => {
    getRecentFiles.mockClear();
    // Reset tabs store to default state (single tab)
    usePolicyTabsStore.getState()._reset();
  });

  it("memoizes recent file reads across rerenders", () => {
    const { rerender } = render(<EditorHomeTab onNavigateToTab={() => {}} />);

    expect(getRecentFiles).toHaveBeenCalledTimes(1);

    rerender(<EditorHomeTab onNavigateToTab={() => {}} />);

    expect(getRecentFiles).toHaveBeenCalledTimes(1);
  });

  it("disables template buttons when the tab limit is reached", async () => {
    const user = userEvent.setup();

    // Fill the store with 25 tabs to hit the limit
    const store = usePolicyTabsStore.getState();
    for (let i = 0; i < 24; i++) {
      store.newTab({});
    }

    render(<EditorHomeTab onNavigateToTab={() => {}} />);

    const strictTemplate = screen.getByText(/^strict$/i).closest("button");
    expect(strictTemplate).not.toBeNull();
    expect(strictTemplate).toBeDisabled();

    await user.click(strictTemplate!);

    // Verify no new tab was created beyond 25
    expect(usePolicyTabsStore.getState().tabs.length).toBe(25);
  });

  it("creates a new YARA rule from the start-new section", async () => {
    const user = userEvent.setup();
    const newTabSpy = vi.spyOn(usePolicyTabsStore.getState(), "newTab");

    render(<EditorHomeTab onNavigateToTab={() => {}} />);

    await user.click(screen.getByRole("button", { name: /yara rule/i }));

    expect(newTabSpy).toHaveBeenCalledWith(
      expect.objectContaining({ fileType: "yara_rule" }),
    );

    newTabSpy.mockRestore();
  });
});
