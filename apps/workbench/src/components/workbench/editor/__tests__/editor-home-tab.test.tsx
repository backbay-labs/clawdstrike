import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { EditorHomeTab } from "../editor-home-tab";

const multiDispatch = vi.fn();
const openFile = vi.fn();
const openFileByPath = vi.fn();
const getRecentFiles = vi.fn(() => ["/tmp/example.yaml"]);

const multiPolicyState = {
  tabs: [],
  multiDispatch,
  multiState: { activeTabId: "tab-1" },
  canAddTab: true,
};

vi.mock("@/lib/workbench/multi-policy-store", () => ({
  useMultiPolicy: () => multiPolicyState,
  useWorkbench: () => ({ openFile, openFileByPath }),
}));

vi.mock("@/lib/workbench/policy-store", () => ({
  getRecentFiles: () => getRecentFiles(),
}));

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: () => true,
}));

describe("EditorHomeTab", () => {
  beforeEach(() => {
    multiDispatch.mockReset();
    openFile.mockReset();
    openFileByPath.mockReset();
    getRecentFiles.mockClear();
    multiPolicyState.tabs = [];
    multiPolicyState.canAddTab = true;
  });

  it("memoizes recent file reads across rerenders", () => {
    const { rerender } = render(<EditorHomeTab onNavigateToTab={() => {}} />);

    expect(getRecentFiles).toHaveBeenCalledTimes(1);

    rerender(<EditorHomeTab onNavigateToTab={() => {}} />);

    expect(getRecentFiles).toHaveBeenCalledTimes(1);
  });

  it("disables template buttons when the tab limit is reached", async () => {
    const user = userEvent.setup();
    multiPolicyState.canAddTab = false;

    render(<EditorHomeTab onNavigateToTab={() => {}} />);

    const strictTemplate = screen.getByText(/^strict$/i).closest("button");
    expect(strictTemplate).not.toBeNull();
    expect(strictTemplate).toBeDisabled();

    await user.click(strictTemplate!);

    expect(multiDispatch).not.toHaveBeenCalled();
  });

  it("creates a new YARA rule from the start-new section", async () => {
    const user = userEvent.setup();

    render(<EditorHomeTab onNavigateToTab={() => {}} />);

    await user.click(screen.getByRole("button", { name: /yara rule/i }));

    expect(multiDispatch).toHaveBeenCalledWith({
      type: "NEW_TAB",
      fileType: "yara_rule",
    });
  });
});
