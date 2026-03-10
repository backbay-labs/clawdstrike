import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ClaudeCodeHint } from "../claude-code-hint";

// ---------------------------------------------------------------------------
// Mock the hint settings hook (useHintSettingsSafe)
// ---------------------------------------------------------------------------

const mockGetHint = vi.hoisted(() => vi.fn());
const mockShowHints = vi.hoisted(() => ({ value: true }));
const mockCtx = vi.hoisted(() => ({ value: null as object | null }));

vi.mock("@/lib/workbench/use-hint-settings", () => ({
  useHintSettingsSafe: () => mockCtx.value,
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setupContextMock(overrides?: { showHints?: boolean }) {
  const show = overrides?.showHints ?? true;
  mockShowHints.value = show;
  mockCtx.value = {
    showHints: show,
    setShowHints: vi.fn(),
    getHint: mockGetHint,
    updateHint: vi.fn(),
    resetHint: vi.fn(),
    resetAll: vi.fn(),
    isCustomized: vi.fn().mockReturnValue(false),
  };
}

function clearContextMock() {
  mockCtx.value = null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ClaudeCodeHint", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearContextMock();
  });

  // -------------------------------------------------------------------------
  // Raw props rendering (no hintId)
  // -------------------------------------------------------------------------

  it("renders hint text and copy button with raw props", () => {
    render(<ClaudeCodeHint hint="Test hint text" prompt="Test prompt text" />);

    expect(screen.getByText("Test hint text")).toBeInTheDocument();
    expect(screen.getByText("Copy prompt")).toBeInTheDocument();
  });

  it("renders nothing when neither hint nor prompt is provided", () => {
    const { container } = render(<ClaudeCodeHint />);
    expect(container.firstChild).toBeNull();
  });

  it("still renders when showHints is false and raw props are provided (no hintId)", () => {
    setupContextMock({ showHints: false });

    render(<ClaudeCodeHint hint="Raw hint" prompt="Raw prompt" />);
    expect(screen.getByText("Raw hint")).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Store-based rendering (with hintId)
  // -------------------------------------------------------------------------

  it("renders hint from store when hintId is provided", () => {
    setupContextMock();
    mockGetHint.mockReturnValue({
      hint: "Store hint text",
      prompt: "Store prompt text",
    });

    render(<ClaudeCodeHint hintId="home.audit" />);

    expect(screen.getByText("Store hint text")).toBeInTheDocument();
    expect(mockGetHint).toHaveBeenCalledWith("home.audit");
  });

  it("returns null when showHints is false and hintId is provided", () => {
    setupContextMock({ showHints: false });
    mockGetHint.mockReturnValue({
      hint: "Should not appear",
      prompt: "Should not appear",
    });

    const { container } = render(<ClaudeCodeHint hintId="home.audit" />);
    expect(container.firstChild).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Props override store
  // -------------------------------------------------------------------------

  it("explicit props override store values when both hintId and props are provided", () => {
    setupContextMock();
    mockGetHint.mockReturnValue({
      hint: "Store hint",
      prompt: "Store prompt",
    });

    render(
      <ClaudeCodeHint
        hintId="home.audit"
        hint="Override hint"
        prompt="Override prompt"
      />,
    );

    expect(screen.getByText("Override hint")).toBeInTheDocument();
  });

  it("partial prop override: hint from props, prompt from store", () => {
    setupContextMock();
    mockGetHint.mockReturnValue({
      hint: "Store hint",
      prompt: "Store prompt",
    });

    render(<ClaudeCodeHint hintId="home.audit" hint="Override hint only" />);

    expect(screen.getByText("Override hint only")).toBeInTheDocument();
    // The prompt from store is used internally for the copy action
  });

  // -------------------------------------------------------------------------
  // Copy button behavior
  //
  // NOTE: userEvent.setup() installs its own Clipboard stub on
  // navigator.clipboard, so we spy on that stub AFTER render (before
  // the click) to intercept the component's writeText call.
  // -------------------------------------------------------------------------

  it("copy button copies prompt to clipboard", async () => {
    const user = userEvent.setup();
    render(<ClaudeCodeHint hint="Copy test" prompt="The prompt to copy" />);

    // Spy on the clipboard stub that userEvent installed
    const spy = vi.spyOn(navigator.clipboard, "writeText");

    await user.click(screen.getByText("Copy prompt"));

    expect(spy).toHaveBeenCalledWith("The prompt to copy");
    spy.mockRestore();
  });

  it("shows 'Copied' feedback after click", async () => {
    const user = userEvent.setup();
    render(<ClaudeCodeHint hint="Copy test" prompt="prompt" />);

    await user.click(screen.getByText("Copy prompt"));

    expect(screen.getByText("Copied")).toBeInTheDocument();
  });

  it("copy button copies store prompt when hintId is used without prompt prop", async () => {
    setupContextMock();
    mockGetHint.mockReturnValue({
      hint: "Hint",
      prompt: "Store prompt for copy",
    });

    const user = userEvent.setup();
    render(<ClaudeCodeHint hintId="editor.validate" />);

    // Spy on the clipboard stub that userEvent installed
    const spy = vi.spyOn(navigator.clipboard, "writeText");

    await user.click(screen.getByText("Copy prompt"));

    expect(spy).toHaveBeenCalledWith("Store prompt for copy");
    spy.mockRestore();
  });

  it("does not crash when clipboard API fails", async () => {
    const user = userEvent.setup();
    render(<ClaudeCodeHint hint="Fail test" prompt="prompt" />);

    // Make the clipboard stub reject
    const spy = vi
      .spyOn(navigator.clipboard, "writeText")
      .mockRejectedValue(new Error("Clipboard not available"));

    await user.click(screen.getByText("Copy prompt"));

    // After a failed write, setCopied(true) never runs, so component remains stable
    // The hint text should still be visible
    expect(screen.getByText("Fail test")).toBeInTheDocument();
    // "Copy prompt" button should still show (not "Copied")
    expect(screen.getByText("Copy prompt")).toBeInTheDocument();
    spy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // Context not available (useHintSettingsSafe returns null)
  // -------------------------------------------------------------------------

  it("renders with raw props when provider is not mounted", () => {
    clearContextMock();

    render(<ClaudeCodeHint hint="No provider" prompt="Still works" />);

    expect(screen.getByText("No provider")).toBeInTheDocument();
  });

  it("renders empty when hintId is provided but no provider is mounted", () => {
    clearContextMock();

    // Without context, hintId cannot be resolved, so resolvedHint = "" and resolvedPrompt = ""
    const { container } = render(<ClaudeCodeHint hintId="home.audit" />);
    expect(container.firstChild).toBeNull();
  });

  // -------------------------------------------------------------------------
  // className passthrough
  // -------------------------------------------------------------------------

  it("passes className to the root element", () => {
    const { container } = render(
      <ClaudeCodeHint hint="Styled" prompt="p" className="custom-class" />,
    );

    expect(container.firstChild).toHaveClass("custom-class");
  });
});
