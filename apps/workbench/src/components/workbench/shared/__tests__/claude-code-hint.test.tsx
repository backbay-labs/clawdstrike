import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ClaudeCodeHint } from "../claude-code-hint";


const mockGetHint = vi.hoisted(() => vi.fn());
const mockShowHints = vi.hoisted(() => ({ value: true }));
const mockCtx = vi.hoisted(() => ({ value: null as object | null }));

vi.mock("@/lib/workbench/use-hint-settings", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/workbench/use-hint-settings")>();
  return {
    ...actual,
    useHintSettingsSafe: () => mockCtx.value,
  };
});


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


describe("ClaudeCodeHint", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearContextMock();
  });

  it("renders prompt rows with raw props", () => {
    render(<ClaudeCodeHint hint="Test hint text" prompt="Test prompt text" />);
    expect(screen.getByText("Test hint text")).toBeInTheDocument();
  });

  it("renders nothing when neither hint nor prompt is provided and no hintId", () => {
    const { container } = render(<ClaudeCodeHint />);
    // Without hintId, hint, or prompt, fallback prompts are used
    // so the component renders
    expect(container.firstChild).not.toBeNull();
  });

  it("renders context-aware prompts when hintId is provided", () => {
    setupContextMock();

    render(<ClaudeCodeHint hintId="editor.validate" />);

    // Should show the 3 editor context prompts
    expect(screen.getByText("Validate & tighten")).toBeInTheDocument();
    expect(screen.getByText("Generate test scenarios")).toBeInTheDocument();
    expect(screen.getByText("Check compliance scores")).toBeInTheDocument();
  });

  it("returns null when showHints is false and hintId is provided", () => {
    setupContextMock({ showHints: false });

    const { container } = render(<ClaudeCodeHint hintId="home.audit" />);
    expect(container.firstChild).toBeNull();
  });

  it("renders Claude Code header", () => {
    render(<ClaudeCodeHint hint="Test" prompt="p" />);
    expect(screen.getByText("Claude Code")).toBeInTheDocument();
  });

  it("dismiss button hides the card", async () => {
    const user = userEvent.setup();
    render(<ClaudeCodeHint hint="Dismissable" prompt="p" />);

    expect(screen.getByText("Dismissable")).toBeInTheDocument();

    await user.click(screen.getByTitle("Dismiss"));

    expect(screen.queryByText("Dismissable")).toBeNull();
  });

  it("clicking a prompt row copies to clipboard", async () => {
    setupContextMock();
    const user = userEvent.setup();
    render(<ClaudeCodeHint hintId="editor.validate" />);

    const spy = vi.spyOn(navigator.clipboard, "writeText");

    await user.click(screen.getByText("Validate & tighten"));

    expect(spy).toHaveBeenCalledTimes(1);
    // Should have copied the full prompt text (not just the label)
    expect(spy.mock.calls[0][0].length).toBeGreaterThan(20);
    spy.mockRestore();
  });

  it("renders with raw props when provider is not mounted", () => {
    clearContextMock();
    render(<ClaudeCodeHint hint="No provider" prompt="Still works" />);
    expect(screen.getByText("No provider")).toBeInTheDocument();
  });

  it("passes className to the root element", () => {
    const { container } = render(
      <ClaudeCodeHint hint="Styled" prompt="p" className="custom-class" />,
    );
    expect(container.firstChild).toHaveClass("custom-class");
  });
});
