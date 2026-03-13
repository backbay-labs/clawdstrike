import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { HintSettings } from "../hint-settings";

// ---------------------------------------------------------------------------
// Mock the hint settings hook
// ---------------------------------------------------------------------------

const mockSetShowHints = vi.hoisted(() => vi.fn());
const mockUpdateHint = vi.hoisted(() => vi.fn());
const mockResetHint = vi.hoisted(() => vi.fn());
const mockResetAll = vi.hoisted(() => vi.fn());
const mockGetHint = vi.hoisted(() => vi.fn());
const mockIsCustomized = vi.hoisted(() => vi.fn());
const mockShowHints = vi.hoisted(() => ({ value: true }));

vi.mock("@/lib/workbench/use-hint-settings", async () => {
  const actual = await vi.importActual<typeof import("@/lib/workbench/use-hint-settings")>(
    "@/lib/workbench/use-hint-settings",
  );
  return {
    ...actual,
    useHintSettings: () => ({
      showHints: mockShowHints.value,
      setShowHints: mockSetShowHints,
      getHint: mockGetHint,
      updateHint: mockUpdateHint,
      resetHint: mockResetHint,
      resetAll: mockResetAll,
      isCustomized: mockIsCustomized,
    }),
  };
});

// Re-import the actual constants after mocking (they are passed through)
import { DEFAULT_HINTS, HINT_LABELS, type HintId } from "@/lib/workbench/use-hint-settings";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALL_HINT_IDS: HintId[] = [
  "home.audit",
  "editor.validate",
  "simulator.scenarios",
  "compliance.check",
  "observe.synth",
  "risk.assess",
  "library.audit",
  "library.testSuite",
  "library.harden",
  "library.compare",
];

function setupDefaultMocks() {
  mockShowHints.value = true;
  mockIsCustomized.mockImplementation(() => false);
  mockGetHint.mockImplementation((id: HintId) => ({ ...DEFAULT_HINTS[id] }));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("HintSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupDefaultMocks();
  });

  // -------------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------------

  it("renders all 10 hint labels", () => {
    render(<HintSettings />);

    for (const id of ALL_HINT_IDS) {
      expect(screen.getByText(HINT_LABELS[id])).toBeInTheDocument();
    }
  });

  it("renders description input for each hint", () => {
    render(<HintSettings />);

    // Each hint card has a "Description" label and an input with the hint text
    const descriptionLabels = screen.getAllByText("Description");
    expect(descriptionLabels).toHaveLength(10);
  });

  it("renders prompt textarea for each hint", () => {
    render(<HintSettings />);

    const promptLabels = screen.getAllByText("Prompt");
    expect(promptLabels).toHaveLength(10);
  });

  it("each hint shows its description text in the input", () => {
    render(<HintSettings />);

    for (const id of ALL_HINT_IDS) {
      const input = screen.getByDisplayValue(DEFAULT_HINTS[id].hint);
      expect(input).toBeInTheDocument();
    }
  });

  it("each hint shows its prompt text in the textarea", () => {
    render(<HintSettings />);

    for (const id of ALL_HINT_IDS) {
      const textarea = screen.getByDisplayValue(DEFAULT_HINTS[id].prompt);
      expect(textarea).toBeInTheDocument();
    }
  });

  // -------------------------------------------------------------------------
  // Master toggle
  // -------------------------------------------------------------------------

  it("clicking the master toggle calls setShowHints with the opposite value", async () => {
    const user = userEvent.setup();
    render(<HintSettings />);

    // The toggle is a button wrapping a styled switch. Find the toggle container
    // that has the switch indicator. The toggle is inside the header area.
    // The switch is the span with rounded-full classes. We can find the toggle button
    // by its role.
    const toggleButton = screen.getByRole("switch", { name: "Show Claude Code Hints" });
    expect(toggleButton).toHaveAttribute("aria-checked", "true");

    await user.click(toggleButton);
    expect(mockSetShowHints).toHaveBeenCalledWith(false);
  });

  it("clicking the master toggle when disabled calls setShowHints(true)", async () => {
    mockShowHints.value = false;
    const user = userEvent.setup();
    render(<HintSettings />);

    const toggleButton = screen.getByRole("switch", { name: "Show Claude Code Hints" });
    expect(toggleButton).toHaveAttribute("aria-checked", "false");

    await user.click(toggleButton);
    expect(mockSetShowHints).toHaveBeenCalledWith(true);
  });

  // -------------------------------------------------------------------------
  // Editing hints
  // -------------------------------------------------------------------------

  it("editing a description calls updateHint with correct ID", async () => {
    const user = userEvent.setup();
    render(<HintSettings />);

    const input = screen.getByDisplayValue(DEFAULT_HINTS["home.audit"].hint);
    // Type a single character at the end; the component calls updateHint on each onChange
    await user.type(input, "X");

    // Verify updateHint was called with the correct hint ID and a hint field
    const calls = mockUpdateHint.mock.calls.filter(
      ([id]) => id === "home.audit",
    );
    expect(calls.length).toBeGreaterThan(0);
    const lastCall = calls[calls.length - 1];
    expect(lastCall[0]).toBe("home.audit");
    expect(lastCall[1]).toHaveProperty("hint");
    // The value should be the original hint + "X" appended
    expect(lastCall[1].hint).toBe(DEFAULT_HINTS["home.audit"].hint + "X");
  });

  it("editing a prompt calls updateHint with correct ID", async () => {
    const user = userEvent.setup();
    render(<HintSettings />);

    const textarea = screen.getByDisplayValue(DEFAULT_HINTS["editor.validate"].prompt);
    // Type a single character at the end
    await user.type(textarea, "Z");

    const calls = mockUpdateHint.mock.calls.filter(
      ([id]) => id === "editor.validate",
    );
    expect(calls.length).toBeGreaterThan(0);
    const lastCall = calls[calls.length - 1];
    expect(lastCall[0]).toBe("editor.validate");
    expect(lastCall[1]).toHaveProperty("prompt");
    expect(lastCall[1].prompt).toBe(DEFAULT_HINTS["editor.validate"].prompt + "Z");
  });

  // -------------------------------------------------------------------------
  // Customized badge and per-hint Reset
  // -------------------------------------------------------------------------

  it("customized hints show a 'customized' badge", () => {
    mockIsCustomized.mockImplementation((id: HintId) => id === "home.audit");
    render(<HintSettings />);

    expect(screen.getByText("customized")).toBeInTheDocument();
  });

  it("'Reset' button is hidden for non-customized hints", () => {
    mockIsCustomized.mockImplementation(() => false);
    render(<HintSettings />);

    // "Reset" buttons only appear inside customized hint cards
    // With no customized hints, there should be no Reset buttons at all
    // (also no Reset All button since hasAnyCustomized is false)
    const resetButtons = screen.queryAllByText("Reset");
    expect(resetButtons).toHaveLength(0);
  });

  it("'Reset' button on a customized hint calls resetHint", async () => {
    mockIsCustomized.mockImplementation((id: HintId) => id === "home.audit");
    const user = userEvent.setup();
    render(<HintSettings />);

    // Find the Reset button (not Reset All)
    const resetButton = screen.getByText("Reset");
    await user.click(resetButton);

    expect(mockResetHint).toHaveBeenCalledWith("home.audit");
  });

  // -------------------------------------------------------------------------
  // Reset All
  // -------------------------------------------------------------------------

  it("'Reset All' button is hidden when no hints are customized", () => {
    mockIsCustomized.mockImplementation(() => false);
    render(<HintSettings />);

    expect(screen.queryByText("Reset All")).not.toBeInTheDocument();
  });

  it("'Reset All' button is shown when at least one hint is customized", () => {
    mockIsCustomized.mockImplementation((id: HintId) => id === "compliance.check");
    render(<HintSettings />);

    expect(screen.getByText("Reset All")).toBeInTheDocument();
  });

  it("'Reset All' requires confirmation click before calling resetAll", async () => {
    mockIsCustomized.mockImplementation(() => true);
    const user = userEvent.setup();
    render(<HintSettings />);

    const resetAllButton = screen.getByText("Reset All");
    await user.click(resetAllButton);

    // First click shows confirmation
    expect(mockResetAll).not.toHaveBeenCalled();
    expect(screen.getByText("Confirm reset?")).toBeInTheDocument();

    // Second click actually resets
    await user.click(screen.getByText("Confirm reset?"));
    expect(mockResetAll).toHaveBeenCalledOnce();
  });

  // -------------------------------------------------------------------------
  // Hint groups
  // -------------------------------------------------------------------------

  it("hints are grouped by section", () => {
    render(<HintSettings />);

    expect(screen.getByText("Dashboard & Editor")).toBeInTheDocument();
    expect(screen.getByText("Simulator & Analysis")).toBeInTheDocument();
    expect(screen.getByText("Library Prompts")).toBeInTheDocument();
  });

  it("Dashboard & Editor group contains home.audit and editor.validate", () => {
    render(<HintSettings />);

    expect(screen.getByText(HINT_LABELS["home.audit"])).toBeInTheDocument();
    expect(screen.getByText(HINT_LABELS["editor.validate"])).toBeInTheDocument();
  });

  it("Simulator & Analysis group contains 4 hints", () => {
    render(<HintSettings />);

    const expectedIds: HintId[] = [
      "simulator.scenarios",
      "compliance.check",
      "observe.synth",
      "risk.assess",
    ];
    for (const id of expectedIds) {
      expect(screen.getByText(HINT_LABELS[id])).toBeInTheDocument();
    }
  });

  it("Library Prompts group contains 4 hints", () => {
    render(<HintSettings />);

    const expectedIds: HintId[] = [
      "library.audit",
      "library.testSuite",
      "library.harden",
      "library.compare",
    ];
    for (const id of expectedIds) {
      expect(screen.getByText(HINT_LABELS[id])).toBeInTheDocument();
    }
  });

  // -------------------------------------------------------------------------
  // Multiple customized hints
  // -------------------------------------------------------------------------

  it("shows customized badge on multiple hints", () => {
    mockIsCustomized.mockImplementation(
      (id: HintId) => id === "home.audit" || id === "library.compare",
    );
    render(<HintSettings />);

    const badges = screen.getAllByText("customized");
    expect(badges).toHaveLength(2);
  });
});
