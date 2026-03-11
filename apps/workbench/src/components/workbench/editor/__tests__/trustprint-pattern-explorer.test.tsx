import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TrustprintPatternExplorer } from "../trustprint-pattern-explorer";
import {
  S2BENCH_PATTERNS,
  ALL_STAGES,
  ALL_CATEGORIES,
  STAGE_LABELS,
  type PatternEntry,
} from "@/lib/workbench/trustprint-patterns";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a subset of patterns missing specific stage+category combos. */
function patternsWithGaps(
  gaps: Array<{ stage: string; category: string }>,
): PatternEntry[] {
  return S2BENCH_PATTERNS.filter(
    (p) => !gaps.some((g) => g.stage === p.stage && g.category === p.category),
  );
}

/** Create a minimal pattern set for focused tests. */
function makePatterns(
  entries: Array<{ stage: string; category: string; id?: string; label?: string }>,
): PatternEntry[] {
  return entries.map((e, i) => ({
    id: e.id ?? `test-${e.stage}-${e.category}-${i}`,
    stage: e.stage as PatternEntry["stage"],
    category: e.category as PatternEntry["category"],
    label: e.label ?? `Test pattern ${i}`,
    embedding: [0.1, 0.2, 0.3],
  }));
}

// ---------------------------------------------------------------------------
// Full mode - Heatmap rendering
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Heatmap", () => {
  it("renders heatmap grid with correct number of cells", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const grid = screen.getByRole("grid", { name: /pattern coverage heatmap/i });
    const cells = within(grid).getAllByRole("gridcell");

    // 4 stages x 9 categories = 36 cells
    expect(cells).toHaveLength(ALL_STAGES.length * ALL_CATEGORIES.length);
  });

  it("displays correct count in each heatmap cell for full s2bench data", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const grid = screen.getByRole("grid", { name: /pattern coverage heatmap/i });
    const cells = within(grid).getAllByRole("gridcell");

    // Each cell should show "1" since s2bench has exactly 1 pattern per combination
    for (const cell of cells) {
      expect(cell).toHaveTextContent("1");
    }
  });

  it("displays count of 0 for empty cells", () => {
    const patterns = patternsWithGaps([
      { stage: "perception", category: "jailbreak" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    const cell = screen.getByRole("gridcell", {
      name: /Perception Jailbreak 0 patterns/,
    });
    expect(cell).toHaveTextContent("0");
  });

  it("applies dashed red border to gap cells", () => {
    const patterns = patternsWithGaps([
      { stage: "action", category: "evasion" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    const cell = screen.getByRole("gridcell", {
      name: /Action Evasion 0 patterns/,
    });
    expect(cell.className).toContain("border-dashed");
    expect(cell.className).toContain("border-[#c45c5c]");
  });

  it("renders stage column headers", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    for (const stage of ALL_STAGES) {
      // Stage labels appear in both the heatmap header and the table, so use getAllByText
      const elements = screen.getAllByText(STAGE_LABELS[stage]);
      expect(elements.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("renders category row labels", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    // Category short labels appear in both heatmap rows and table cells, so use getAllByText
    expect(screen.getAllByText("Prompt Inj").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Jailbreak").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Supply Chain").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Priv Esc").length).toBeGreaterThanOrEqual(1);
  });

  it("displays stats line with correct counts", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const stats = screen.getByTestId("stats-line");
    expect(stats).toHaveTextContent("36 patterns across 4 stages, 9 categories.");
    expect(stats).toHaveTextContent("0 gaps.");
  });

  it("displays gap count in stats line when gaps exist", () => {
    const patterns = patternsWithGaps([
      { stage: "cognition", category: "supply_chain" },
      { stage: "feedback", category: "evasion" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    const stats = screen.getByTestId("stats-line");
    expect(stats).toHaveTextContent("2 gaps.");
  });

  it("shows multiple patterns per cell when data has duplicates", () => {
    const patterns = [
      ...S2BENCH_PATTERNS,
      {
        id: "extra-perception-jailbreak",
        category: "jailbreak" as const,
        stage: "perception" as const,
        label: "Extra jailbreak pattern",
        embedding: [0.5, 0.5, 0.5],
      },
    ];
    render(<TrustprintPatternExplorer patterns={patterns} />);

    const cell = screen.getByRole("gridcell", {
      name: /Perception Jailbreak 2 patterns/,
    });
    expect(cell).toHaveTextContent("2");
  });
});

// ---------------------------------------------------------------------------
// Full mode - Table filtering
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Table filtering", () => {
  it("renders all patterns in the table by default", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // 36 data rows + 1 header row
    expect(rows).toHaveLength(37);
  });

  it("filters table by stage dropdown", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const stageSelect = screen.getByLabelText("Filter by stage");
    await user.selectOptions(stageSelect, "perception");

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // 9 perception patterns + 1 header
    expect(rows).toHaveLength(10);
  });

  it("filters table by category dropdown", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const catSelect = screen.getByLabelText("Filter by category");
    await user.selectOptions(catSelect, "jailbreak");

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // 4 jailbreak patterns (one per stage) + 1 header
    expect(rows).toHaveLength(5);
  });

  it("filters table by stage and category combined", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const stageSelect = screen.getByLabelText("Filter by stage");
    await user.selectOptions(stageSelect, "action");

    const catSelect = screen.getByLabelText("Filter by category");
    await user.selectOptions(catSelect, "evasion");

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // 1 matching pattern + 1 header
    expect(rows).toHaveLength(2);
  });

  it("filters table by text search", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const searchInput = screen.getByLabelText("Search patterns");
    await user.type(searchInput, "role-play");

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // "Jailbreak attempt via role-play" should match
    expect(rows).toHaveLength(2); // 1 result + header
  });

  it("shows empty state when no patterns match", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const searchInput = screen.getByLabelText("Search patterns");
    await user.type(searchInput, "xyznonexistent");

    expect(screen.getByText("No patterns match the current filters.")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Full mode - Heatmap cell click filters table
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Cell click filtering", () => {
  it("clicking a heatmap cell filters the table to that stage+category", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const cell = screen.getByRole("gridcell", {
      name: /Cognition Jailbreak 1 pattern/,
    });
    await user.click(cell);

    // Should show filter badge
    const badge = screen.getByTestId("heatmap-filter-badge");
    expect(badge).toHaveTextContent("Filtered: Cognition x Jailbreak");

    // Table should show only matching patterns
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(2); // 1 result + header
  });

  it("clicking the same cell again clears the filter", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const cell = screen.getByRole("gridcell", {
      name: /Cognition Jailbreak 1 pattern/,
    });

    // First click: filter
    await user.click(cell);
    expect(screen.getByTestId("heatmap-filter-badge")).toBeInTheDocument();

    // Second click: clear
    await user.click(cell);
    expect(screen.queryByTestId("heatmap-filter-badge")).not.toBeInTheDocument();

    // Table should show all patterns again
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(37);
  });

  it("clear button on heatmap filter badge removes the filter", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const cell = screen.getByRole("gridcell", {
      name: /Action Prompt Injection 1 pattern/,
    });
    await user.click(cell);

    const clearBtn = screen.getByLabelText("Clear heatmap filter");
    await user.click(clearBtn);

    expect(screen.queryByTestId("heatmap-filter-badge")).not.toBeInTheDocument();
  });

  it("heatmap filter hides stage/category dropdowns", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    // Initially, dropdowns are present
    expect(screen.getByLabelText("Filter by stage")).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by category")).toBeInTheDocument();

    // Click a heatmap cell
    const cell = screen.getByRole("gridcell", {
      name: /Feedback Evasion 1 pattern/,
    });
    await user.click(cell);

    // Dropdowns should be hidden
    expect(screen.queryByLabelText("Filter by stage")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Filter by category")).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Full mode - Gap detection
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Gap detection", () => {
  it("shows 'Full coverage' when no gaps exist", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    expect(screen.getByText("Full coverage")).toBeInTheDocument();
  });

  it("shows gap count when gaps exist", () => {
    const patterns = patternsWithGaps([
      { stage: "perception", category: "supply_chain" },
      { stage: "action", category: "data_exfiltration" },
      { stage: "feedback", category: "reconnaissance" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    expect(screen.getByText("3 gaps detected")).toBeInTheDocument();
  });

  it("renders individual gap cards with stage and category labels", () => {
    const patterns = patternsWithGaps([
      { stage: "cognition", category: "supply_chain" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    const gapCard = screen.getByTestId("gap-card-cognition-supply_chain");
    expect(gapCard).toHaveTextContent("No patterns for Cognition + Supply Chain");
    expect(gapCard).toHaveTextContent("Add patterns to improve coverage");
  });

  it("shows singular 'gap' for exactly 1 gap", () => {
    const patterns = patternsWithGaps([
      { stage: "feedback", category: "privilege_escalation" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    expect(screen.getByText("1 gap detected")).toBeInTheDocument();
  });

  it("detects all 36 gaps when given empty pattern array", () => {
    render(<TrustprintPatternExplorer patterns={[]} />);

    expect(screen.getByText("36 gaps detected")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Full mode - Table sorting
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Table sorting", () => {
  it("sorts by ID ascending by default", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // First data row (index 1, after header) should start with the first sorted ID
    const firstCell = within(rows[1]).getAllByRole("cell")[0];
    expect(firstCell).toHaveTextContent("s2b-action-data_exfiltration");
  });

  it("clicking a sort header toggles direction", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    // Click ID header to toggle to desc
    const idHeader = screen.getByRole("button", { name: /^ID/ });
    await user.click(idHeader);

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    const firstCell = within(rows[1]).getAllByRole("cell")[0];
    // Descending: last alphabetically
    expect(firstCell).toHaveTextContent("s2b-perception-supply_chain");
  });

  it("clicking a different sort header changes sort key", async () => {
    const user = userEvent.setup();
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    const stageHeader = screen.getByRole("button", { name: /^Stage/ });
    await user.click(stageHeader);

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    // "action" comes first alphabetically
    const stageCell = within(rows[1]).getAllByRole("cell")[2];
    expect(stageCell).toHaveTextContent("Action");
  });
});

// ---------------------------------------------------------------------------
// Full mode - Pattern selection
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Pattern selection", () => {
  it("calls onSelectPattern when a table row is clicked", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(
      <TrustprintPatternExplorer
        patterns={S2BENCH_PATTERNS}
        onSelectPattern={onSelect}
      />,
    );

    const row = screen.getByTestId("pattern-row-s2b-perception-jailbreak");
    await user.click(row);

    expect(onSelect).toHaveBeenCalledWith("s2b-perception-jailbreak");
  });

  it("highlights the selected pattern row", () => {
    render(
      <TrustprintPatternExplorer
        patterns={S2BENCH_PATTERNS}
        selectedPatternId="s2b-action-evasion"
      />,
    );

    const row = screen.getByTestId("pattern-row-s2b-action-evasion");
    expect(row.className).toContain("bg-[#d4a84b]/10");
    expect(row.className).toContain("border-l-[#d4a84b]");
  });

  it("shows embedding dimension info for each pattern", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} />);

    // All s2bench entries have 3-dim embeddings
    const dimCells = screen.getAllByText("3-dim");
    expect(dimCells.length).toBe(S2BENCH_PATTERNS.length);
  });
});

// ---------------------------------------------------------------------------
// Compact mode
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Compact mode", () => {
  it("renders compact heatmap grid", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} compact />);

    const grid = screen.getByRole("grid", { name: /pattern coverage heatmap/i });
    const cells = within(grid).getAllByRole("gridcell");
    expect(cells).toHaveLength(36);
  });

  it("does not render table in compact mode", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} compact />);

    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("does not render gap panel in compact mode", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} compact />);

    expect(screen.queryByText("Full coverage")).not.toBeInTheDocument();
    expect(screen.queryByText(/gaps detected/)).not.toBeInTheDocument();
  });

  it("shows coverage badge with counts", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} compact />);

    const badge = screen.getByTestId("compact-coverage-badge");
    expect(badge).toHaveTextContent("36/36 cells covered");
  });

  it("shows gap count in coverage badge when gaps exist", () => {
    const patterns = patternsWithGaps([
      { stage: "perception", category: "jailbreak" },
      { stage: "action", category: "evasion" },
      { stage: "feedback", category: "data_poisoning" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} compact />);

    const badge = screen.getByTestId("compact-coverage-badge");
    expect(badge).toHaveTextContent("33/36 cells covered");
    expect(badge).toHaveTextContent("3 gaps");
  });

  it("compact heatmap cells have hover tooltips", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} compact />);

    const grid = screen.getByRole("grid", { name: /pattern coverage heatmap/i });
    const cells = within(grid).getAllByRole("gridcell");

    // Check first cell has a title attribute
    const firstCell = cells[0];
    expect(firstCell).toHaveAttribute("title");
    expect(firstCell.getAttribute("title")).toContain("Perception");
    expect(firstCell.getAttribute("title")).toContain("Prompt Injection");
  });

  it("compact grid has width of 200px", () => {
    render(<TrustprintPatternExplorer patterns={S2BENCH_PATTERNS} compact />);

    const grid = screen.getByRole("grid", { name: /pattern coverage heatmap/i });
    expect(grid.style.width).toBe("200px");
  });

  it("compact gap cells have dashed red border", () => {
    const patterns = patternsWithGaps([
      { stage: "cognition", category: "reconnaissance" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} compact />);

    const grid = screen.getByRole("grid", { name: /pattern coverage heatmap/i });
    const cells = within(grid).getAllByRole("gridcell");

    // Find the cell for cognition + reconnaissance (category index 5, stage index 1)
    // Row-major: categories are rows, stages are columns
    // reconnaissance is index 5 in ALL_CATEGORIES, cognition is index 1 in ALL_STAGES
    const gapCell = cells[5 * ALL_STAGES.length + 1];
    expect(gapCell.className).toContain("border-dashed");
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("TrustprintPatternExplorer - Edge cases", () => {
  it("handles empty patterns array without crashing", () => {
    render(<TrustprintPatternExplorer patterns={[]} />);

    const stats = screen.getByTestId("stats-line");
    expect(stats).toHaveTextContent("0 patterns across 4 stages, 9 categories.");
  });

  it("handles patterns with higher-dimensional embeddings", () => {
    const patterns = makePatterns([
      { stage: "perception", category: "jailbreak" },
    ]);
    patterns[0].embedding = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8];
    render(<TrustprintPatternExplorer patterns={patterns} />);

    expect(screen.getByText("8-dim")).toBeInTheDocument();
  });

  it("renders with a single pattern", () => {
    const patterns = makePatterns([
      { stage: "action", category: "prompt_injection", label: "Solo pattern" },
    ]);
    render(<TrustprintPatternExplorer patterns={patterns} />);

    const stats = screen.getByTestId("stats-line");
    expect(stats).toHaveTextContent("1 pattern across 4 stages, 9 categories.");
    expect(stats).toHaveTextContent("35 gaps.");
  });
});
