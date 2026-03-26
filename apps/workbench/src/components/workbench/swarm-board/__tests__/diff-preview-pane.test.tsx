import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/tauri-bridge", () => ({
  readTextFileFromDisk: vi.fn().mockResolvedValue(null),
}));

vi.mock("../diff-highlight", () => ({
  resolveParser: vi.fn().mockResolvedValue(null),
  highlightLine: vi.fn().mockReturnValue([]),
  extractDiffFilePath: vi.fn().mockReturnValue(null),
}));

vi.mock("style-mod", () => ({
  StyleModule: { mount: vi.fn() },
}));

vi.mock("../codemirror-theme", () => ({
  diffHighlightStyle: { module: null },
}));

import { DiffPreviewPane } from "../diff-preview-pane";
import { resolveParser, highlightLine, extractDiffFilePath } from "../diff-highlight";
import { diffHighlightStyle } from "../codemirror-theme";

const SAMPLE_DIFF = `diff --git a/src/auth.rs b/src/auth.rs
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -1,2 +1,3 @@
 export const auth = true;
-export const stale = false;
+export const stale = true;`;

describe("DiffPreviewPane", () => {
  it("renders diff lines with correct background tinting", () => {
    render(<DiffPreviewPane diffContent={SAMPLE_DIFF} />);

    const pane = screen.getByTestId("diff-preview-pane");
    expect(pane).toBeInTheDocument();

    // Add line should have green background
    const addLine = screen.getByText("+export const stale = true;");
    expect(addLine).toBeInTheDocument();
    const addStyle = addLine.closest("span[style]");
    expect(addStyle).toBeTruthy();
    expect(addStyle!.getAttribute("style")).toContain("rgba(56, 168, 118, 0.12)");

    // Remove line should have red background
    const removeLine = screen.getByText("-export const stale = false;");
    expect(removeLine).toBeInTheDocument();
    const removeStyle = removeLine.closest("span[style]");
    expect(removeStyle).toBeTruthy();
    expect(removeStyle!.getAttribute("style")).toContain("rgba(184, 84, 80, 0.12)");
  });

  it("renders empty message when no content is provided", () => {
    render(<DiffPreviewPane />);

    expect(screen.getByTestId("diff-preview-empty")).toBeInTheDocument();
    expect(screen.getByText("No diff preview available")).toBeInTheDocument();
  });

  it("renders the loading state when reading from disk", () => {
    render(<DiffPreviewPane diffPath="/some/path.diff" />);

    expect(screen.getByTestId("diff-preview-loading")).toBeInTheDocument();
    expect(screen.getByText("loading diff...")).toBeInTheDocument();
  });

  it("shows hidden-line-count footer when maxLines truncates", () => {
    render(<DiffPreviewPane diffContent={SAMPLE_DIFF} maxLines={3} />);

    const pane = screen.getByTestId("diff-preview-pane");
    expect(pane).toBeInTheDocument();
    // 7 lines total, maxLines=3, so 4 hidden
    expect(screen.getByText(/\+4 more lines/)).toBeInTheDocument();
  });

  it("renders line numbers when showLineNumbers is true", () => {
    render(<DiffPreviewPane diffContent={SAMPLE_DIFF} showLineNumbers />);

    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("falls back to plain text when no parser is available", () => {
    // resolveParser returns null by default (mock above)
    render(<DiffPreviewPane diffContent={SAMPLE_DIFF} />);

    const pane = screen.getByTestId("diff-preview-pane");
    expect(pane).toBeInTheDocument();

    // Lines should render as plain text with fallback color
    const addLine = screen.getByText("+export const stale = true;");
    expect(addLine).toBeInTheDocument();
    expect(addLine.getAttribute("style")).toContain("color");
  });
});

describe("getDiffLineBg", () => {
  it("returns correct backgroundColor for add kind", async () => {
    // Import the function directly via the module
    const mod = await import("../diff-preview-pane");
    const getDiffLineBg = (mod as any).getDiffLineBg;
    expect(getDiffLineBg("add")).toBe("rgba(56, 168, 118, 0.12)");
  });

  it("returns correct backgroundColor for remove kind", async () => {
    const mod = await import("../diff-preview-pane");
    const getDiffLineBg = (mod as any).getDiffLineBg;
    expect(getDiffLineBg("remove")).toBe("rgba(184, 84, 80, 0.12)");
  });

  it("returns correct backgroundColor for hunk kind", async () => {
    const mod = await import("../diff-preview-pane");
    const getDiffLineBg = (mod as any).getDiffLineBg;
    expect(getDiffLineBg("hunk")).toBe("rgba(85, 128, 204, 0.12)");
  });

  it("returns undefined for meta and context kinds", async () => {
    const mod = await import("../diff-preview-pane");
    const getDiffLineBg = (mod as any).getDiffLineBg;
    expect(getDiffLineBg("meta")).toBeUndefined();
    expect(getDiffLineBg("context")).toBeUndefined();
  });
});

describe("getDiffLineFallbackColor", () => {
  it("returns correct fallback color for each kind", async () => {
    const mod = await import("../diff-preview-pane");
    const getDiffLineFallbackColor = (mod as any).getDiffLineFallbackColor;
    expect(getDiffLineFallbackColor("add")).toBe("#8bd4ab");
    expect(getDiffLineFallbackColor("remove")).toBe("#e3a19e");
    expect(getDiffLineFallbackColor("hunk")).toBe("#8fb2ff");
    expect(getDiffLineFallbackColor("meta")).toBe("#7b8496");
    expect(getDiffLineFallbackColor("context")).toBe("#c7ccd6");
  });
});
