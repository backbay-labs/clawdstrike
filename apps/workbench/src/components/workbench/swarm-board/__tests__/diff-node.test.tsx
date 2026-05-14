import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Stub component exercising the diff node contract.
// Replace with real component import when available.
// ---------------------------------------------------------------------------

const MAX_VISIBLE_FILES = 4;

function DiffNode({ data }: { data: SwarmBoardNodeData }) {
  const summary = data.diffSummary;

  return (
    <div data-testid="diff-node">
      <h3 data-testid="node-title">{data.title}</h3>
      {summary && (
        <>
          <div data-testid="line-counts">
            <span data-testid="added-count" style={{ color: "#3dbf84" }}>
              +{summary.added}
            </span>
            <span data-testid="removed-count" style={{ color: "#ef4444" }}>
              -{summary.removed}
            </span>
          </div>
          {summary.files.length > 0 && (
            <ul data-testid="changed-files-list">
              {summary.files.slice(0, MAX_VISIBLE_FILES).map((file, i) => (
                <li key={i} data-testid="changed-file">
                  {file}
                </li>
              ))}
              {summary.files.length > MAX_VISIBLE_FILES && (
                <li data-testid="truncated-indicator">
                  +{summary.files.length - MAX_VISIBLE_FILES} more
                </li>
              )}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DiffNode", () => {
  describe("line count display", () => {
    it("shows added count with green color", () => {
      render(
        <DiffNode
          data={{
            title: "Auth changes",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 47, removed: 12, files: [] },
          }}
        />,
      );

      const added = screen.getByTestId("added-count");
      expect(added.textContent).toBe("+47");
      expect(added.style.color).toBe("rgb(61, 191, 132)");
    });

    it("shows removed count with red color", () => {
      render(
        <DiffNode
          data={{
            title: "Refactor",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 5, removed: 30, files: [] },
          }}
        />,
      );

      const removed = screen.getByTestId("removed-count");
      expect(removed.textContent).toBe("-30");
      expect(removed.style.color).toBe("rgb(239, 68, 68)");
    });

    it("shows zero counts correctly", () => {
      render(
        <DiffNode
          data={{
            title: "No changes",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 0, removed: 0, files: [] },
          }}
        />,
      );

      expect(screen.getByTestId("added-count").textContent).toBe("+0");
      expect(screen.getByTestId("removed-count").textContent).toBe("-0");
    });

    it("handles large numbers", () => {
      render(
        <DiffNode
          data={{
            title: "Big refactor",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 1234, removed: 567, files: [] },
          }}
        />,
      );

      expect(screen.getByTestId("added-count").textContent).toBe("+1234");
      expect(screen.getByTestId("removed-count").textContent).toBe("-567");
    });
  });

  describe("changed files list", () => {
    it("lists changed files", () => {
      render(
        <DiffNode
          data={{
            title: "Changes",
            status: "idle",
            nodeType: "diff",
            diffSummary: {
              added: 10,
              removed: 5,
              files: ["src/main.rs", "Cargo.toml", "tests/test.rs"],
            },
          }}
        />,
      );

      const files = screen.getAllByTestId("changed-file");
      expect(files).toHaveLength(3);
      expect(files[0].textContent).toBe("src/main.rs");
      expect(files[1].textContent).toBe("Cargo.toml");
      expect(files[2].textContent).toBe("tests/test.rs");
    });

    it("does not render file list when files array is empty", () => {
      render(
        <DiffNode
          data={{
            title: "No files",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 0, removed: 0, files: [] },
          }}
        />,
      );

      expect(screen.queryByTestId("changed-files-list")).toBeNull();
    });

    it("truncates long file lists at 4 files", () => {
      render(
        <DiffNode
          data={{
            title: "Many files",
            status: "idle",
            nodeType: "diff",
            diffSummary: {
              added: 100,
              removed: 50,
              files: [
                "src/a.rs",
                "src/b.rs",
                "src/c.rs",
                "src/d.rs",
                "src/e.rs",
                "src/f.rs",
              ],
            },
          }}
        />,
      );

      const files = screen.getAllByTestId("changed-file");
      expect(files).toHaveLength(4);
      expect(files[0].textContent).toBe("src/a.rs");
      expect(files[3].textContent).toBe("src/d.rs");

      const truncated = screen.getByTestId("truncated-indicator");
      expect(truncated.textContent).toBe("+2 more");
    });

    it("does not show truncation indicator when exactly 4 files", () => {
      render(
        <DiffNode
          data={{
            title: "Exact",
            status: "idle",
            nodeType: "diff",
            diffSummary: {
              added: 10,
              removed: 2,
              files: ["a.rs", "b.rs", "c.rs", "d.rs"],
            },
          }}
        />,
      );

      const files = screen.getAllByTestId("changed-file");
      expect(files).toHaveLength(4);
      expect(screen.queryByTestId("truncated-indicator")).toBeNull();
    });

    it("shows correct count in truncation indicator for many files", () => {
      const files = Array.from({ length: 20 }, (_, i) => `file-${i}.rs`);

      render(
        <DiffNode
          data={{
            title: "Huge diff",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 500, removed: 200, files },
          }}
        />,
      );

      expect(screen.getByTestId("truncated-indicator").textContent).toBe("+16 more");
    });
  });

  describe("no diff summary", () => {
    it("does not render line counts or files when diffSummary is undefined", () => {
      render(
        <DiffNode
          data={{
            title: "Pending",
            status: "idle",
            nodeType: "diff",
          }}
        />,
      );

      expect(screen.queryByTestId("line-counts")).toBeNull();
      expect(screen.queryByTestId("changed-files-list")).toBeNull();
    });
  });

  it("renders node title", () => {
    render(
      <DiffNode
        data={{
          title: "My Diff Title",
          status: "idle",
          nodeType: "diff",
          diffSummary: { added: 1, removed: 0, files: ["f.rs"] },
        }}
      />,
    );

    expect(screen.getByTestId("node-title").textContent).toBe("My Diff Title");
  });
});
