import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Stub component exercising the artifact node contract.
// Replace with real component import when available.
// ---------------------------------------------------------------------------

const FILE_ICONS: Record<string, string> = {
  rust: "RS",
  typescript: "TS",
  javascript: "JS",
  python: "PY",
  yaml: "YML",
  json: "JSON",
  markdown: "MD",
  toml: "TOML",
};

function ArtifactNode({ data }: { data: SwarmBoardNodeData }) {
  const fileIcon = data.fileType ? FILE_ICONS[data.fileType] ?? "FILE" : "FILE";

  return (
    <div data-testid="artifact-node">
      <span data-testid="file-icon">{fileIcon}</span>
      <h3 data-testid="node-title">{data.title}</h3>
      {data.filePath && (
        <span data-testid="file-path">{data.filePath}</span>
      )}
      {data.fileType && (
        <span data-testid="file-type-badge">{data.fileType}</span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ArtifactNode", () => {
  describe("file icon", () => {
    it("shows file icon based on file type", () => {
      render(
        <ArtifactNode
          data={{
            title: "main.rs",
            status: "idle",
            nodeType: "artifact",
            filePath: "src/main.rs",
            fileType: "rust",
          }}
        />,
      );

      expect(screen.getByTestId("file-icon").textContent).toBe("RS");
    });

    it("shows TS icon for TypeScript files", () => {
      render(
        <ArtifactNode
          data={{
            title: "index.ts",
            status: "idle",
            nodeType: "artifact",
            filePath: "src/index.ts",
            fileType: "typescript",
          }}
        />,
      );

      expect(screen.getByTestId("file-icon").textContent).toBe("TS");
    });

    it("shows PY icon for Python files", () => {
      render(
        <ArtifactNode
          data={{
            title: "main.py",
            status: "idle",
            nodeType: "artifact",
            filePath: "src/main.py",
            fileType: "python",
          }}
        />,
      );

      expect(screen.getByTestId("file-icon").textContent).toBe("PY");
    });

    it("shows generic FILE icon for unknown file types", () => {
      render(
        <ArtifactNode
          data={{
            title: "data.csv",
            status: "idle",
            nodeType: "artifact",
            filePath: "data/data.csv",
            fileType: "csv",
          }}
        />,
      );

      expect(screen.getByTestId("file-icon").textContent).toBe("FILE");
    });

    it("shows generic FILE icon when fileType is undefined", () => {
      render(
        <ArtifactNode
          data={{
            title: "unknown",
            status: "idle",
            nodeType: "artifact",
            filePath: "unknown",
          }}
        />,
      );

      expect(screen.getByTestId("file-icon").textContent).toBe("FILE");
    });
  });

  describe("file name", () => {
    it("shows file name as title", () => {
      render(
        <ArtifactNode
          data={{
            title: "auth.rs",
            status: "idle",
            nodeType: "artifact",
            filePath: "src/middleware/auth.rs",
            fileType: "rust",
          }}
        />,
      );

      expect(screen.getByTestId("node-title").textContent).toBe("auth.rs");
    });
  });

  describe("file path", () => {
    it("shows full file path", () => {
      render(
        <ArtifactNode
          data={{
            title: "auth.rs",
            status: "idle",
            nodeType: "artifact",
            filePath: "src/middleware/auth.rs",
            fileType: "rust",
          }}
        />,
      );

      expect(screen.getByTestId("file-path").textContent).toBe("src/middleware/auth.rs");
    });

    it("does not render file path when undefined", () => {
      render(
        <ArtifactNode
          data={{
            title: "orphaned",
            status: "idle",
            nodeType: "artifact",
          }}
        />,
      );

      expect(screen.queryByTestId("file-path")).toBeNull();
    });
  });

  describe("file type badge", () => {
    it("shows file type badge", () => {
      render(
        <ArtifactNode
          data={{
            title: "config.yaml",
            status: "idle",
            nodeType: "artifact",
            filePath: "config.yaml",
            fileType: "yaml",
          }}
        />,
      );

      expect(screen.getByTestId("file-type-badge").textContent).toBe("yaml");
    });

    it("does not render badge when fileType is undefined", () => {
      render(
        <ArtifactNode
          data={{
            title: "no-type",
            status: "idle",
            nodeType: "artifact",
          }}
        />,
      );

      expect(screen.queryByTestId("file-type-badge")).toBeNull();
    });

    it.each([
      ["rust", "rust"],
      ["typescript", "typescript"],
      ["javascript", "javascript"],
      ["python", "python"],
      ["yaml", "yaml"],
      ["json", "json"],
      ["markdown", "markdown"],
      ["toml", "toml"],
    ])("shows '%s' file type as badge text '%s'", (fileType, expected) => {
      render(
        <ArtifactNode
          data={{
            title: `file.${fileType}`,
            status: "idle",
            nodeType: "artifact",
            filePath: `file.${fileType}`,
            fileType,
          }}
        />,
      );

      expect(screen.getByTestId("file-type-badge").textContent).toBe(expected);
    });
  });
});
