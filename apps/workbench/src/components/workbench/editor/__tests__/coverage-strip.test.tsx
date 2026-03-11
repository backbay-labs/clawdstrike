import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CoverageStrip } from "../coverage-strip";

describe("CoverageStrip", () => {
  it("rounds the displayed coverage percentage", () => {
    render(
      <CoverageStrip
        report={{
          totalGuards: 3,
          enabledGuards: 3,
          coveredGuards: 2,
          coveragePercent: 66.666666,
          guards: [
            {
              guardId: "forbidden_path",
              guardName: "Forbidden Path",
              status: "covered",
              scenarioCount: 1,
              scenarioIds: ["s1"],
            },
            {
              guardId: "shell_command",
              guardName: "Shell Command",
              status: "covered",
              scenarioCount: 1,
              scenarioIds: ["s2"],
            },
            {
              guardId: "mcp_tool",
              guardName: "MCP Tool",
              status: "uncovered",
              scenarioCount: 0,
              scenarioIds: [],
            },
          ],
          gaps: ["mcp_tool"],
        }}
      />,
    );

    expect(screen.getByText("67%")).toBeInTheDocument();
    expect(screen.queryByText(/66\.666/)).toBeNull();
  });
});
