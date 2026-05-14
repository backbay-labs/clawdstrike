import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import type { TestScenario, WorkbenchPolicy } from "@/lib/workbench/types";

vi.mock("../redteam-panel", () => ({
  useRedTeamPlugins: () => ({
    enabledPlugins: new Set(["prompt-guard"]),
    togglePlugin: vi.fn(),
    grouped: {
      prompt_injection: [
        {
          id: "prompt-guard",
          severity: "high",
          description: "Prompt injection probe",
        },
      ],
    },
    categoryOrder: ["prompt_injection"],
    coverage: { covered: 0, total: 1, uncoveredPlugins: ["prompt-guard"] },
    generating: false,
    handleGenerate: vi.fn(),
    handleFillGaps: vi.fn(),
  }),
  PluginCategoryGroup: ({ category }: { category: string }) => (
    <div>{category} plugins</div>
  ),
  CoverageIndicator: ({ covered, total }: { covered: number; total: number }) => (
    <div>{covered}/{total} covered</div>
  ),
}));

import { ScenarioList } from "../scenario-list";

const policy: WorkbenchPolicy = {
  version: "1.4.0",
  name: "Mobile Simulator Policy",
  description: "Test policy",
  guards: {
    prompt_injection: { enabled: true },
  },
  settings: {},
};

const scenarios: TestScenario[] = [
  {
    id: "scenario-1",
    name: "Existing Probe",
    description: "Test scenario",
    category: "attack",
    actionType: "user_input",
    payload: {},
    severity: "high",
  },
];

describe("ScenarioList", () => {
  it("keeps the Red Team generator reachable in horizontal mobile mode", async () => {
    const user = userEvent.setup();

    render(
      <ScenarioList
        scenarios={scenarios}
        selectedId="scenario-1"
        onSelect={vi.fn()}
        onAdd={vi.fn()}
        onRunAll={vi.fn()}
        onGenerate={vi.fn()}
        onScenariosGenerated={vi.fn()}
        policy={policy}
        horizontal
      />,
    );

    expect(screen.getByRole("button", { name: "Library" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Red Team" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Existing Probe/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Red Team" }));

    expect(screen.getByText("Attack Plugins")).toBeInTheDocument();
    expect(screen.getByText("prompt_injection plugins")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate 1 Scenarios/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Library" }));

    expect(screen.queryByText("Attack Plugins")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Existing Probe/i })).toBeInTheDocument();
  });
});
