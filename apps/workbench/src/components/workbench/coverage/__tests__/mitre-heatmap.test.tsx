import React from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MitreHeatmap } from "../mitre-heatmap";
import type { PolicyTab } from "@/features/policy/types/policy-tab";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";

vi.mock("@/components/ui/scroll-area", () => ({
  ScrollArea: ({ children, className }: { children: React.ReactNode; className?: string }) => (
    <div className={className}>{children}</div>
  ),
}));

function makeTab(partial: Pick<PolicyTab, "id" | "documentId" | "name" | "fileType" | "yaml">): PolicyTab {
  return {
    ...partial,
    filePath: null,
    dirty: false,
    policy: DEFAULT_POLICY,
    validation: {
      valid: true,
      errors: [],
      warnings: [],
    },
    nativeValidation: {
      guardErrors: {},
      topLevelErrors: [],
      topLevelWarnings: [],
      loading: false,
      valid: null,
    },
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: null,
  };
}

describe("MitreHeatmap", () => {
  it("extracts Sigma coverage from flow-style tags", () => {
    const tabs: PolicyTab[] = [
      makeTab({
        id: "sigma-flow",
        documentId: "doc-sigma-flow",
        name: "Flow Sigma",
        fileType: "sigma_rule",
        yaml: `title: Flow Sigma
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
  category: process_creation
tags: [attack.t1059, attack.t1059.001]
detection:
  selection:
    CommandLine|contains:
      - powershell
  condition: selection
level: medium
`,
      }),
    ];

    render(<MitreHeatmap tabs={tabs} />);

    expect(screen.getByText(/2 of \d+ techniques covered/)).toBeInTheDocument();
  });

  it("keeps technique rule counts stable across rerenders", () => {
    const tab = makeTab({
      id: "sigma-rerender",
      documentId: "doc-sigma-rerender",
      name: "Stable Sigma",
      fileType: "sigma_rule",
      yaml: `title: Stable Sigma
id: 22222222-2222-2222-2222-222222222222
status: experimental
logsource:
  category: process_creation
tags:
  - attack.t1059
detection:
  selection:
    CommandLine|contains:
      - bash
  condition: selection
level: medium
`,
    });

    const { rerender } = render(<MitreHeatmap tabs={[tab]} />);

    fireEvent.click(screen.getByText("T1059"));
    expect(screen.getByText("Covering Rules (1)")).toBeInTheDocument();
    expect(screen.getByText("Stable Sigma")).toBeInTheDocument();

    rerender(<MitreHeatmap tabs={[tab]} />);

    expect(screen.getByText("Covering Rules (1)")).toBeInTheDocument();
    expect(screen.getByText("Stable Sigma")).toBeInTheDocument();
  });
});
