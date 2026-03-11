import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CrashRecoveryBanner } from "../crash-recovery-banner";

describe("CrashRecoveryBanner", () => {
  it("renders nothing when recovery entries are empty", () => {
    const { container } = render(
      <CrashRecoveryBanner
        entries={[]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByText(/Recovered unsaved changes/i)).toBeNull();
  });

  it("renders a single named policy without duplicating the policy list suffix", () => {
    render(
      <CrashRecoveryBanner
        entries={[
          {
            tabId: "tab-1",
            policyName: "prod-policy",
            yaml: "version: '1.2.0'\nname: prod-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 0, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("prod-policy")).toBeInTheDocument();
    expect(screen.queryByText(/\(prod-policy/)).toBeNull();
  });
});
