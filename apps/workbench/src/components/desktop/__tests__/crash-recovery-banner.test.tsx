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
});
