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

  it("avoids implying a single unnamed recovery belongs to the current tab", () => {
    render(
      <CrashRecoveryBanner
        entries={[
          {
            tabId: "tab-1",
            policyName: "",
            yaml: "version: '1.2.0'\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 0, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("an unnamed tab")).toBeInTheDocument();
    expect(screen.queryByText(/the current tab/i)).toBeNull();
  });

  it("warns when sensitive fields were omitted from recovery storage", () => {
    render(
      <CrashRecoveryBanner
        entries={[
          {
            tabId: "tab-1",
            policyName: "sensitive-policy",
            yaml: "version: '1.4.0'\nname: sensitive-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 0, 0),
            sensitiveFieldsStripped: true,
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(
      screen.getByText(/Sensitive fields were omitted from recovery/i),
    ).toBeInTheDocument();
  });

  it("describes mixed named and unnamed recoveries without implying only one tab recovered", () => {
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
          {
            tabId: "tab-2",
            policyName: "",
            yaml: "version: '1.2.0'\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 1, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("2 tabs")).toBeInTheDocument();
    expect(screen.getByText(/\(including prod-policy\)/)).toBeInTheDocument();
    expect(screen.queryByText(/\(prod-policy\)/)).toBeNull();
  });

  it("uses unique named policies in mixed recovery summaries", () => {
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
          {
            tabId: "tab-2",
            policyName: "prod-policy",
            yaml: "version: '1.2.0'\nname: prod-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 1, 0),
          },
          {
            tabId: "tab-3",
            policyName: "staging-policy",
            yaml: "version: '1.2.0'\nname: staging-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 2, 0),
          },
          {
            tabId: "tab-4",
            policyName: "",
            yaml: "version: '1.2.0'\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 3, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("4 tabs")).toBeInTheDocument();
    expect(
      screen.getByText(/\(including prod-policy, staging-policy\)/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/3 named:/)).toBeNull();
  });

  it("describes duplicate named recoveries without implying unnamed tabs", () => {
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
          {
            tabId: "tab-2",
            policyName: "prod-policy",
            yaml: "version: '1.2.0'\nname: prod-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 1, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("2 tabs")).toBeInTheDocument();
    expect(screen.getByText(/\(all named prod-policy\)/)).toBeInTheDocument();
    expect(screen.queryByText(/\(including prod-policy\)/)).toBeNull();
  });

  it("adds context when all recovered tabs are named but have different policy names", () => {
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
          {
            tabId: "tab-2",
            policyName: "staging-policy",
            yaml: "version: '1.2.0'\nname: staging-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 1, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("2 tabs")).toBeInTheDocument();
    expect(screen.getByText(/\(named prod-policy, staging-policy\)/)).toBeInTheDocument();
    expect(screen.queryByText(/\(including prod-policy, staging-policy\)/)).toBeNull();
  });

  it("treats whitespace-only recovery names as unnamed tabs", () => {
    render(
      <CrashRecoveryBanner
        entries={[
          {
            tabId: "tab-1",
            policyName: "   ",
            yaml: "version: '1.2.0'\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 0, 0),
          },
          {
            tabId: "tab-2",
            policyName: "prod-policy",
            yaml: "version: '1.2.0'\nname: prod-policy\n",
            filePath: null,
            timestamp: Date.UTC(2026, 2, 11, 12, 1, 0),
          },
        ]}
        onRestore={vi.fn()}
        onDismiss={vi.fn()}
      />,
    );

    expect(screen.getByText("2 tabs")).toBeInTheDocument();
    expect(screen.getByText(/\(including prod-policy\)/)).toBeInTheDocument();
    expect(screen.queryByText(/\(including\s+\)/)).toBeNull();
  });
});
