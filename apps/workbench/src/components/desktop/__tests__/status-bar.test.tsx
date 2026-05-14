import React from "react";
import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { StatusBar } from "../status-bar";
import { renderWithProviders } from "@/test/test-helpers";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { usePolicyTabs, useWorkbenchState } from "@/features/policy/hooks/use-policy-actions";
import { isDesktop } from "@/lib/tauri-bridge";
import { usePaneStore } from "@/features/panes/pane-store";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

function DetectionStatusHarness() {
  const { multiDispatch } = usePolicyTabs();
  const { dispatch } = useWorkbenchState();

  return (
    <>
      <button
        type="button"
        onClick={() =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `rule demo_rule {
  strings:
    $re = /a{2,3}/
  condition:
    $re
}
`,
          })}
      >
        open-yara
      </button>
      <button
        type="button"
        onClick={() =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `rule missing_condition {
  strings:
    $a = "x"
}
`,
          })}
      >
        open-invalid-yara
      </button>
      <button
        type="button"
        onClick={() =>
          dispatch({
            type: "SET_NATIVE_VALIDATION",
            payload: {
              guardErrors: {},
              topLevelErrors: ["Native YARA validation failed"],
              topLevelWarnings: [],
              loading: false,
              valid: false,
            },
          })}
      >
        set-native-invalid
      </button>
      <button
        type="button"
        onClick={() =>
          dispatch({
            type: "SET_NATIVE_VALIDATION",
            payload: {
              guardErrors: {},
              topLevelErrors: [],
              topLevelWarnings: [],
              loading: true,
              valid: null,
            },
          })}
      >
        set-native-loading
      </button>
      <StatusBar />
    </>
  );
}

function StatusBarVisibilityHarness() {
  const { multiDispatch } = usePolicyTabs();
  const [ready, setReady] = React.useState(false);

  React.useEffect(() => {
    multiDispatch({
      type: "NEW_TAB",
      fileType: "yara_rule",
      yaml: `rule demo_rule {
  strings:
    $re = /a{2,3}/
  condition:
    $re
}
`,
    });
    setReady(true);
  }, [multiDispatch]);

  if (!ready) {
    return null;
  }

  return (
    <>
      <button type="button" onClick={() => multiDispatch({ type: "NEW_TAB" })}>
        open-policy
      </button>
      <StatusBar />
    </>
  );
}

beforeEach(() => {
  vi.mocked(isDesktop).mockReturnValue(false);
});

afterEach(() => {
  usePaneStore.getState()._reset();
});

describe("StatusBar", () => {
  it("shows 'Valid' status when there are no errors or warnings", () => {
    renderWithProviders(<StatusBar />);

    expect(screen.getByText("Valid")).toBeInTheDocument();
  });

  it("shows the checkmark icon for valid state", () => {
    renderWithProviders(<StatusBar />);

    // Unicode checkmark U+2714
    expect(screen.getByText("\u2714")).toBeInTheDocument();
  });

  it("shows guard count in the format enabled/total", () => {
    renderWithProviders(<StatusBar />);

    const totalGuards = GUARD_REGISTRY.length;
    // Default policy has 3 enabled guards: forbidden_path, egress_allowlist, secret_leak
    expect(screen.getByText(`3/${totalGuards} guards`)).toBeInTheDocument();
  });

  it("shows the schema version from active policy", () => {
    renderWithProviders(<StatusBar />);

    // Default policy version is "1.2.0"
    expect(screen.getByText("v1.2.0")).toBeInTheDocument();
  });

  it("shows 'unsaved' when there is no file path", () => {
    renderWithProviders(<StatusBar />);

    expect(screen.getByText("unsaved")).toBeInTheDocument();
  });

  it("hides the unsaved file-path segment for unsaved file routes", () => {
    usePaneStore.getState().syncRoute("/file/__new__/draft-policy");

    renderWithProviders(<StatusBar />);

    expect(screen.queryByText("unsaved")).not.toBeInTheDocument();
  });

  it("renders as a footer element", () => {
    renderWithProviders(<StatusBar />);

    const footer = screen.getByRole("contentinfo");
    expect(footer).toBeInTheDocument();
    expect(footer.tagName).toBe("FOOTER");
  });

  it("prefers native validation status for detection tabs when available", () => {
    vi.mocked(isDesktop).mockReturnValue(true);
    renderWithProviders(<DetectionStatusHarness />);

    fireEvent.click(screen.getByRole("button", { name: "open-yara" }));
    fireEvent.click(screen.getByRole("button", { name: "set-native-invalid" }));

    expect(screen.getByText("1 error")).toBeInTheDocument();
    expect(screen.getByText("YARA Rule")).toBeInTheDocument();
  });

  it("shows a validating state while desktop native validation is still pending", () => {
    vi.mocked(isDesktop).mockReturnValue(true);
    renderWithProviders(<DetectionStatusHarness />);

    fireEvent.click(screen.getByRole("button", { name: "open-invalid-yara" }));
    fireEvent.click(screen.getByRole("button", { name: "set-native-loading" }));

    expect(screen.getByText("Validating...")).toBeInTheDocument();
    expect(screen.queryByText("1 error")).not.toBeInTheDocument();
    expect(screen.getByText("YARA Rule")).toBeInTheDocument();
  });

  it("falls back to format-aware client validation for detection tabs on web", () => {
    renderWithProviders(<DetectionStatusHarness />);

    fireEvent.click(screen.getByRole("button", { name: "open-invalid-yara" }));

    expect(screen.getByText("1 error")).toBeInTheDocument();
    expect(screen.getByText("YARA Rule")).toBeInTheDocument();
  });

  it("reveals segments that start empty once their content appears", async () => {
    renderWithProviders(<StatusBarVisibilityHarness />);

    expect(screen.queryByText("v1.2.0")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "open-policy" }));

    await waitFor(() => {
      expect(screen.getByText("v1.2.0")).toBeInTheDocument();
    });
  });
});
