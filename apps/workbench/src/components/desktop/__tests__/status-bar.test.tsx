import React from "react";
import { beforeEach, describe, it, expect, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { StatusBar } from "../status-bar";
import { renderWithProviders } from "@/test/test-helpers";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { useMultiPolicy, useWorkbench } from "@/lib/workbench/multi-policy-store";
import { isDesktop } from "@/lib/tauri-bridge";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

function DetectionStatusHarness() {
  const { multiDispatch } = useMultiPolicy();
  const { dispatch } = useWorkbench();

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

beforeEach(() => {
  vi.mocked(isDesktop).mockReturnValue(false);
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
});
