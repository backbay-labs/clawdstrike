import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  MultiPolicyProvider,
  useMultiPolicy,
  useWorkbench,
} from "../multi-policy-store";
import type { WorkbenchPolicy } from "../types";

const TABS_STORAGE_KEY = "clawdstrike_workbench_tabs";
const SAVED_POLICIES_KEY = "clawdstrike_workbench_policies";

function makePolicy(name: string): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name,
    description: "",
    guards: {},
    settings: {},
  };
}

function ReopenHarness() {
  const { multiDispatch } = useMultiPolicy();
  const { state } = useWorkbench();

  return React.createElement(
    "div",
    null,
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () => multiDispatch({ type: "SET_FILE_PATH", path: "/tmp/policy.yaml" }),
      },
      "set-path",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () => multiDispatch({ type: "UPDATE_META", name: "Dirty Policy" }),
      },
      "dirty",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB_OR_SWITCH",
            policy: makePolicy("Reloaded Policy"),
            filePath: "/tmp/policy.yaml",
            fallbackYaml: '# from disk\nversion: "1.2.0"\nname: "Reloaded Policy"\n',
          }),
      },
      "reopen",
    ),
    React.createElement("pre", { "data-testid": "yaml" }, state.yaml),
    React.createElement("span", { "data-testid": "dirty" }, String(state.dirty)),
  );
}

function PersistedSensitiveHarness() {
  const { state } = useWorkbench();

  return React.createElement(
    "div",
    null,
    React.createElement("pre", { "data-testid": "persisted-yaml" }, state.yaml),
    React.createElement("span", { "data-testid": "persisted-dirty" }, String(state.dirty)),
    React.createElement("span", { "data-testid": "persisted-file-path" }, state.filePath ?? ""),
  );
}

function SaveSensitivePolicyHarness() {
  const { dispatch, saveCurrentPolicy } = useWorkbench();

  return React.createElement(
    "div",
    null,
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          dispatch({
            type: "SET_YAML",
            yaml: `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
    embedding_api_key: "super-secret"
`,
          }),
      },
      "set-sensitive-yaml",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () => saveCurrentPolicy(),
      },
      "save-policy",
    ),
  );
}

beforeEach(() => {
  localStorage.clear();
});

describe("MultiPolicyProvider", () => {
  it("reloads already-open files from disk instead of only switching tabs", () => {
    render(
      React.createElement(
        MultiPolicyProvider,
        null,
        React.createElement(ReopenHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "set-path" }));
    fireEvent.click(screen.getByRole("button", { name: "dirty" }));

    expect(screen.getByTestId("yaml").textContent).toContain("Dirty Policy");
    expect(screen.getByTestId("dirty").textContent).toBe("true");

    act(() => {
      fireEvent.click(screen.getByRole("button", { name: "reopen" }));
    });

    expect(screen.getByTestId("yaml").textContent).toContain("# from disk");
    expect(screen.getByTestId("yaml").textContent).toContain("Reloaded Policy");
    expect(screen.getByTestId("dirty").textContent).toBe("false");
  });

  it("restores tabs with stripped sensitive fields as unsaved dirty tabs", () => {
    localStorage.setItem(
      TABS_STORAGE_KEY,
      JSON.stringify({
        tabs: [
          {
            id: "tab-sensitive",
            name: "Sensitive Policy",
            filePath: "/tmp/sensitive.yaml",
            yaml: `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
`,
            sensitiveFieldsStripped: true,
          },
        ],
        activeTabId: "tab-sensitive",
      }),
    );

    render(
      React.createElement(
        MultiPolicyProvider,
        null,
        React.createElement(PersistedSensitiveHarness),
      ),
    );

    expect(screen.getByTestId("persisted-yaml").textContent).toContain("spider_sense");
    expect(screen.getByTestId("persisted-dirty").textContent).toBe("true");
    expect(screen.getByTestId("persisted-file-path").textContent).toBe("");
  });

  it("sanitizes saved policies before persisting them to localStorage", async () => {
    render(
      React.createElement(
        MultiPolicyProvider,
        null,
        React.createElement(SaveSensitivePolicyHarness),
      ),
    );

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "set-sensitive-yaml" }));
      fireEvent.click(screen.getByRole("button", { name: "save-policy" }));
    });

    const raw = localStorage.getItem(SAVED_POLICIES_KEY);
    expect(raw).not.toBeNull();
    expect(raw).not.toContain("embedding_api_key");
    expect(raw).not.toContain("super-secret");
  });
});
