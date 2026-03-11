import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  MultiPolicyProvider,
  useMultiPolicy,
  useWorkbench,
} from "../multi-policy-store";
import type { WorkbenchPolicy } from "../types";

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
});
