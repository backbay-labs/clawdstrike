import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TestRunnerProvider, useTestRunner } from "../test-store";

function Harness() {
  const { state, dispatch } = useTestRunner();

  return (
    <div>
      <div data-testid="suite-yaml">{state.suiteYaml}</div>
      <button
        type="button"
        onClick={() => dispatch({ type: "SET_SUITE_YAML", yaml: 'scenarios: []\n' })}
      >
        set-suite
      </button>
    </div>
  );
}

describe("TestRunnerProvider", () => {
  it("resets suite state when the provider key changes", () => {
    const { rerender } = render(
      <TestRunnerProvider key="tab-a">
        <Harness />
      </TestRunnerProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "set-suite" }));
    expect(screen.getByTestId("suite-yaml").textContent).toContain("scenarios");

    rerender(
      <TestRunnerProvider key="tab-b">
        <Harness />
      </TestRunnerProvider>,
    );

    expect(screen.getByTestId("suite-yaml").textContent).toBe("");
  });
});
