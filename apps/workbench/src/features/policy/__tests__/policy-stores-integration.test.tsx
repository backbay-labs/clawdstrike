import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { PolicyBootstrapProvider } from "@/features/policy/hooks/use-policy-bootstrap";
import { usePolicyTabs, useWorkbenchState } from "@/features/policy/hooks/use-policy-actions";

const TABS_STORAGE_KEY = "clawdstrike_workbench_tabs";
const SAVED_POLICIES_KEY = "clawdstrike_workbench_policies";

function ReopenHarness() {
  const { multiDispatch } = usePolicyTabs();
  const { state } = useWorkbenchState();

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
            type: "OPEN_TAB_OR_SWITCH",
            filePath: "/tmp/policy.yaml",
            fileType: "clawdstrike_policy",
            yaml: '# from disk\nversion: "1.2.0"\nname: "Reloaded Policy"\n',
            name: "Reloaded Policy",
          }),
      },
      "reopen",
    ),
    React.createElement("pre", { "data-testid": "yaml" }, state.yaml),
    React.createElement("span", { "data-testid": "dirty" }, String(state.dirty)),
  );
}

function PersistedSensitiveHarness() {
  const { state } = useWorkbenchState();

  return React.createElement(
    "div",
    null,
    React.createElement("pre", { "data-testid": "persisted-yaml" }, state.yaml),
    React.createElement("span", { "data-testid": "persisted-dirty" }, String(state.dirty)),
    React.createElement("span", { "data-testid": "persisted-file-path" }, state.filePath ?? ""),
  );
}

function PersistedSuiteHarness() {
  const { activeTab } = usePolicyTabs();

  return React.createElement(
    "span",
    { "data-testid": "persisted-suite" },
    activeTab?.testSuiteYaml ?? "",
  );
}

function PersistedFileTypeHarness() {
  const { activeTab } = usePolicyTabs();

  return React.createElement(
    "span",
    { "data-testid": "persisted-file-type" },
    activeTab?.fileType ?? "",
  );
}

function SigmaTabHarness() {
  const { multiDispatch, activeTab, tabs } = usePolicyTabs();
  const { state } = useWorkbenchState();

  return React.createElement(
    "div",
    null,
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "sigma_rule",
            yaml: `title: Demo Sigma
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - calc
  condition: selection
level: medium
`,
          }),
      },
      "new-sigma",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () => multiDispatch({ type: "UPDATE_META", name: "Should Not Rewrite" }),
      },
      "update-meta",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "OPEN_TAB_OR_SWITCH",
            filePath: "/tmp/demo-rule.yar",
            fileType: "yara_rule",
            yaml: `rule demo_rule {
    condition:
        true
}
`,
          }),
      },
      "open-yara",
    ),
    React.createElement("span", { "data-testid": "active-file-type" }, activeTab?.fileType ?? ""),
    React.createElement("span", { "data-testid": "tab-count" }, String(tabs.length)),
    React.createElement("pre", { "data-testid": "active-yaml" }, state.yaml),
  );
}

function SaveSensitivePolicyHarness() {
  const { dispatch, saveCurrentPolicy } = useWorkbenchState();

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
        onClick: () =>
          dispatch({
            type: "SET_YAML",
            yaml: `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
    embedding_api_key: "super-secret"
  broken: [unterminated
`,
          }),
      },
      "set-broken-sensitive-yaml",
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

function YaraValidationHarness() {
  const { multiDispatch } = usePolicyTabs();
  const { state } = useWorkbenchState();

  return React.createElement(
    "div",
    null,
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `rule regex_quantifier {
  strings:
    $re = /a{2,3}/
  condition:
    $re
}
`,
          }),
      },
      "new-yara-regex",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `rule multiline_hex {
  strings:
    $hex = {
      AA BB
      CC DD
    }
  condition:
    $hex
}
`,
          }),
      },
      "new-yara-hex",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `rule commented_braces {
  /*
    this stray brace should not close the rule }
  */
  condition:
    true
}
`,
          }),
      },
      "new-yara-comment",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `/*
rule ignored_comment {
  condition:
    true
}
*/
rule actual_rule {
  condition:
    true
}
`,
          }),
      },
      "new-yara-commented-rule",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "yara_rule",
            yaml: `/* banner */ rule inline_comment {
  condition:
    true
}
`,
          }),
      },
      "new-yara-inline-comment-prefix",
    ),
    React.createElement("span", { "data-testid": "yara-valid" }, String(state.validation.valid)),
    React.createElement(
      "pre",
      { "data-testid": "yara-errors" },
      state.validation.errors.map((issue) => issue.message).join("\n"),
    ),
  );
}

function StructuredValidationHarness() {
  const { multiDispatch } = usePolicyTabs();
  const { state } = useWorkbenchState();

  return React.createElement(
    "div",
    null,
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "sigma_rule",
            yaml: `title: Broken Sigma
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
  category: process_creation
detection:
  selection: foo
  condition: selection
level: medium
`,
          }),
      },
      "new-sigma-bad-selector",
    ),
    React.createElement(
      "button",
      {
        type: "button",
        onClick: () =>
          multiDispatch({
            type: "NEW_TAB",
            fileType: "ocsf_event",
            yaml: '{"class_uid":1001,"activity_id":"x","severity_id":"high","metadata":{}}',
          }),
      },
      "new-ocsf-bad-types",
    ),
    React.createElement("span", { "data-testid": "structured-valid" }, String(state.validation.valid)),
    React.createElement(
      "pre",
      { "data-testid": "structured-errors" },
      state.validation.errors.map((issue) => issue.message).join("\n"),
    ),
  );
}

beforeEach(() => {
  localStorage.clear();
});

describe("Policy store integration", () => {
  it("reloads already-open files from disk instead of only switching tabs", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
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
        PolicyBootstrapProvider,
        null,
        React.createElement(PersistedSensitiveHarness),
      ),
    );

    expect(screen.getByTestId("persisted-yaml").textContent).toContain("spider_sense");
    expect(screen.getByTestId("persisted-dirty").textContent).toBe("true");
    expect(screen.getByTestId("persisted-file-path").textContent).toBe("");
  });

  it("drops persisted test suite yaml from browser storage on restore", () => {
    vi.useFakeTimers();
    try {
      localStorage.setItem(
        TABS_STORAGE_KEY,
        JSON.stringify({
          tabs: [
            {
              id: "tab-suite",
              name: "Suite Policy",
              filePath: null,
              yaml: `version: "1.2.0"\nname: "Suite Policy"\n`,
              testSuiteYaml: `scenarios:\n  - name: leaked-secret\n    input: "ghp_secret_value"\n`,
            },
          ],
          activeTabId: "tab-suite",
        }),
      );

      render(
        React.createElement(
          PolicyBootstrapProvider,
          null,
          React.createElement(PersistedSuiteHarness),
        ),
      );

      expect(screen.getByTestId("persisted-suite").textContent).toBe("");

      act(() => {
        vi.advanceTimersByTime(600);
      });

      const raw = localStorage.getItem(TABS_STORAGE_KEY);
      expect(raw).not.toContain("testSuiteYaml");
      expect(raw).not.toContain("ghp_secret_value");
    } finally {
      vi.useRealTimers();
    }
  });

  it("coerces invalid persisted file types back to a safe default", () => {
    localStorage.setItem(
      TABS_STORAGE_KEY,
      JSON.stringify({
        tabs: [
          {
            id: "tab-invalid-type",
            name: "Recovered Policy",
            fileType: "mystery_type",
            filePath: null,
            yaml: 'version: "1.2.0"\nname: "Recovered Policy"\n',
          },
        ],
        activeTabId: "tab-invalid-type",
      }),
    );

    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(PersistedFileTypeHarness),
      ),
    );

    expect(screen.getByTestId("persisted-file-type").textContent).toBe("clawdstrike_policy");
  });

  it("sanitizes saved policies before persisting them to localStorage", async () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
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

  it("sanitizes saved policies even when the current yaml is invalid", async () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(SaveSensitivePolicyHarness),
      ),
    );

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "set-sensitive-yaml" }));
      fireEvent.click(screen.getByRole("button", { name: "set-broken-sensitive-yaml" }));
      fireEvent.click(screen.getByRole("button", { name: "save-policy" }));
    });

    const raw = localStorage.getItem(SAVED_POLICIES_KEY);
    expect(raw).not.toBeNull();
    expect(raw).not.toContain("embedding_api_key");
    expect(raw).not.toContain("super-secret");
  });

  it("does not rewrite non-policy tabs through UPDATE_META actions", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(SigmaTabHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-sigma" }));
    const before = screen.getByTestId("active-yaml").textContent;

    fireEvent.click(screen.getByRole("button", { name: "update-meta" }));

    expect(screen.getByTestId("active-file-type").textContent).toBe("sigma_rule");
    expect(screen.getByTestId("active-yaml").textContent).toBe(before);
    expect(screen.getByTestId("active-yaml").textContent).toContain("title: Demo Sigma");
  });

  it("opens typed detection files in new tabs without clobbering the current tab", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(SigmaTabHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-sigma" }));
    fireEvent.click(screen.getByRole("button", { name: "open-yara" }));

    expect(screen.getByTestId("tab-count").textContent).toBe("3");
    expect(screen.getByTestId("active-file-type").textContent).toBe("yara_rule");
    expect(screen.getByTestId("active-yaml").textContent).toContain("rule demo_rule");
  });

  it("restores persisted Sigma tabs without coercing them into policies", () => {
    localStorage.setItem(
      TABS_STORAGE_KEY,
      JSON.stringify({
        tabs: [
          {
            id: "tab-sigma",
            name: "Persisted Sigma",
            filePath: "/tmp/persisted-sigma.yml",
            fileType: "sigma_rule",
            yaml: `title: Persisted Sigma
id: 22222222-2222-2222-2222-222222222222
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - whoami
  condition: selection
level: medium
`,
          },
        ],
        activeTabId: "tab-sigma",
      }),
    );

    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(SigmaTabHarness),
      ),
    );

    expect(screen.getByTestId("active-file-type").textContent).toBe("sigma_rule");
    expect(screen.getByTestId("active-yaml").textContent).toContain("title: Persisted Sigma");
    expect(screen.getByTestId("active-yaml").textContent).not.toContain("guards:");
  });

  it("does not miscount braces inside YARA regex literals", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(YaraValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-yara-regex" }));

    expect(screen.getByTestId("yara-valid").textContent).toBe("true");
    expect(screen.getByTestId("yara-errors").textContent).toBe("");
  });

  it("keeps multi-line YARA hex strings out of structural brace counting", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(YaraValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-yara-hex" }));

    expect(screen.getByTestId("yara-valid").textContent).toBe("true");
    expect(screen.getByTestId("yara-errors").textContent).toBe("");
  });

  it("ignores braces inside YARA block comments", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(YaraValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-yara-comment" }));

    expect(screen.getByTestId("yara-valid").textContent).toBe("true");
    expect(screen.getByTestId("yara-errors").textContent).toBe("");
  });

  it("ignores rule declarations that appear only inside multiline comments", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(YaraValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-yara-commented-rule" }));

    expect(screen.getByTestId("yara-valid").textContent).toBe("true");
    expect(screen.getByTestId("yara-errors").textContent).toBe("");
  });

  it("detects rule declarations that follow an inline block-comment prefix", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(YaraValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-yara-inline-comment-prefix" }));

    expect(screen.getByTestId("yara-valid").textContent).toBe("true");
    expect(screen.getByTestId("yara-errors").textContent).toBe("");
  });

  it("rejects Sigma sources without object-valued detection selectors", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(StructuredValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-sigma-bad-selector" }));

    expect(screen.getByTestId("structured-valid").textContent).toBe("false");
    expect(screen.getByTestId("structured-errors").textContent).toContain(
      "object-valued detection selector",
    );
  });

  it("rejects OCSF sources with invalid required field types", () => {
    render(
      React.createElement(
        PolicyBootstrapProvider,
        null,
        React.createElement(StructuredValidationHarness),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "new-ocsf-bad-types" }));

    expect(screen.getByTestId("structured-valid").textContent).toBe("false");
    expect(screen.getByTestId("structured-errors").textContent).toContain(
      "Invalid type for OCSF field activity_id",
    );
    expect(screen.getByTestId("structured-errors").textContent).toContain(
      "Invalid type for OCSF field severity_id",
    );
  });
});
