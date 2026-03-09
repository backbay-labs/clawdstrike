import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { readAutosave, clearAutosave, type AutosaveEntry } from "../use-auto-save";

// ---------------------------------------------------------------------------
// We test the exported utility functions (readAutosave, clearAutosave,
// writeAutosave is private so we simulate it via localStorage.setItem
// directly). The hook itself (useAutoSave) requires the full WorkbenchProvider
// context, so we focus on the underlying logic.
// ---------------------------------------------------------------------------

const AUTOSAVE_KEY = "clawdstrike_workbench_autosave";

function makeEntry(overrides?: Partial<AutosaveEntry>): AutosaveEntry {
  return {
    yaml: 'version: "1.2.0"\nname: "test"\nguards: {}',
    filePath: "/tmp/test.yaml",
    timestamp: 1741478400000,
    policyName: "test-policy",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// localStorage mock (jsdom in this project doesn't provide full localStorage)
// ---------------------------------------------------------------------------

let store: Record<string, string>;

const localStorageMock = {
  getItem: (key: string) => store[key] ?? null,
  setItem: (key: string, value: string) => { store[key] = value; },
  removeItem: (key: string) => { delete store[key]; },
  clear: () => { store = {}; },
  get length() { return Object.keys(store).length; },
  key: (index: number) => Object.keys(store)[index] ?? null,
};

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  store = {};
  vi.stubGlobal("localStorage", localStorageMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// readAutosave
// ---------------------------------------------------------------------------

describe("readAutosave", () => {
  it("returns null when nothing is stored", () => {
    expect(readAutosave()).toBeNull();
  });

  it("returns the stored entry when valid", () => {
    const entry = makeEntry();
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
    const result = readAutosave();
    expect(result).not.toBeNull();
    expect(result!.yaml).toBe(entry.yaml);
    expect(result!.filePath).toBe(entry.filePath);
    expect(result!.timestamp).toBe(entry.timestamp);
    expect(result!.policyName).toBe(entry.policyName);
  });

  it("returns null for invalid JSON", () => {
    localStorage.setItem(AUTOSAVE_KEY, "not valid json{{{");
    expect(readAutosave()).toBeNull();
  });

  it("returns null when stored value is not an object", () => {
    localStorage.setItem(AUTOSAVE_KEY, '"just a string"');
    expect(readAutosave()).toBeNull();
  });

  it("returns null when yaml field is missing", () => {
    localStorage.setItem(
      AUTOSAVE_KEY,
      JSON.stringify({ filePath: null, timestamp: 123, policyName: "test" }),
    );
    expect(readAutosave()).toBeNull();
  });

  it("returns null when timestamp field is not a number", () => {
    localStorage.setItem(
      AUTOSAVE_KEY,
      JSON.stringify({ yaml: "test", filePath: null, timestamp: "not a number", policyName: "test" }),
    );
    expect(readAutosave()).toBeNull();
  });

  it("returns null when policyName field is missing", () => {
    localStorage.setItem(
      AUTOSAVE_KEY,
      JSON.stringify({ yaml: "test", filePath: null, timestamp: 123 }),
    );
    expect(readAutosave()).toBeNull();
  });

  it("accepts null filePath", () => {
    const entry = makeEntry({ filePath: null });
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
    const result = readAutosave();
    expect(result).not.toBeNull();
    expect(result!.filePath).toBeNull();
  });

  it("returns null when stored value is null", () => {
    localStorage.setItem(AUTOSAVE_KEY, "null");
    expect(readAutosave()).toBeNull();
  });

  it("returns null when stored value is an array", () => {
    localStorage.setItem(AUTOSAVE_KEY, "[]");
    expect(readAutosave()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// clearAutosave
// ---------------------------------------------------------------------------

describe("clearAutosave", () => {
  it("removes the autosave entry from localStorage", () => {
    const entry = makeEntry();
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
    expect(localStorage.getItem(AUTOSAVE_KEY)).not.toBeNull();
    clearAutosave();
    expect(localStorage.getItem(AUTOSAVE_KEY)).toBeNull();
  });

  it("does not throw when nothing is stored", () => {
    expect(() => clearAutosave()).not.toThrow();
  });

  it("does not affect other localStorage keys", () => {
    localStorage.setItem("other_key", "value");
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(makeEntry()));
    clearAutosave();
    expect(localStorage.getItem("other_key")).toBe("value");
  });
});

// ---------------------------------------------------------------------------
// write + read roundtrip (via localStorage.setItem simulating writeAutosave)
// ---------------------------------------------------------------------------

describe("write + read roundtrip", () => {
  it("stores and retrieves yaml content correctly", () => {
    const yaml = `version: "1.4.0"\nname: "recovery-test"\nguards:\n  forbidden_path:\n    enabled: true`;
    const entry = makeEntry({ yaml, policyName: "recovery-test" });
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
    const result = readAutosave();
    expect(result).not.toBeNull();
    expect(result!.yaml).toBe(yaml);
    expect(result!.policyName).toBe("recovery-test");
  });

  it("stores and retrieves large yaml content", () => {
    const yaml = "version: '1.2.0'\n" + "# comment\n".repeat(1000);
    const entry = makeEntry({ yaml });
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
    const result = readAutosave();
    expect(result).not.toBeNull();
    expect(result!.yaml).toBe(yaml);
  });

  it("clearAutosave then readAutosave returns null", () => {
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(makeEntry()));
    clearAutosave();
    expect(readAutosave()).toBeNull();
  });

  it("multiple writes overwrite previous entry", () => {
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(makeEntry({ policyName: "first" })));
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(makeEntry({ policyName: "second" })));
    const result = readAutosave();
    expect(result!.policyName).toBe("second");
  });

  it("preserves special characters in yaml", () => {
    const yaml = 'patterns:\n  - "**/.ssh/**"\n  - "C:\\\\Users\\\\*"';
    const entry = makeEntry({ yaml });
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
    const result = readAutosave();
    expect(result!.yaml).toBe(yaml);
  });
});
