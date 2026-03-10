import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import React from "react";
import {
  HintSettingsProvider,
  useHintSettings,
  DEFAULT_HINTS,
  HINT_LABELS,
  type HintId,
} from "../use-hint-settings";

// ---------------------------------------------------------------------------
// The setup.ts file already provides a localStorage mock that resets between
// tests (beforeEach → localStorage.clear()), so we can read/write directly.
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_hint_settings";

/** Helper: render the hook inside the provider. */
function renderHintSettings() {
  return renderHook(() => useHintSettings(), {
    wrapper: ({ children }: { children: React.ReactNode }) =>
      React.createElement(HintSettingsProvider, null, children),
  });
}

// ---------------------------------------------------------------------------
// loadState (tested indirectly through the provider reading localStorage)
// ---------------------------------------------------------------------------

describe("loadState / initial state", () => {
  it("returns defaults when localStorage is empty", () => {
    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(true);

    const allIds = Object.keys(DEFAULT_HINTS) as HintId[];
    for (const id of allIds) {
      expect(result.current.getHint(id)).toEqual(DEFAULT_HINTS[id]);
      expect(result.current.isCustomized(id)).toBe(false);
    }
  });

  it("returns defaults when localStorage has invalid JSON", () => {
    localStorage.setItem(STORAGE_KEY, "not valid json{{{");
    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(true);
    expect(result.current.getHint("home.audit")).toEqual(DEFAULT_HINTS["home.audit"]);
  });

  it("returns defaults when localStorage has wrong schema (string instead of object)", () => {
    localStorage.setItem(STORAGE_KEY, '"just a string"');
    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(true);
  });

  it("returns defaults when localStorage has null", () => {
    localStorage.setItem(STORAGE_KEY, "null");
    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(true);
  });

  it("returns defaults when localStorage has an array", () => {
    localStorage.setItem(STORAGE_KEY, "[]");
    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(true);
  });

  it("correctly merges stored overrides with defaults", () => {
    const state = {
      showHints: false,
      overrides: {
        "home.audit": { hint: "Custom audit hint" },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(false);
    const hint = result.current.getHint("home.audit");
    expect(hint.hint).toBe("Custom audit hint");
    // prompt should still be the default since it wasn't overridden
    expect(hint.prompt).toBe(DEFAULT_HINTS["home.audit"].prompt);
  });

  it("ignores unknown hint IDs in overrides (they are stored but getHint only handles known IDs)", () => {
    const state = {
      showHints: true,
      overrides: {
        "unknown.hint.id": { hint: "this should be ignored" },
        "home.audit": { hint: "valid override" },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    const hint = result.current.getHint("home.audit");
    expect(hint.hint).toBe("valid override");
    // Known IDs without overrides still return defaults
    expect(result.current.getHint("editor.validate")).toEqual(DEFAULT_HINTS["editor.validate"]);
  });

  it("ignores overrides with non-object values", () => {
    const state = {
      showHints: true,
      overrides: {
        "home.audit": "not an object",
        "editor.validate": null,
        "simulator.scenarios": 42,
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    expect(result.current.getHint("home.audit")).toEqual(DEFAULT_HINTS["home.audit"]);
    expect(result.current.getHint("editor.validate")).toEqual(DEFAULT_HINTS["editor.validate"]);
  });

  it("ignores override fields with empty strings", () => {
    const state = {
      showHints: true,
      overrides: {
        "home.audit": { hint: "", prompt: "" },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    expect(result.current.getHint("home.audit")).toEqual(DEFAULT_HINTS["home.audit"]);
    expect(result.current.isCustomized("home.audit")).toBe(false);
  });

  it("handles overrides with non-string hint/prompt values", () => {
    const state = {
      showHints: true,
      overrides: {
        "home.audit": { hint: 42, prompt: true },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    // Non-string values are skipped by loadState validation
    expect(result.current.getHint("home.audit")).toEqual(DEFAULT_HINTS["home.audit"]);
  });
});

// ---------------------------------------------------------------------------
// persistState (tested indirectly through mutations)
// ---------------------------------------------------------------------------

describe("persistState / setShowHints", () => {
  it("persistState writes to localStorage when showHints changes", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.setShowHints(false);
    });

    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.showHints).toBe(false);
  });

  it("showHints defaults to true", () => {
    const { result } = renderHintSettings();
    expect(result.current.showHints).toBe(true);
  });

  it("showHints toggle persists to localStorage", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.setShowHints(false);
    });
    expect(result.current.showHints).toBe(false);
    expect(JSON.parse(localStorage.getItem(STORAGE_KEY)!).showHints).toBe(false);

    act(() => {
      result.current.setShowHints(true);
    });
    expect(result.current.showHints).toBe(true);
    expect(JSON.parse(localStorage.getItem(STORAGE_KEY)!).showHints).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// getHint
// ---------------------------------------------------------------------------

describe("getHint", () => {
  it("returns default when no override exists", () => {
    const { result } = renderHintSettings();
    const hint = result.current.getHint("editor.validate");
    expect(hint).toEqual(DEFAULT_HINTS["editor.validate"]);
  });

  it("returns merged value when partial override exists (hint overridden but prompt default)", () => {
    const state = {
      showHints: true,
      overrides: {
        "editor.validate": { hint: "Custom validate hint" },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    const hint = result.current.getHint("editor.validate");
    expect(hint.hint).toBe("Custom validate hint");
    expect(hint.prompt).toBe(DEFAULT_HINTS["editor.validate"].prompt);
  });

  it("returns full override when both hint and prompt are overridden", () => {
    const state = {
      showHints: true,
      overrides: {
        "editor.validate": {
          hint: "Custom hint",
          prompt: "Custom prompt",
        },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    const hint = result.current.getHint("editor.validate");
    expect(hint.hint).toBe("Custom hint");
    expect(hint.prompt).toBe("Custom prompt");
  });

  it("returns merged value when only prompt is overridden", () => {
    const state = {
      showHints: true,
      overrides: {
        "simulator.scenarios": { prompt: "Custom prompt only" },
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));

    const { result } = renderHintSettings();
    const hint = result.current.getHint("simulator.scenarios");
    expect(hint.hint).toBe(DEFAULT_HINTS["simulator.scenarios"].hint);
    expect(hint.prompt).toBe("Custom prompt only");
  });
});

// ---------------------------------------------------------------------------
// updateHint
// ---------------------------------------------------------------------------

describe("updateHint", () => {
  it("persists to localStorage", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "Updated hint" });
    });

    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.overrides["home.audit"]).toEqual({ hint: "Updated hint" });
  });

  it("marks the hint as customized", () => {
    const { result } = renderHintSettings();

    expect(result.current.isCustomized("home.audit")).toBe(false);

    act(() => {
      result.current.updateHint("home.audit", { hint: "Changed" });
    });

    expect(result.current.isCustomized("home.audit")).toBe(true);
  });

  it("does not store override when value matches default", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", {
        hint: DEFAULT_HINTS["home.audit"].hint,
      });
    });

    // Setting to the default value should remove the override
    expect(result.current.isCustomized("home.audit")).toBe(false);
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.overrides["home.audit"]).toBeUndefined();
  });

  it("merges partial updates with existing overrides", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "Step 1" });
    });
    act(() => {
      result.current.updateHint("home.audit", { prompt: "Step 2" });
    });

    const hint = result.current.getHint("home.audit");
    expect(hint.hint).toBe("Step 1");
    expect(hint.prompt).toBe("Step 2");
  });

  it("updates getHint return value immediately", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("risk.assess", { hint: "New risk hint" });
    });

    expect(result.current.getHint("risk.assess").hint).toBe("New risk hint");
    expect(result.current.getHint("risk.assess").prompt).toBe(
      DEFAULT_HINTS["risk.assess"].prompt,
    );
  });
});

// ---------------------------------------------------------------------------
// resetHint
// ---------------------------------------------------------------------------

describe("resetHint", () => {
  it("removes the override for one hint", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "Custom" });
      result.current.updateHint("editor.validate", { hint: "Also custom" });
    });

    expect(result.current.isCustomized("home.audit")).toBe(true);
    expect(result.current.isCustomized("editor.validate")).toBe(true);

    act(() => {
      result.current.resetHint("home.audit");
    });

    expect(result.current.isCustomized("home.audit")).toBe(false);
    expect(result.current.getHint("home.audit")).toEqual(DEFAULT_HINTS["home.audit"]);
    // Other override is unaffected
    expect(result.current.isCustomized("editor.validate")).toBe(true);
  });

  it("persists to localStorage after reset", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "Temp" });
    });
    act(() => {
      result.current.resetHint("home.audit");
    });

    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.overrides["home.audit"]).toBeUndefined();
  });

  it("is safe to call on a hint with no override", () => {
    const { result } = renderHintSettings();

    // Should not throw
    act(() => {
      result.current.resetHint("home.audit");
    });

    expect(result.current.getHint("home.audit")).toEqual(DEFAULT_HINTS["home.audit"]);
  });
});

// ---------------------------------------------------------------------------
// resetAll
// ---------------------------------------------------------------------------

describe("resetAll", () => {
  it("removes all overrides", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "A" });
      result.current.updateHint("editor.validate", { hint: "B" });
      result.current.updateHint("simulator.scenarios", { prompt: "C" });
    });

    act(() => {
      result.current.resetAll();
    });

    const allIds = Object.keys(DEFAULT_HINTS) as HintId[];
    for (const id of allIds) {
      expect(result.current.isCustomized(id)).toBe(false);
      expect(result.current.getHint(id)).toEqual(DEFAULT_HINTS[id]);
    }
  });

  it("persists empty overrides to localStorage", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "Custom" });
    });
    act(() => {
      result.current.resetAll();
    });

    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.overrides).toEqual({});
  });

  it("preserves showHints value", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.setShowHints(false);
      result.current.updateHint("home.audit", { hint: "Custom" });
    });
    act(() => {
      result.current.resetAll();
    });

    expect(result.current.showHints).toBe(false);
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.showHints).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isCustomized
// ---------------------------------------------------------------------------

describe("isCustomized", () => {
  it("returns false for defaults", () => {
    const { result } = renderHintSettings();

    const allIds = Object.keys(DEFAULT_HINTS) as HintId[];
    for (const id of allIds) {
      expect(result.current.isCustomized(id)).toBe(false);
    }
  });

  it("returns true after update", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("library.compare", { hint: "Changed" });
    });

    expect(result.current.isCustomized("library.compare")).toBe(true);
  });

  it("returns false after reset", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("library.compare", { hint: "Changed" });
    });
    act(() => {
      result.current.resetHint("library.compare");
    });

    expect(result.current.isCustomized("library.compare")).toBe(false);
  });

  it("returns false when updating a hint back to its default value", () => {
    const { result } = renderHintSettings();

    act(() => {
      result.current.updateHint("home.audit", { hint: "Temporary" });
    });
    expect(result.current.isCustomized("home.audit")).toBe(true);

    act(() => {
      result.current.updateHint("home.audit", {
        hint: DEFAULT_HINTS["home.audit"].hint,
      });
    });
    expect(result.current.isCustomized("home.audit")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// HINT_LABELS / DEFAULT_HINTS coverage
// ---------------------------------------------------------------------------

describe("HINT_LABELS and DEFAULT_HINTS", () => {
  it("all 10 hint IDs have labels", () => {
    const ids = Object.keys(HINT_LABELS) as HintId[];
    expect(ids).toHaveLength(10);
  });

  it("all 10 hint IDs have default configs", () => {
    const ids = Object.keys(DEFAULT_HINTS) as HintId[];
    expect(ids).toHaveLength(10);
  });

  it("HINT_LABELS and DEFAULT_HINTS have the same keys", () => {
    const labelKeys = Object.keys(HINT_LABELS).sort();
    const defaultKeys = Object.keys(DEFAULT_HINTS).sort();
    expect(labelKeys).toEqual(defaultKeys);
  });

  it("every default config has non-empty hint and prompt strings", () => {
    for (const [id, config] of Object.entries(DEFAULT_HINTS)) {
      expect(config.hint.length).toBeGreaterThan(0);
      expect(config.prompt.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// useHintSettings outside provider
// ---------------------------------------------------------------------------

describe("useHintSettings outside provider", () => {
  it("throws when used outside HintSettingsProvider", () => {
    // Suppress React error boundary logs
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(() => {
      renderHook(() => useHintSettings());
    }).toThrow("useHintSettings must be used within HintSettingsProvider");

    spy.mockRestore();
  });
});
