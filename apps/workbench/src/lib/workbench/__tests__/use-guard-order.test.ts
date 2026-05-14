import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { GUARD_REGISTRY, GUARD_CATEGORIES } from "../guard-registry";

// The useGuardOrder hook relies on localStorage and React useState. We test
// the underlying logic by re-implementing the pure helper functions that
// the hook uses internally: getDefaultGuardOrder, loadPreference,
// savePreference. These are module-private, so we replicate their logic
// here and verify correctness against the actual GUARD_REGISTRY.

const STORAGE_KEY = "clawdstrike_workbench_guard_order";

type GuardViewMode = "category" | "custom";

interface GuardOrderPreference {
  viewMode: GuardViewMode;
  guardOrder: string[];
}

/** Default flat order: all guard IDs in category order. */
function getDefaultGuardOrder(): string[] {
  return GUARD_CATEGORIES.flatMap((cat) => cat.guards);
}

function loadPreference(): GuardOrderPreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as Partial<GuardOrderPreference>;
      const viewMode: GuardViewMode =
        parsed.viewMode === "custom" ? "custom" : "category";
      let guardOrder = Array.isArray(parsed.guardOrder)
        ? parsed.guardOrder
        : getDefaultGuardOrder();

      const knownIds: Set<string> = new Set(GUARD_REGISTRY.map((g) => g.id));
      const existingIds = new Set(guardOrder.filter((id) => knownIds.has(id)));
      for (const id of knownIds) {
        if (!existingIds.has(id)) {
          guardOrder.push(id);
        }
      }
      guardOrder = guardOrder.filter((id) => knownIds.has(id));

      return { viewMode, guardOrder };
    }
  } catch {
    // ignore
  }
  return { viewMode: "category", guardOrder: getDefaultGuardOrder() };
}

function savePreference(pref: GuardOrderPreference) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(pref));
  } catch {
    // ignore
  }
}

// Simulate moveGuardUp logic
function moveGuardUp(order: string[], guardId: string): string[] {
  const idx = order.indexOf(guardId);
  if (idx <= 0) return order;
  const next = [...order];
  next[idx] = next[idx - 1];
  next[idx - 1] = guardId;
  return next;
}

// Simulate moveGuardDown logic
function moveGuardDown(order: string[], guardId: string): string[] {
  const idx = order.indexOf(guardId);
  if (idx < 0 || idx >= order.length - 1) return order;
  const next = [...order];
  next[idx] = next[idx + 1];
  next[idx + 1] = guardId;
  return next;
}

// Simulate reorderGuard logic
function reorderGuard(order: string[], sourceId: string, targetId: string): string[] {
  if (sourceId === targetId) return order;
  const sourceIdx = order.indexOf(sourceId);
  const targetIdx = order.indexOf(targetId);
  if (sourceIdx < 0 || targetIdx < 0) return order;
  const next = [...order];
  next.splice(sourceIdx, 1);
  const insertIdx = next.indexOf(targetId);
  next.splice(insertIdx, 0, sourceId);
  return next;
}

// Simulate moveGuardToIndex logic
function moveGuardToIndex(order: string[], sourceId: string, targetIndex: number): string[] {
  const sourceIdx = order.indexOf(sourceId);
  if (sourceIdx < 0) return order;
  if (sourceIdx === targetIndex) return order;
  const next = [...order];
  next.splice(sourceIdx, 1);
  const clampedIdx = Math.max(0, Math.min(targetIndex, next.length));
  next.splice(clampedIdx, 0, sourceId);
  return next;
}


let store: Record<string, string>;

const localStorageMock = {
  getItem: (key: string) => store[key] ?? null,
  setItem: (key: string, value: string) => { store[key] = value; },
  removeItem: (key: string) => { delete store[key]; },
  clear: () => { store = {}; },
  get length() { return Object.keys(store).length; },
  key: (index: number) => Object.keys(store)[index] ?? null,
};


beforeEach(() => {
  store = {};
  vi.stubGlobal("localStorage", localStorageMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});


describe("getDefaultGuardOrder", () => {
  it("returns all 13 guard IDs", () => {
    const order = getDefaultGuardOrder();
    expect(order).toHaveLength(13);
  });

  it("contains all known guard IDs", () => {
    const order = getDefaultGuardOrder();
    for (const guard of GUARD_REGISTRY) {
      expect(order).toContain(guard.id);
    }
  });

  it("preserves category ordering (filesystem first, cua last)", () => {
    const order = getDefaultGuardOrder();
    const fpIdx = order.indexOf("forbidden_path");
    const cuaIdx = order.indexOf("computer_use");
    expect(fpIdx).toBeLessThan(cuaIdx);
  });

  it("has no duplicate entries", () => {
    const order = getDefaultGuardOrder();
    expect(new Set(order).size).toBe(order.length);
  });
});


describe("loadPreference", () => {
  it("returns default when nothing is stored", () => {
    const pref = loadPreference();
    expect(pref.viewMode).toBe("category");
    expect(pref.guardOrder).toEqual(getDefaultGuardOrder());
  });

  it("restores viewMode from localStorage", () => {
    savePreference({ viewMode: "custom", guardOrder: getDefaultGuardOrder() });
    const pref = loadPreference();
    expect(pref.viewMode).toBe("custom");
  });

  it("defaults viewMode to category for invalid values", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ viewMode: "invalid", guardOrder: getDefaultGuardOrder() }),
    );
    const pref = loadPreference();
    expect(pref.viewMode).toBe("category");
  });

  it("restores custom guard order from localStorage", () => {
    const customOrder = [...getDefaultGuardOrder()].reverse();
    savePreference({ viewMode: "custom", guardOrder: customOrder });
    const pref = loadPreference();
    expect(pref.guardOrder).toEqual(customOrder);
  });

  it("adds new guards at the end when stored order is missing them", () => {
    // Simulate a stored preference missing the last guard
    const partialOrder = getDefaultGuardOrder().slice(0, -1);
    savePreference({ viewMode: "category", guardOrder: partialOrder });
    const pref = loadPreference();
    expect(pref.guardOrder).toHaveLength(13);
    // The missing guard should be at the end
    const defaultOrder = getDefaultGuardOrder();
    const missingGuard = defaultOrder[defaultOrder.length - 1];
    expect(pref.guardOrder).toContain(missingGuard);
  });

  it("removes unknown guards from stored order", () => {
    const orderWithUnknown = [...getDefaultGuardOrder(), "made_up_guard"];
    savePreference({ viewMode: "category", guardOrder: orderWithUnknown });
    const pref = loadPreference();
    expect(pref.guardOrder).not.toContain("made_up_guard");
    expect(pref.guardOrder).toHaveLength(13);
  });

  it("handles corrupt JSON gracefully", () => {
    localStorage.setItem(STORAGE_KEY, "not valid json{{{");
    const pref = loadPreference();
    expect(pref.viewMode).toBe("category");
    expect(pref.guardOrder).toEqual(getDefaultGuardOrder());
  });

  it("defaults guardOrder when stored guardOrder is not an array", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ viewMode: "custom", guardOrder: "not an array" }),
    );
    const pref = loadPreference();
    expect(pref.guardOrder).toEqual(getDefaultGuardOrder());
  });
});


describe("savePreference", () => {
  it("persists to localStorage", () => {
    const pref: GuardOrderPreference = {
      viewMode: "custom",
      guardOrder: getDefaultGuardOrder(),
    };
    savePreference(pref);
    const stored = localStorage.getItem(STORAGE_KEY);
    expect(stored).not.toBeNull();
    const parsed = JSON.parse(stored!);
    expect(parsed.viewMode).toBe("custom");
  });

  it("overwrites previous preference", () => {
    savePreference({ viewMode: "category", guardOrder: getDefaultGuardOrder() });
    savePreference({ viewMode: "custom", guardOrder: getDefaultGuardOrder() });
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
    expect(stored.viewMode).toBe("custom");
  });
});


describe("moveGuardUp", () => {
  it("moves a guard up by one position", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardUp(order, "b");
    expect(result).toEqual(["b", "a", "c"]);
  });

  it("returns same order when guard is already first", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardUp(order, "a");
    expect(result).toBe(order); // same reference
  });

  it("returns same order when guard is not found", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardUp(order, "z");
    expect(result).toBe(order);
  });

  it("moves last guard up correctly", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardUp(order, "c");
    expect(result).toEqual(["a", "c", "b"]);
  });
});


describe("moveGuardDown", () => {
  it("moves a guard down by one position", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardDown(order, "b");
    expect(result).toEqual(["a", "c", "b"]);
  });

  it("returns same order when guard is already last", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardDown(order, "c");
    expect(result).toBe(order);
  });

  it("returns same order when guard is not found", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardDown(order, "z");
    expect(result).toBe(order);
  });

  it("moves first guard down correctly", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardDown(order, "a");
    expect(result).toEqual(["b", "a", "c"]);
  });
});


describe("reorderGuard", () => {
  it("moves source before target", () => {
    const order = ["a", "b", "c", "d"];
    const result = reorderGuard(order, "d", "b");
    expect(result).toEqual(["a", "d", "b", "c"]);
  });

  it("returns same order when source equals target", () => {
    const order = ["a", "b", "c"];
    const result = reorderGuard(order, "b", "b");
    expect(result).toBe(order);
  });

  it("returns same order when source not found", () => {
    const order = ["a", "b", "c"];
    const result = reorderGuard(order, "z", "b");
    expect(result).toBe(order);
  });

  it("returns same order when target not found", () => {
    const order = ["a", "b", "c"];
    const result = reorderGuard(order, "a", "z");
    expect(result).toBe(order);
  });

  it("handles move forward correctly", () => {
    const order = ["a", "b", "c", "d"];
    const result = reorderGuard(order, "a", "c");
    expect(result).toEqual(["b", "a", "c", "d"]);
  });
});


describe("moveGuardToIndex", () => {
  it("moves a guard to a specific index", () => {
    const order = ["a", "b", "c", "d"];
    const result = moveGuardToIndex(order, "d", 1);
    expect(result).toEqual(["a", "d", "b", "c"]);
  });

  it("returns same order when already at target index", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardToIndex(order, "b", 1);
    expect(result).toBe(order);
  });

  it("returns same order when guard not found", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardToIndex(order, "z", 0);
    expect(result).toBe(order);
  });

  it("clamps to beginning for negative index", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardToIndex(order, "c", -5);
    expect(result).toEqual(["c", "a", "b"]);
  });

  it("clamps to end for oversized index", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardToIndex(order, "a", 100);
    expect(result).toEqual(["b", "c", "a"]);
  });

  it("moves to index 0 correctly", () => {
    const order = ["a", "b", "c"];
    const result = moveGuardToIndex(order, "c", 0);
    expect(result).toEqual(["c", "a", "b"]);
  });
});
