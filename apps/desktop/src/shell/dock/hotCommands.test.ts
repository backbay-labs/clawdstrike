import { beforeEach, describe, expect, it } from "vitest";

import {
  HOT_COMMANDS_STORAGE_KEY,
  loadHotCommands,
  markHotCommandUsed,
  removeHotCommand,
  resolveHotCommandAction,
  saveHotCommands,
  upsertHotCommand,
} from "./hotCommands";

class MemoryStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

beforeEach(() => {
  (globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();
});

describe("hotCommands", () => {
  it("loads default commands when storage is empty", () => {
    const commands = loadHotCommands();
    expect(commands.length).toBeGreaterThan(0);
    expect(commands.some((entry) => entry.title === "Open Fleet")).toBe(true);
  });

  it("round-trips saved commands", () => {
    const seeded = upsertHotCommand(loadHotCommands(), {
      title: "Open Events",
      command: "/events",
      scope: "nexus",
      pinned: true,
    });

    saveHotCommands(seeded);
    const restored = loadHotCommands();
    expect(restored.some((entry) => entry.title === "Open Events")).toBe(true);
  });

  it("updates last-used timestamp and removes commands", () => {
    const seeded = upsertHotCommand(loadHotCommands(), {
      id: "custom_cmd",
      title: "Policy Tester",
      command: "/policy-tester",
    });

    const marked = markHotCommandUsed(seeded, "custom_cmd");
    const target = marked.find((entry) => entry.id === "custom_cmd");
    expect(target?.lastUsedAt).toBeDefined();

    const removed = removeHotCommand(marked, "custom_cmd");
    expect(removed.find((entry) => entry.id === "custom_cmd")).toBeUndefined();
  });

  it("parses command actions", () => {
    expect(resolveHotCommandAction("/operations?tab=fleet")).toEqual({
      kind: "navigate",
      path: "/operations?tab=fleet",
    });
    expect(resolveHotCommandAction("palette")).toEqual({ kind: "palette" });
    expect(resolveHotCommandAction("open nexus-labs")).toEqual({
      kind: "navigate",
      path: "/nexus",
    });
    expect(resolveHotCommandAction("announce command")).toEqual({
      kind: "event",
      payload: "announce command",
    });
    expect(resolveHotCommandAction("   ")).toEqual({
      kind: "invalid",
      reason: "Command is empty",
    });
  });

  it("handles invalid stored payload", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem(HOT_COMMANDS_STORAGE_KEY, "{broken");
    const commands = loadHotCommands();
    expect(commands.length).toBeGreaterThan(0);
  });
});
