import { describe, it, expect, afterEach, vi } from "vitest";
import {
  registerGutterExtension,
  getGutterExtensions,
  onGutterExtensionChange,
} from "../gutter-extension-registry";
import type { GutterExtensionEntry } from "../gutter-extension-registry";

/**
 * Create a mock CodeMirror Extension value. In practice these are opaque
 * objects, but for testing we just need a unique reference.
 */
function mockExtension(label: string): unknown {
  return { __mock: label };
}

function makeEntry(
  id: string,
  ext?: unknown,
): GutterExtensionEntry {
  return {
    id,
    extension: ext ?? mockExtension(id),
  } as GutterExtensionEntry;
}

describe("gutter-extension-registry", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("registration adds extension and returns dispose", () => {
    const entry = makeEntry("plugin.gutter1");
    const dispose = registerGutterExtension(entry);
    disposers.push(dispose);

    const extensions = getGutterExtensions();
    expect(extensions).toHaveLength(1);
    expect(extensions[0]).toBe(entry.extension);
  });

  it("disposal removes extension and notifies listeners", () => {
    const listener = vi.fn();
    const unsub = onGutterExtensionChange(listener);
    disposers.push(unsub);

    const dispose = registerGutterExtension(makeEntry("plugin.disposable"));
    expect(getGutterExtensions()).toHaveLength(1);

    // Reset call count after registration notification
    listener.mockClear();

    dispose();
    expect(getGutterExtensions()).toHaveLength(0);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("duplicate id throws Error", () => {
    disposers.push(registerGutterExtension(makeEntry("plugin.dup")));
    expect(() => registerGutterExtension(makeEntry("plugin.dup"))).toThrow(
      'Gutter extension "plugin.dup" already registered',
    );
  });

  it("getGutterExtensions returns empty array when nothing registered (reference stable)", () => {
    const snap1 = getGutterExtensions();
    const snap2 = getGutterExtensions();
    expect(snap1).toEqual([]);
    expect(snap1).toBe(snap2); // same frozen reference
  });

  it("listener notification fires on register and dispose", () => {
    const listener = vi.fn();
    const unsub = onGutterExtensionChange(listener);
    disposers.push(unsub);

    const dispose = registerGutterExtension(makeEntry("plugin.notify"));
    expect(listener).toHaveBeenCalledTimes(1);

    dispose();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("multiple extensions returned in registration order", () => {
    const ext1 = mockExtension("first");
    const ext2 = mockExtension("second");
    const ext3 = mockExtension("third");

    disposers.push(registerGutterExtension(makeEntry("plugin.a", ext1)));
    disposers.push(registerGutterExtension(makeEntry("plugin.b", ext2)));
    disposers.push(registerGutterExtension(makeEntry("plugin.c", ext3)));

    const extensions = getGutterExtensions();
    expect(extensions).toHaveLength(3);
    expect(extensions[0]).toBe(ext1);
    expect(extensions[1]).toBe(ext2);
    expect(extensions[2]).toBe(ext3);
  });

  it("unsubscribe stops notifications", () => {
    const listener = vi.fn();
    const unsub = onGutterExtensionChange(listener);

    unsub();
    disposers.push(registerGutterExtension(makeEntry("plugin.after-unsub")));
    expect(listener).not.toHaveBeenCalled();
  });

  it("getGutterExtensions returns stable snapshot reference when no changes occur", () => {
    disposers.push(registerGutterExtension(makeEntry("plugin.stable")));
    const snap1 = getGutterExtensions();
    const snap2 = getGutterExtensions();
    expect(snap1).toBe(snap2); // same object identity
  });
});
