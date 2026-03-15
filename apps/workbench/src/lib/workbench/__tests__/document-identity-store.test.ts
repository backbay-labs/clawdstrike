import { describe, it, expect, beforeEach } from "vitest";
import {
  DocumentIdentityStore,
  normalizePath,
} from "../detection-workflow/document-identity-store";

describe("normalizePath", () => {
  it("collapses repeated slashes", () => {
    expect(normalizePath("/foo//bar///baz")).toMatch(/\/foo\/bar\/baz/i);
  });

  it("strips trailing slashes", () => {
    expect(normalizePath("/foo/bar/")).toMatch(/\/foo\/bar$/i);
  });

  it("normalizes backslashes to forward slashes", () => {
    expect(normalizePath("C:\\Users\\test\\file.yaml")).toMatch(
      /c:\/users\/test\/file\.yaml/i,
    );
  });
});

describe("DocumentIdentityStore", () => {
  let store: DocumentIdentityStore;

  beforeEach(() => {
    localStorage.clear();
    store = new DocumentIdentityStore();
  });

  it("returns null for unknown paths", () => {
    expect(store.resolve("/nonexistent/path.yaml")).toBeNull();
  });

  it("registers and resolves an alias", () => {
    store.register("/home/user/policy.yaml", "doc-123");
    expect(store.resolve("/home/user/policy.yaml")).toBe("doc-123");
  });

  it("survives persistence round-trip", () => {
    store.register("/home/user/policy.yaml", "doc-456");

    // Create a new instance that loads from localStorage
    const store2 = new DocumentIdentityStore();
    expect(store2.resolve("/home/user/policy.yaml")).toBe("doc-456");
  });

  it("updates alias when same path is re-registered with different documentId", () => {
    store.register("/home/user/policy.yaml", "doc-old");
    store.register("/home/user/policy.yaml", "doc-new");
    expect(store.resolve("/home/user/policy.yaml")).toBe("doc-new");
  });

  it("supports moving files (old alias removed, new alias added)", () => {
    store.register("/old/path.yaml", "doc-789");
    store.move("/old/path.yaml", "/new/path.yaml");

    expect(store.resolve("/old/path.yaml")).toBeNull();
    expect(store.resolve("/new/path.yaml")).toBe("doc-789");
  });

  it("unregister removes the alias", () => {
    store.register("/home/user/policy.yaml", "doc-abc");
    store.unregister("/home/user/policy.yaml");
    expect(store.resolve("/home/user/policy.yaml")).toBeNull();
  });

  it("clear removes all aliases", () => {
    store.register("/path1.yaml", "doc-1");
    store.register("/path2.yaml", "doc-2");
    store.clear();
    expect(store.resolve("/path1.yaml")).toBeNull();
    expect(store.resolve("/path2.yaml")).toBeNull();
  });

  it("entries returns all registered aliases", () => {
    store.register("/a.yaml", "doc-a");
    store.register("/b.yaml", "doc-b");
    const entries = store.entries();
    expect(entries).toHaveLength(2);
    const ids = entries.map((e) => e.documentId).sort();
    expect(ids).toEqual(["doc-a", "doc-b"]);
  });

  it("handles corrupt localStorage gracefully", () => {
    localStorage.setItem(
      "clawdstrike_document_identity_aliases",
      "not valid json {{",
    );
    const safeStore = new DocumentIdentityStore();
    // Should not throw, should start empty
    expect(safeStore.resolve("/anything")).toBeNull();
  });

  it("handles invalid entries in localStorage gracefully", () => {
    localStorage.setItem(
      "clawdstrike_document_identity_aliases",
      JSON.stringify([{ invalid: true }, { normalizedPath: "/ok", documentId: "d1" }]),
    );
    const safeStore = new DocumentIdentityStore();
    expect(safeStore.resolve("/ok")).toBe("d1");
  });
});
