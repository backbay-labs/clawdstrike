import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { PublicationStore } from "../detection-workflow/publication-store";
import type { PublicationManifest } from "../detection-workflow/shared-types";

function makeManifest(overrides: Partial<PublicationManifest> = {}): PublicationManifest {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-1",
    sourceFileType: "clawdstrike_policy",
    target: "native_policy",
    createdAt: new Date().toISOString(),
    sourceHash: "abc123",
    outputHash: "def456",
    validationSnapshot: { valid: true, diagnosticCount: 0 },
    runSnapshot: null,
    coverageSnapshot: null,
    converter: { id: "identity", version: "1.0.0" },
    signer: null,
    provenance: null,
    ...overrides,
  };
}

describe("PublicationStore", () => {
  let store: PublicationStore;

  beforeEach(async () => {
    store = new PublicationStore();
    await store.init();
  });

  afterEach(() => {
    store.close();
  });

  it("saves and retrieves a manifest", async () => {
    const manifest = makeManifest();
    await store.saveManifest(manifest);
    const retrieved = await store.getManifest(manifest.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(manifest.id);
    expect(retrieved!.sourceHash).toBe("abc123");
  });

  it("returns null for non-existent manifest", async () => {
    const result = await store.getManifest("nonexistent");
    expect(result).toBeNull();
  });

  it("retrieves manifests by documentId in descending order", async () => {
    await store.saveManifest(
      makeManifest({ documentId: "doc-m", createdAt: "2026-03-15T10:00:00.000Z" }),
    );
    const laterManifest = makeManifest({
      documentId: "doc-m",
      createdAt: "2026-03-15T11:00:00.000Z",
    });
    await store.saveManifest(laterManifest);

    const manifests = await store.getManifestsForDocument("doc-m");
    expect(manifests).toHaveLength(2);
    // Most recent first
    expect(manifests[0].id).toBe(laterManifest.id);
  });

  it("gets latest manifest for a document", async () => {
    await store.saveManifest(
      makeManifest({ documentId: "doc-lat", createdAt: "2026-03-15T10:00:00.000Z" }),
    );
    const latest = makeManifest({
      documentId: "doc-lat",
      createdAt: "2026-03-15T12:00:00.000Z",
    });
    await store.saveManifest(latest);

    const result = await store.getLatestManifest("doc-lat");
    expect(result).not.toBeNull();
    expect(result!.id).toBe(latest.id);
  });

  it("deletes a manifest", async () => {
    const manifest = makeManifest();
    await store.saveManifest(manifest);
    await store.deleteManifest(manifest.id);
    const result = await store.getManifest(manifest.id);
    expect(result).toBeNull();
  });

  it("counts manifests per document", async () => {
    await store.saveManifest(makeManifest({ documentId: "doc-cnt" }));
    await store.saveManifest(makeManifest({ documentId: "doc-cnt" }));
    await store.saveManifest(makeManifest({ documentId: "doc-other" }));

    expect(await store.getManifestCount("doc-cnt")).toBe(2);
    expect(await store.getManifestCount("doc-other")).toBe(1);
  });

  it("throws when store not initialized", async () => {
    const uninitStore = new PublicationStore();
    await expect(uninitStore.saveManifest(makeManifest())).rejects.toThrow("not initialized");
  });
});
