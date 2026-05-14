import { describe, expect, it } from "vitest";
import { createTestManifest, validateManifest } from "../src/manifest-validation";

describe("sdk validateManifest", () => {
  it("accepts a valid manifest", () => {
    const result = validateManifest(createTestManifest());
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("rejects manifests missing activationEvents", () => {
    const manifest = createTestManifest();
    const { activationEvents, ...withoutActivationEvents } = manifest;
    void activationEvents;

    const result = validateManifest(withoutActivationEvents);

    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.objectContaining({ field: "activationEvents" }),
    );
  });

  it("rejects installation.publisherKey when it is an empty string", () => {
    const manifest = createTestManifest({
      installation: {
        downloadUrl: "https://plugins.clawdstrike.dev/example-1.0.0.tgz",
        size: 4096,
        checksum: "a".repeat(64),
        signature: "signed-manifest",
        publisherKey: "",
      },
    });

    const result = validateManifest(manifest);

    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.objectContaining({ field: "installation.publisherKey" }),
    );
  });
});
