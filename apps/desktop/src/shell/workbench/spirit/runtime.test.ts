import { describe, expect, it } from "vitest";
import { createHuntSpiritState, normalizeHuntSpiritState } from "./defaults";
import { deriveHuntSpiritRuntimeState } from "./runtime";

describe("normalizeHuntSpiritState", () => {
  it("returns null when the payload is not bound yet", () => {
    expect(normalizeHuntSpiritState(null)).toBeNull();
    expect(normalizeHuntSpiritState({ thesis: "trace egress" })).toBeNull();
  });

  it("hydrates a bound spirit with defaults", () => {
    const spirit = normalizeHuntSpiritState({
      kind: "forge",
      bindSource: "quick-bind",
      anchorArtifactIds: ["art_1", "art_1", ""],
    });

    expect(spirit).not.toBeNull();
    expect(spirit?.kind).toBe("forge");
    expect(spirit?.liveMood).toBe("attuned");
    expect(spirit?.anchorArtifactIds).toEqual(["art_1"]);
  });
});

describe("deriveHuntSpiritRuntimeState", () => {
  it("returns a dormant runtime when no spirit is bound", () => {
    const runtime = deriveHuntSpiritRuntimeState(null, { currentShell: "hunt" });

    expect(runtime.shouldRender).toBe(false);
    expect(runtime.kind).toBeNull();
    expect(runtime.stance).toBe("idle");
  });

  it("promotes attach mode into an absorb stance", () => {
    const spirit = createHuntSpiritState({
      kind: "forge",
      bindSource: "quick-bind",
      bindReason: "Run-heavy and file-led.",
      confidenceScore: 82,
    });

    const runtime = deriveHuntSpiritRuntimeState(spirit, {
      currentShell: "lab",
      currentLens: "files",
      likelyIntent: "mount",
      isAttachMode: true,
    });

    expect(runtime.kind).toBe("forge");
    expect(runtime.stance).toBe("absorb");
    expect(runtime.shouldRender).toBe(true);
    expect(runtime.emphasis).toContain("files");
    expect(runtime.emphasis).toContain("mount");
  });
});
