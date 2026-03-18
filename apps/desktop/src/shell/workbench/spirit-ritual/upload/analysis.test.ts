import { describe, expect, it } from "vitest";
import { analyzeSpiritUploadDraft, createExternalUploadItem } from "./analysis";
import type { SpiritRitualUploadDraft } from "../state/types";

describe("analyzeSpiritUploadDraft", () => {
  it("prefers lantern when receipt and evidence anchors dominate the selection", () => {
    const draft: SpiritRitualUploadDraft = {
      items: [
        {
          id: "artifact:receipt",
          kind: "artifact-anchor",
          label: "Guard receipt",
          artifactId: "art_receipt",
          artifactKind: "receipt",
          semanticHints: ["evidence", "cite"],
          mimeType: null,
          extension: "pdf",
          byteSize: null,
        },
        {
          id: "artifact:evidence",
          kind: "artifact-anchor",
          label: "Memory fragment",
          artifactId: "art_evidence",
          artifactKind: "evidence",
          semanticHints: ["evidence"],
          mimeType: null,
          extension: "bin",
          byteSize: null,
        },
      ],
      selectedItemIds: ["artifact:receipt", "artifact:evidence"],
      preferredAnchorIds: ["art_receipt", "art_evidence"],
    };

    const analysis = analyzeSpiritUploadDraft(draft);

    expect(analysis.scoredKinds[0]?.kind).toBe("lantern");
    expect(analysis.anchorArtifactIds).toEqual(["art_receipt", "art_evidence"]);
    expect(analysis.focusSurfaces).toContain("Evidence");
  });

  it("infers a usable file-like anchor from an external upload", () => {
    const item = createExternalUploadItem({
      label: "payload.bin",
      mimeType: "application/octet-stream",
    });

    expect(item.kind).toBe("external-file");
    expect(item.artifactKind).toBe("file");
  });
});

