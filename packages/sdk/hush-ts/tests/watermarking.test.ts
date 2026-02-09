import { describe, it, expect } from "vitest";

import { PromptWatermarker, WatermarkExtractor } from "../src/watermarking";

describe("watermarking", () => {
  it("embeds and extracts a verified metadata watermark", async () => {
    const w = await PromptWatermarker.create();
    const payload = w.generatePayload("app", "session");
    const out = await w.watermark("hello", payload);

    const extractor = new WatermarkExtractor({
      trustedPublicKeys: [w.publicKeyHex()],
      allowUnverified: false,
    });
    const r = await extractor.extract(out.watermarked);
    expect(r.found).toBe(true);
    expect(r.verified).toBe(true);
    expect(r.watermark?.payload.applicationId).toBe("app");
    expect(r.watermark?.payload.sessionId).toBe("session");
  });

  it("encodes payload as RFC 8785 canonical JSON bytes", async () => {
    const w = await PromptWatermarker.create({
      // deterministic keys help keep this test stable
      privateKeyHex: "11".repeat(32),
    });

    const out = await w.watermark("hello", {
      applicationId: "app",
      sessionId: "session",
      createdAt: 1,
      sequenceNumber: 2,
    });

    const decoded = new TextDecoder().decode(out.watermark.encodedData);
    expect(decoded).toBe(
      '{"applicationId":"app","createdAt":1,"sequenceNumber":2,"sessionId":"session"}',
    );
  });
});
