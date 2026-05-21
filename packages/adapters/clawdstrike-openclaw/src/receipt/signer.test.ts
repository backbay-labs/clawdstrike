import { describe, expect, it } from "vitest";

import { ReceiptSigner } from "./signer.js";
import type { Decision, PolicyEvent } from "../types.js";

const decision: Decision = {
  status: "allow",
  reason: "allowed",
};

const event: PolicyEvent = {
  eventId: "receipt-signer-test",
  eventType: "tool_call",
  timestamp: "2026-05-21T00:00:00.000Z",
  data: {
    type: "tool",
    toolName: "read_file",
    parameters: { path: "/tmp/example.txt" },
  },
};

describe("ReceiptSigner", () => {
  it("fails closed when signed receipts are requested without a signing bridge", () => {
    const signer = new ReceiptSigner({ sign: true });

    expect(() => signer.createReceipt(decision, event, "policy-hash")).toThrow(
      /signed receipts require/i,
    );
  });
});
