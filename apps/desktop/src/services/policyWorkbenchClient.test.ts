import { beforeEach, describe, expect, it, vi } from "vitest";

const validatePolicyMock = vi.fn();

vi.mock("./hushdClient", () => {
  class MockHushdClient {
    constructor(_baseUrl: string) {}

    validatePolicy = validatePolicyMock;
    getPolicy = vi.fn();
    eval = vi.fn();
    updatePolicy = vi.fn();
  }

  return {
    HushdClient: MockHushdClient,
  };
});

vi.mock("./tauri", () => ({
  isTauri: vi.fn(() => false),
  policyEvalEvent: vi.fn(),
  policyLoad: vi.fn(),
  policySave: vi.fn(),
  policyValidate: vi.fn(),
}));

import { PolicyWorkbenchClient, PolicyWorkbenchClientError } from "./policyWorkbenchClient";

describe("PolicyWorkbenchClient", () => {
  beforeEach(() => {
    validatePolicyMock.mockReset();
  });

  it("preserves warning code metadata from daemon validation", async () => {
    validatePolicyMock.mockResolvedValue({
      valid: true,
      errors: [],
      warnings: [
        {
          path: "guards.forbidden_path",
          code: "policy_deprecated_field",
          message: "deprecated field",
        },
      ],
      normalized_version: "1.2.0",
    });

    const client = new PolicyWorkbenchClient("http://localhost:9876");
    const result = await client.validatePolicy('version: "1.2.0"');

    expect(result.warnings).toEqual([
      {
        path: "guards.forbidden_path",
        code: "policy_deprecated_field",
        message: "deprecated field",
      },
    ]);
    expect(result.normalized_version).toBe("1.2.0");
  });

  it("falls back to policy_warning when warning code is absent", async () => {
    validatePolicyMock.mockResolvedValue({
      valid: true,
      errors: [],
      warnings: [
        {
          path: "guards",
          message: "warning without code",
        },
      ],
    });

    const client = new PolicyWorkbenchClient("http://localhost:9876");
    const result = await client.validatePolicy('version: "1.2.0"');

    expect(result.warnings[0]?.code).toBe("policy_warning");
  });

  it("classifies unsupported event type failures as policy_eval_invalid_event", async () => {
    validatePolicyMock.mockRejectedValue(new Error("unsupported eventType: launch_missiles"));

    const client = new PolicyWorkbenchClient("http://localhost:9876");

    await expect(client.validatePolicy('version: "1.2.0"')).rejects.toMatchObject({
      code: "policy_eval_invalid_event",
    } satisfies Partial<PolicyWorkbenchClientError>);
  });

  it("does not classify generic eventType mentions as invalid-event errors", async () => {
    validatePolicyMock.mockRejectedValue(
      new Error("request failed: eventType metadata unavailable"),
    );

    const client = new PolicyWorkbenchClient("http://localhost:9876");

    await expect(client.validatePolicy('version: "1.2.0"')).rejects.toMatchObject({
      code: "policy_request_failed",
    } satisfies Partial<PolicyWorkbenchClientError>);
  });
});
