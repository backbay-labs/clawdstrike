import { describe, expect, it, vi } from "vitest";

import {
  BrokerPreviewApprovalRequiredError,
  SecretBrokerClient,
  sha256Hex,
} from "./client.js";

describe("SecretBrokerClient", () => {
  it("issues a capability and executes through brokerd", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            preview: {
              preview_id: "preview-123",
              provider: "openai",
              operation: "responses.create",
              summary: "Run OpenAI responses.create against gpt-4.1-mini",
              created_at: new Date().toISOString(),
              risk_level: "medium",
              data_classes: ["llm_prompt"],
              resources: [{ kind: "model", value: "gpt-4.1-mini" }],
              egress_host: "api.openai.com",
              approval_required: false,
              approval_state: "not_required",
            },
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            capability: "signed-capability",
            capability_id: "cap-123",
            expires_at: new Date().toISOString(),
            policy_hash: "hash-123",
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            execution_id: "exec-123",
            capability_id: "cap-123",
            provider: "openai",
            status: 200,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ id: "resp_123" }),
            content_type: "application/json",
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      );

    const client = new SecretBrokerClient({
      hushdBaseUrl: "http://hushd.test",
      brokerdBaseUrl: "http://brokerd.test",
      proofBindingMode: "loopback",
      fetchImpl,
    });

    const result = await client.execute({
      provider: "openai",
      secretRef: "openai/dev",
      request: {
        url: "https://api.openai.com/v1/responses",
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{\"model\":\"gpt-4.1-mini\"}",
        bodySha256: sha256Hex("{\"model\":\"gpt-4.1-mini\"}"),
      },
      sessionId: "sess-1",
    });

    expect(result.capabilityId).toBe("cap-123");
    expect(result.executionId).toBe("exec-123");
    expect(result.provider).toBe("openai");
    expect(result.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(3);

    const previewBody = JSON.parse(String(fetchImpl.mock.calls[0]?.[1]?.body));
    expect(previewBody.secret_ref).toBe("openai/dev");
    const capabilityBody = JSON.parse(String(fetchImpl.mock.calls[1]?.[1]?.body));
    expect(capabilityBody.secret_ref).toBe("openai/dev");
    expect(capabilityBody.proof_binding.mode).toBe("loopback");
    expect(capabilityBody.preview_id).toBe("preview-123");

    const executeBody = JSON.parse(String(fetchImpl.mock.calls[2]?.[1]?.body));
    expect(executeBody.capability).toBe("signed-capability");
    expect(typeof executeBody.binding_secret).toBe("string");
    expect(sha256Hex(executeBody.binding_secret)).toBe(capabilityBody.proof_binding.binding_sha256);
  });

  it("uses a DPoP-like proof for non-loopback brokerd targets", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            preview: {
              preview_id: "preview-dpop",
              provider: "openai",
              operation: "responses.create",
              summary: "Run OpenAI responses.create",
              created_at: new Date().toISOString(),
              risk_level: "medium",
              egress_host: "api.openai.com",
              approval_required: false,
              approval_state: "not_required",
            },
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            capability: "signed-capability",
            capability_id: "cap-dpop",
            expires_at: new Date().toISOString(),
            policy_hash: "hash-dpop",
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            execution_id: "exec-dpop",
            capability_id: "cap-dpop",
            provider: "openai",
            status: 200,
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      );

    const client = new SecretBrokerClient({
      hushdBaseUrl: "http://hushd.test",
      brokerdBaseUrl: "https://brokerd.example",
      fetchImpl,
    });

    await client.execute({
      provider: "openai",
      secretRef: "openai/prod",
      request: {
        url: "https://api.openai.com/v1/responses",
        method: "POST",
        body: "{\"model\":\"gpt-4.1-mini\"}",
        bodySha256: sha256Hex("{\"model\":\"gpt-4.1-mini\"}"),
      },
    });

    const capabilityBody = JSON.parse(String(fetchImpl.mock.calls[0]?.[1]?.body));
    expect(capabilityBody.preview_id).toBeUndefined();
    const capabilityIssueBody = JSON.parse(String(fetchImpl.mock.calls[1]?.[1]?.body));
    expect(capabilityIssueBody.preview_id).toBe("preview-dpop");
    expect(capabilityIssueBody.proof_binding.mode).toBe("dpop");
    expect(typeof capabilityIssueBody.proof_binding.key_thumbprint).toBe("string");

    const executeBody = JSON.parse(String(fetchImpl.mock.calls[2]?.[1]?.body));
    expect(executeBody.binding_secret).toBeUndefined();
    expect(executeBody.binding_proof.mode).toBe("dpop");
    expect(sha256Hex(executeBody.binding_proof.public_key)).toBe(
      capabilityIssueBody.proof_binding.key_thumbprint,
    );
    expect(typeof executeBody.binding_proof.signature).toBe("string");
    expect(typeof executeBody.binding_proof.nonce).toBe("string");
  });

  it("fails closed when hushd rejects capability issuance", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ error: { code: "BROKER_DENY" } }), {
        status: 403,
        headers: { "content-type": "application/json" },
      }),
    );

    const client = new SecretBrokerClient({
      hushdBaseUrl: "http://hushd.test",
      brokerdBaseUrl: "http://brokerd.test",
      previewBeforeExecute: false,
      fetchImpl,
    });

    await expect(
      client.execute({
        provider: "openai",
        secretRef: "openai/dev",
        request: {
          url: "https://api.openai.com/v1/responses",
          method: "POST",
        },
      }),
    ).rejects.toThrow("BROKER_CAPABILITY_REQUEST_FAILED");
  });

  it("raises a preview-approval error when hushd marks the intent as pending approval", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          preview: {
            preview_id: "preview-pending",
            provider: "openai",
            operation: "responses.create",
            summary: "Run OpenAI responses.create",
            created_at: new Date().toISOString(),
            risk_level: "high",
            egress_host: "api.openai.com",
            approval_required: true,
            approval_state: "pending",
          },
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      ),
    );

    const client = new SecretBrokerClient({
      hushdBaseUrl: "http://hushd.test",
      brokerdBaseUrl: "http://brokerd.test",
      fetchImpl,
    });

    await expect(
      client.execute({
        provider: "openai",
        secretRef: "openai/dev",
        request: {
          url: "https://api.openai.com/v1/responses",
          method: "POST",
        },
      }),
    ).rejects.toBeInstanceOf(BrokerPreviewApprovalRequiredError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("issues a capability and executes a streamed broker response", async () => {
    const streamBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("data: hello\n\n"));
        controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
        controller.close();
      },
    });
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            preview: {
              preview_id: "preview-stream",
              provider: "openai",
              operation: "responses.create",
              summary: "Run OpenAI responses.create",
              created_at: new Date().toISOString(),
              risk_level: "medium",
              egress_host: "api.openai.com",
              approval_required: false,
              approval_state: "not_required",
            },
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            capability: "signed-capability",
            capability_id: "cap-stream",
            expires_at: new Date().toISOString(),
            policy_hash: "hash-stream",
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(streamBody, {
          status: 200,
          headers: {
            "content-type": "text/event-stream",
            "x-clawdstrike-execution-id": "exec-stream",
            "x-clawdstrike-capability-id": "cap-stream",
            "x-clawdstrike-provider": "openai",
          },
        }),
      );

    const client = new SecretBrokerClient({
      hushdBaseUrl: "http://hushd.test",
      brokerdBaseUrl: "http://brokerd.test",
      proofBindingMode: "loopback",
      fetchImpl,
    });

    const result = await client.executeStream({
      provider: "openai",
      secretRef: "openai/dev",
      request: {
        url: "https://api.openai.com/v1/responses",
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{\"model\":\"gpt-4.1-mini\",\"stream\":true}",
        bodySha256: sha256Hex("{\"model\":\"gpt-4.1-mini\",\"stream\":true}"),
      },
    });

    expect(result.executionId).toBe("exec-stream");
    expect(result.capabilityId).toBe("cap-stream");
    expect(result.contentType).toBe("text/event-stream");
    expect(await readStreamAsText(result.body)).toContain("[DONE]");
  });
});

async function readStreamAsText(stream: ReadableStream<Uint8Array>): Promise<string> {
  return await new Response(stream).text();
}
