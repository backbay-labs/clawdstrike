import { describe, expect, it, vi } from "vitest";
import type { Decision, PolicyEngineLike, PolicyEvent } from "@clawdstrike/adapter-core";
import { ClawdstrikeBlockedError } from "@clawdstrike/adapter-core";
import { secureTools } from "./secure-tools.js";

function createDenyEngine(denyEventType: string): PolicyEngineLike {
  return {
    evaluate: async (event: PolicyEvent): Promise<Decision> => {
      if (event.eventType === denyEventType) {
        return {
          status: "deny",
          reason_code: "TEST_DENY",
          guard: "mock",
          message: `${denyEventType} denied`,
        };
      }
      return { status: "allow" };
    },
  };
}

describe("secureTools (OpenAI)", () => {
  it("blocks denied tool calls", async () => {
    const engine = createDenyEngine("command_exec");
    const tools = {
      bash: {
        execute: async (input: { command: string }) => input.command,
      },
    };

    const secured = secureTools(tools, engine);

    await expect(secured.bash.execute({ command: "rm -rf /" })).rejects.toThrow(
      ClawdstrikeBlockedError,
    );
  });

  it("allows permitted tool calls", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async () => ({ status: "allow" as const }),
    };

    const tools = {
      echo: {
        execute: async (input: { text: string }) => input.text,
      },
    };

    const secured = secureTools(tools, engine);
    const result = await secured.echo.execute({ text: "hello" });
    expect(result).toBe("hello");
  });

  it("translates OpenAI CUA actions into canonical CUA events", async () => {
    const engine = createDenyEngine("input.inject");
    const tools = {
      computer_use: {
        execute: async () => "done",
      },
    };

    const secured = secureTools(tools, engine);

    await expect(
      secured.computer_use.execute({
        action: "click",
        sessionId: "sess-1",
        x: 100,
        y: 200,
      } as never),
    ).rejects.toThrow(ClawdstrikeBlockedError);
  });

  it("wraps call() so it cannot bypass security", async () => {
    const engine = createDenyEngine("command_exec");
    const tools = {
      bash: {
        call: async (input: { command: string }) => input.command,
      },
    };

    const secured = secureTools(tools, engine);

    // call() should be wrapped with the same security interceptor
    await expect(secured.bash.call!({ command: "rm -rf /" })).rejects.toThrow(
      ClawdstrikeBlockedError,
    );
  });

  it("preserves this binding for tool methods", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async () => ({ status: "allow" as const }),
    };

    class StatefulTool {
      private prefix = "output:";
      async execute(input: { text: string }) {
        return this.prefix + input.text;
      }
    }

    const tools = { stateful: new StatefulTool() as { execute: (input: { text: string }) => Promise<string> } };
    const secured = secureTools(tools, engine);

    const result = await secured.stateful.execute({ text: "hello" });
    expect(result).toBe("output:hello");
  });

  it("fails closed when translator sees unknown CUA action", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async () => ({ status: "allow" as const }),
    };
    const tools = {
      computer_use: {
        execute: async () => "done",
      },
    };

    const secured = secureTools(tools, engine);

    await expect(
      secured.computer_use.execute({
        action: "mystery_action",
        sessionId: "sess-1",
      } as never),
    ).rejects.toThrow();
  });

  it("uses broker mode for responses.create without calling the direct tool", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async () => ({ status: "allow" as const }),
    };
    const directExecute = vi.fn(async () => ({ direct: true }));
    const client = {
      execute: vi.fn(async () => ({
        executionId: "exec-123",
        capabilityId: "cap-123",
        provider: "openai" as const,
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: "resp_123", output_text: "brokered" }),
        contentType: "application/json",
      })),
    };

    const secured = secureTools(
      {
        "responses.create": {
          execute: directExecute,
        },
      },
      engine,
      {
        broker: {
          client,
          secretRef: "openai/dev",
        },
      },
    );

    const result = await secured["responses.create"].execute({
      body: { model: "gpt-4.1-mini", input: "hello" },
    });

    expect(result).toEqual({ id: "resp_123", output_text: "brokered" });
    expect(directExecute).not.toHaveBeenCalled();
    expect(client.execute).toHaveBeenCalledOnce();
  });

  it("uses broker stream mode for responses.create when stream=true", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async () => ({ status: "allow" as const }),
    };
    const directExecute = vi.fn(async () => ({ direct: true }));
    const brokeredStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("data: hello\n\n"));
        controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
        controller.close();
      },
    });
    const client = {
      execute: vi.fn(async () => ({
        executionId: "exec-123",
        capabilityId: "cap-123",
        provider: "openai" as const,
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: "resp_123", output_text: "brokered" }),
        contentType: "application/json",
      })),
      executeStream: vi.fn(async () => ({
        executionId: "exec-stream",
        capabilityId: "cap-stream",
        provider: "openai" as const,
        status: 200,
        headers: { "content-type": "text/event-stream" },
        body: brokeredStream,
        contentType: "text/event-stream",
      })),
    };

    const secured = secureTools(
      {
        "responses.create": {
          execute: directExecute,
        },
      },
      engine,
      {
        broker: {
          client,
          secretRef: "openai/dev",
        },
      },
    );

    const result = await secured["responses.create"].execute({
      body: { model: "gpt-4.1-mini", input: "hello", stream: true },
    });

    expect(await readStreamAsText(result as ReadableStream<Uint8Array>)).toContain("[DONE]");
    expect(directExecute).not.toHaveBeenCalled();
    expect(client.execute).not.toHaveBeenCalled();
    expect(client.executeStream).toHaveBeenCalledOnce();
  });
});

async function readStreamAsText(stream: ReadableStream<Uint8Array>): Promise<string> {
  return await new Response(stream).text();
}
