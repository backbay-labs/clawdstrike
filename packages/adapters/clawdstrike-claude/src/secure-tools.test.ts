import { describe, expect, it } from "vitest";
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

describe("secureTools (Claude)", () => {
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

  it("translates Claude CUA actions into canonical CUA events", async () => {
    const engine = createDenyEngine("input.inject");
    const tools = {
      computer: {
        execute: async () => "done",
      },
    };

    const secured = secureTools(tools, engine);

    await expect(
      secured.computer.execute({
        action: "mouse_click",
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
      computer: {
        execute: async () => "done",
      },
    };

    const secured = secureTools(tools, engine);

    await expect(
      secured.computer.execute({
        action: "mystery_action",
        sessionId: "sess-1",
      } as never),
    ).rejects.toThrow();
  });
});
