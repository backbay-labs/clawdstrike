import { describe, expect, it } from "vitest";
import type { Decision, PolicyEngineLike } from "@clawdstrike/adapter-core";
import { ClawdstrikeBlockedError } from "@clawdstrike/adapter-core";
import { secureTools } from "./secure-tools.js";

describe("secureTools (OpenCode)", () => {
  it("blocks denied tool calls", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async (): Promise<Decision> => ({
        status: "deny",
        reason_code: "TEST_DENY",
        guard: "mock",
        message: "denied",
      }),
    };

    const tools = {
      bash: { execute: async (input: { command: string }) => input.command },
    };

    const secured = secureTools(tools, engine);
    await expect(secured.bash.execute({ command: "rm -rf /" })).rejects.toThrow(ClawdstrikeBlockedError);
  });

  it("wraps call() so it cannot bypass security", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async (): Promise<Decision> => ({
        status: "deny",
        reason_code: "TEST_DENY",
        guard: "mock",
        message: "denied",
      }),
    };

    const tools = {
      bash: { call: async (input: { command: string }) => input.command },
    };

    const secured = secureTools(tools, engine);
    await expect(secured.bash.call!({ command: "rm -rf /" })).rejects.toThrow(ClawdstrikeBlockedError);
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

  it("allows permitted tool calls", async () => {
    const engine: PolicyEngineLike = {
      evaluate: async () => ({ status: "allow" as const }),
    };

    const tools = {
      echo: { execute: async (input: { text: string }) => input.text },
    };

    const secured = secureTools(tools, engine);
    const result = await secured.echo.execute({ text: "hello" });
    expect(result).toBe("hello");
  });
});
