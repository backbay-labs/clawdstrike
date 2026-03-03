import { describe, expect, it, vi } from "vitest";
import { createSecurityContext } from "./context.js";
import type { ToolInterceptor } from "./interceptor.js";
import { secureToolSet, wrapExecuteWithInterceptor } from "./secure-tool-wrapper.js";

function createInterceptor(overrides: Partial<ToolInterceptor> = {}): ToolInterceptor {
  return {
    beforeExecute: async () => ({
      proceed: true,
      duration: 0,
      decision: { status: "allow" },
    }),
    afterExecute: async (_toolName, _input, output) => ({
      output,
      modified: false,
    }),
    onError: async () => {},
    ...overrides,
  };
}

describe("wrapExecuteWithInterceptor", () => {
  it("forwards sanitize-modified input when provided", async () => {
    const execute = vi.fn(async (input: string) => `ok:${input}`);
    const interceptor = createInterceptor({
      beforeExecute: async () => ({
        proceed: true,
        duration: 0,
        decision: {
          status: "sanitize",
          reason_code: "ADC_POLICY_SANITIZE",
        },
        modifiedInput: "safe string",
        modifiedParameters: { text: "safe object" },
      }),
    });

    const wrapped = wrapExecuteWithInterceptor(
      "echo",
      execute,
      interceptor,
      createSecurityContext(),
    );

    const result = await wrapped("unsafe string");

    expect(result).toBe("ok:safe string");
    expect(execute).toHaveBeenCalledWith("safe string");
  });

  it("forwards sanitize-modified parameters when modifiedInput is absent", async () => {
    const execute = vi.fn(async (input: { text: string }) => input.text);
    const interceptor = createInterceptor({
      beforeExecute: async () => ({
        proceed: true,
        duration: 0,
        decision: {
          status: "sanitize",
          reason_code: "ADC_POLICY_SANITIZE",
        },
        modifiedParameters: { text: "safe object" },
      }),
    });

    const wrapped = wrapExecuteWithInterceptor(
      "echo",
      execute,
      interceptor,
      createSecurityContext(),
    );

    const result = await wrapped({ text: "unsafe object" });

    expect(result).toBe("safe object");
    expect(execute).toHaveBeenCalledWith({ text: "safe object" });
  });

  it("routes replacement-result afterExecute failures through onError", async () => {
    const execute = vi.fn(async () => "unused");
    const onError = vi.fn(async () => undefined);
    const interceptor = createInterceptor({
      beforeExecute: async () => ({
        proceed: true,
        duration: 0,
        decision: { status: "allow" },
        replacementResult: { ok: true },
      }),
      afterExecute: async () => {
        throw new Error("after failed");
      },
      onError,
    });

    const wrapped = wrapExecuteWithInterceptor(
      "echo",
      execute,
      interceptor,
      createSecurityContext(),
    );

    await expect(wrapped({ text: "input" })).rejects.toThrow("after failed");
    expect(execute).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]?.[0]).toBe("echo");
  });
});

describe("secureToolSet", () => {
  it("wraps execute and call independently when both are present", async () => {
    const interceptor = createInterceptor();
    const tools = {
      dual: {
        execute: vi.fn(async (input: string) => `execute:${input}`),
        call: vi.fn(async (input: string) => `call:${input}`),
      },
    };

    const secured = secureToolSet(tools, interceptor, { framework: "test" });

    await expect(secured.dual.execute!("x")).resolves.toBe("execute:x");
    await expect(secured.dual.call!("y")).resolves.toBe("call:y");
    expect(tools.dual.execute).toHaveBeenCalledWith("x");
    expect(tools.dual.call).toHaveBeenCalledWith("y");
  });

  it("preserves missing execute/call members on wrapped tools", () => {
    const interceptor = createInterceptor();
    const tools = {
      executeOnly: {
        execute: async (_input: string) => "ok",
      },
      callOnly: {
        call: async (_input: string) => "ok",
      },
    };

    const secured = secureToolSet(tools, interceptor, { framework: "test" });

    expect(Object.prototype.hasOwnProperty.call(secured.executeOnly, "call")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(secured.callOnly, "execute")).toBe(false);
  });

  it("preserves prototype methods for class-based tools", async () => {
    class ClassTool {
      prefix = "class-tool";

      async execute(input: string): Promise<string> {
        return `${this.prefix}:${input}`;
      }

      describe(): string {
        return this.prefix;
      }
    }

    const tools = {
      klass: new ClassTool(),
    };
    const secured = secureToolSet(tools, createInterceptor(), { framework: "test" });

    await expect(secured.klass.execute("x")).resolves.toBe("class-tool:x");
    expect(typeof secured.klass.describe).toBe("function");
    expect(secured.klass.describe()).toBe("class-tool");
  });
});
