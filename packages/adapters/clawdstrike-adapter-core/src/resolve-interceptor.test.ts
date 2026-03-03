import { describe, expect, it, vi } from "vitest";

import type { AdapterConfig, ToolCallTranslationInput } from "./adapter.js";
import { BaseToolInterceptor } from "./base-tool-interceptor.js";
import { createSecurityContext } from "./context.js";
import { resolveInterceptor } from "./resolve-interceptor.js";

describe("resolveInterceptor", () => {
  it("returns ToolInterceptor inputs unchanged", () => {
    const interceptor = {
      beforeExecute: vi.fn(async () => ({
        proceed: true,
        decision: { status: "allow" as const },
        duration: 0,
      })),
      afterExecute: vi.fn(async (_tool, _input, output) => ({ output, modified: false })),
      onError: vi.fn(async () => undefined),
    };

    expect(resolveInterceptor(interceptor)).toBe(interceptor);
  });

  it("fails closed when translator config is provided for non-configurable ToolInterceptor sources", () => {
    const interceptor = {
      beforeExecute: vi.fn(async () => ({
        proceed: true,
        decision: { status: "allow" as const },
        duration: 0,
      })),
      afterExecute: vi.fn(async (_tool, _input, output) => ({ output, modified: false })),
      onError: vi.fn(async () => undefined),
    };

    expect(() =>
      resolveInterceptor(interceptor, {
        translateToolCall: vi.fn(() => null),
      }),
    ).toThrow(/does not support adapter translator config/);
  });

  it("applies config via withConfig for configurable ToolInterceptor sources", async () => {
    const engine = {
      evaluate: vi.fn(async () => ({ status: "allow" as const })),
    };
    const base = new BaseToolInterceptor(engine, {});
    const withConfig = vi.fn((config: AdapterConfig) => base.withConfig(config));
    const interceptor = {
      beforeExecute: base.beforeExecute.bind(base),
      afterExecute: base.afterExecute.bind(base),
      onError: base.onError.bind(base),
      withConfig,
    };
    const translateToolCall = vi.fn((input: ToolCallTranslationInput) => ({
      eventId: "evt-1",
      eventType: "remote.session.connect" as const,
      timestamp: "2025-01-01T00:00:00.000Z",
      sessionId: input.sessionId,
      data: {
        type: "cua" as const,
        cuaAction: "navigate",
      },
      metadata: { source: "test" },
    }));

    const resolved = resolveInterceptor(interceptor, { translateToolCall });

    await resolved.beforeExecute(
      "computer_use",
      { action: "navigate" },
      createSecurityContext({
        sessionId: "sess-1",
        metadata: { framework: "openai" },
      }),
    );

    expect(withConfig).toHaveBeenCalled();
    expect(translateToolCall).toHaveBeenCalled();
    expect(engine.evaluate).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: "remote.session.connect",
      }),
    );
  });

  it("passes AdapterConfig through to ClawdstrikeLike.createInterceptor", () => {
    const config: AdapterConfig = {
      translateToolCall: vi.fn(() => null),
    };

    const created = {
      beforeExecute: vi.fn(async () => ({
        proceed: true,
        decision: { status: "allow" as const },
        duration: 0,
      })),
      afterExecute: vi.fn(async (_tool, _input, output) => ({ output, modified: false })),
      onError: vi.fn(async () => undefined),
    };
    const createInterceptor = vi.fn(() => created);

    const resolved = resolveInterceptor({ createInterceptor }, config);
    expect(resolved.beforeExecute).toBe(created.beforeExecute);
    expect(resolved.afterExecute).toBe(created.afterExecute);
    expect(resolved.onError).toBe(created.onError);
    expect(createInterceptor).toHaveBeenCalledWith(config);
  });

  it("prefers createInterceptor(config) when source is both ToolInterceptor and ClawdstrikeLike", () => {
    const config: AdapterConfig = {
      translateToolCall: vi.fn(() => null),
    };

    const fallbackInterceptor = {
      beforeExecute: vi.fn(async () => ({
        proceed: true,
        decision: { status: "allow" as const },
        duration: 0,
      })),
      afterExecute: vi.fn(async (_tool, _input, output) => ({ output, modified: false })),
      onError: vi.fn(async () => undefined),
    };
    const created = {
      beforeExecute: vi.fn(async () => ({
        proceed: true,
        decision: { status: "allow" as const },
        duration: 0,
      })),
      afterExecute: vi.fn(async (_tool, _input, output) => ({ output, modified: false })),
      onError: vi.fn(async () => undefined),
    };
    const createInterceptor = vi.fn(() => created);

    const dualSource = {
      ...fallbackInterceptor,
      createInterceptor,
    };

    const resolved = resolveInterceptor(dualSource, config);
    expect(createInterceptor).toHaveBeenCalledWith(config);
    expect(resolved.beforeExecute).toBe(created.beforeExecute);
    expect(resolved.afterExecute).toBe(created.afterExecute);
    expect(resolved.onError).toBe(created.onError);
  });

  it("adds a no-op onError for legacy createInterceptor outputs", async () => {
    const resolved = resolveInterceptor({
      createInterceptor: () => ({
        beforeExecute: async () => ({
          proceed: true,
          decision: { status: "allow" as const },
          duration: 0,
        }),
        afterExecute: async (_tool, _input, output) => ({ output, modified: false }),
      }),
    });

    await expect(resolved.onError("tool", {}, new Error("x"), {} as never)).resolves.toBeUndefined();
  });

  it("wraps PolicyEngineLike inputs in BaseToolInterceptor", () => {
    const engine = {
      evaluate: vi.fn(async () => ({ status: "allow" as const })),
    };

    const resolved = resolveInterceptor(engine);
    expect(resolved).toBeInstanceOf(BaseToolInterceptor);
  });

  it("reconfigures BaseToolInterceptor sources when AdapterConfig is provided", async () => {
    const engine = {
      evaluate: vi.fn(async () => ({ status: "allow" as const })),
    };

    const base = new BaseToolInterceptor(engine, {});
    const translateToolCall = vi.fn((input: ToolCallTranslationInput) => ({
      eventId: "evt-1",
      eventType: "remote.session.connect" as const,
      timestamp: "2025-01-01T00:00:00.000Z",
      sessionId: input.sessionId,
      data: {
        type: "cua" as const,
        cuaAction: "navigate",
      },
      metadata: { source: "test" },
    }));

    const resolved = resolveInterceptor(base, { translateToolCall });
    expect(resolved).toBeInstanceOf(BaseToolInterceptor);
    expect(resolved).not.toBe(base);

    await resolved.beforeExecute(
      "computer_use",
      { action: "navigate" },
      createSecurityContext({
        sessionId: "sess-1",
        metadata: { framework: "openai" },
      }),
    );

    expect(translateToolCall).toHaveBeenCalled();
    expect(engine.evaluate).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: "remote.session.connect",
      }),
    );
  });
});
