import type { AdapterConfig } from "./adapter.js";
import { BaseToolInterceptor } from "./base-tool-interceptor.js";
import type { PolicyEngineLike } from "./engine.js";
import type { ToolInterceptor } from "./interceptor.js";

/**
 * Duck-typed interface matching Clawdstrike SDK instances that expose
 * an interceptor factory method.
 */
export interface ClawdstrikeLike {
  createInterceptor?: (
    config?: AdapterConfig,
  ) => Partial<ToolInterceptor> | ToolInterceptor;
}

/**
 * Union of every accepted security source type.
 *
 * Adapters accept any of:
 * - A `ClawdstrikeLike` instance (SDK object with `createInterceptor`)
 * - A raw `PolicyEngineLike` engine
 * - A pre-built `ToolInterceptor`
 */
export type SecuritySource = ClawdstrikeLike | PolicyEngineLike | ToolInterceptor;

/**
 * Resolve a {@link SecuritySource} into a concrete {@link ToolInterceptor}.
 *
 * Resolution order:
 * 1. Already a `ToolInterceptor` → return as-is or apply config via `withConfig`
 * 2. `ClawdstrikeLike` with `createInterceptor` → call it
 * 3. `PolicyEngineLike` → wrap in a new `BaseToolInterceptor`
 */
export function resolveInterceptor(
  source: SecuritySource,
  config?: AdapterConfig,
): ToolInterceptor {
  if (isClawdstrikeLike(source) && config !== undefined) {
    const interceptor = source.createInterceptor?.(config);
    if (!interceptor) {
      throw new Error("ClawdstrikeLike source must provide createInterceptor()");
    }
    return withDefaultOnError(interceptor);
  }
  if (isToolInterceptor(source)) {
    return withAdapterConfig(source, config);
  }
  if (isClawdstrikeLike(source)) {
    const interceptor = source.createInterceptor?.();
    if (!interceptor) {
      throw new Error("ClawdstrikeLike source must provide createInterceptor()");
    }
    return withDefaultOnError(interceptor);
  }
  return new BaseToolInterceptor(source as PolicyEngineLike, config ?? {});
}

type ConfigurableToolInterceptor = ToolInterceptor & {
  withConfig(config: AdapterConfig): ToolInterceptor;
};

function withAdapterConfig(source: ToolInterceptor, config?: AdapterConfig): ToolInterceptor {
  if (config === undefined) {
    return source;
  }

  if (isConfigurableToolInterceptor(source)) {
    return source.withConfig(config);
  }

  if (config.translateToolCall !== undefined || config.broker !== undefined) {
    throw new Error(
      "ToolInterceptor source does not support adapter translator config or broker config. " +
        "Use a PolicyEngineLike/ClawdstrikeLike source or a configurable interceptor.",
    );
  }

  return source;
}

function withDefaultOnError(interceptor: Partial<ToolInterceptor>): ToolInterceptor {
  if (
    typeof interceptor.beforeExecute !== "function" ||
    typeof interceptor.afterExecute !== "function"
  ) {
    throw new Error(
      "createInterceptor() must return an object with beforeExecute and afterExecute methods",
    );
  }

  return {
    beforeExecute: interceptor.beforeExecute,
    afterExecute: interceptor.afterExecute,
    onError:
      typeof interceptor.onError === "function"
        ? interceptor.onError
        : async () => undefined,
  };
}

export function isToolInterceptor(value: unknown): value is ToolInterceptor {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as ToolInterceptor).beforeExecute === "function" &&
    typeof (value as ToolInterceptor).afterExecute === "function" &&
    typeof (value as ToolInterceptor).onError === "function"
  );
}

export function isClawdstrikeLike(value: unknown): value is ClawdstrikeLike {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as ClawdstrikeLike).createInterceptor === "function"
  );
}

function isConfigurableToolInterceptor(value: ToolInterceptor): value is ConfigurableToolInterceptor {
  return (
    value instanceof BaseToolInterceptor ||
    typeof (value as Partial<ConfigurableToolInterceptor>).withConfig === "function"
  );
}
