import { useEffect } from "react";
import type { ReactNode } from "react";
import type {
  ObservatoryPlayerControllerOptions,
  ObservatoryPlayerIntent,
  ObservatoryPlayerRuntimeApi,
  ObservatoryPlayerState,
  ObservatoryPlayerStepContext,
  ObservatoryPlayerStepResult,
} from "../types";
import { useObservatoryPlayerRuntime } from "./useObservatoryPlayerRuntime";

export interface ObservatoryPlayerControllerProps extends ObservatoryPlayerControllerOptions {
  intent: ObservatoryPlayerIntent;
  stepContext: ObservatoryPlayerStepContext | null;
  enabled?: boolean;
  onStateChange?: (state: ObservatoryPlayerState) => void;
  onStep?: (result: ObservatoryPlayerStepResult) => void;
  children?: (runtime: ObservatoryPlayerRuntimeApi) => ReactNode;
}

export function ObservatoryPlayerController({
  intent,
  stepContext,
  enabled = true,
  onStateChange,
  onStep,
  children,
  ...options
}: ObservatoryPlayerControllerProps) {
  const runtime = useObservatoryPlayerRuntime(options);

  useEffect(() => {
    if (!enabled || !stepContext) return;
    const result = runtime.step(intent, stepContext);
    onStep?.(result);
  }, [enabled, intent, onStep, runtime, stepContext]);

  useEffect(() => {
    onStateChange?.(runtime.state);
  }, [onStateChange, runtime.state]);

  if (!children) return null;
  return <>{children(runtime)}</>;
}
