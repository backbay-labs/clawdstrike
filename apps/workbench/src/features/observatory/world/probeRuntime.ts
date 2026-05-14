// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/world/probeRuntime.ts
// Pure state machine functions for probe lifecycle: ready → active (5200ms) → cooldown (3600ms) → ready.
// No external imports except HuntStationId type.

import type { HuntStationId } from "./types";

export const OBSERVATORY_PROBE_ACTIVE_MS = 5200;
export const OBSERVATORY_PROBE_COOLDOWN_MS = 3600;

export type ObservatoryProbeStatus = "ready" | "active" | "cooldown";

export interface ObservatoryProbeState {
  status: ObservatoryProbeStatus;
  targetStationId: HuntStationId | null;
  activeUntilMs: number | null;
  cooldownUntilMs: number | null;
}

export function createInitialObservatoryProbeState(): ObservatoryProbeState {
  return {
    status: "ready",
    targetStationId: null,
    activeUntilMs: null,
    cooldownUntilMs: null,
  };
}

export function advanceObservatoryProbeState(
  state: ObservatoryProbeState,
  nowMs: number,
): ObservatoryProbeState {
  if (state.status === "active" && state.activeUntilMs != null && nowMs >= state.activeUntilMs) {
    return {
      ...state,
      status: nowMs >= (state.cooldownUntilMs ?? state.activeUntilMs) ? "ready" : "cooldown",
      activeUntilMs: null,
      cooldownUntilMs:
        nowMs >= (state.cooldownUntilMs ?? state.activeUntilMs) ? null : state.cooldownUntilMs,
      targetStationId: nowMs >= (state.cooldownUntilMs ?? state.activeUntilMs)
        ? null
        : state.targetStationId,
    };
  }

  if (state.status === "cooldown" && state.cooldownUntilMs != null && nowMs >= state.cooldownUntilMs) {
    return createInitialObservatoryProbeState();
  }

  return state;
}

export function canDispatchObservatoryProbe(
  state: ObservatoryProbeState,
  nowMs: number,
): boolean {
  return advanceObservatoryProbeState(state, nowMs).status === "ready";
}

export function dispatchObservatoryProbe(
  state: ObservatoryProbeState,
  targetStationId: HuntStationId | null,
  nowMs: number,
): ObservatoryProbeState {
  const resolved = advanceObservatoryProbeState(state, nowMs);
  if (!targetStationId || resolved.status !== "ready") {
    return resolved;
  }

  return {
    status: "active",
    targetStationId,
    activeUntilMs: nowMs + OBSERVATORY_PROBE_ACTIVE_MS,
    cooldownUntilMs: nowMs + OBSERVATORY_PROBE_ACTIVE_MS + OBSERVATORY_PROBE_COOLDOWN_MS,
  };
}

export function getObservatoryProbeCharge(
  state: ObservatoryProbeState,
  nowMs: number,
): number {
  const resolved = advanceObservatoryProbeState(state, nowMs);
  if (resolved.status === "ready") {
    return 1;
  }
  if (resolved.status === "active") {
    return 0;
  }
  if (resolved.cooldownUntilMs == null) {
    return 0;
  }
  const cooldownStartedAtMs = resolved.cooldownUntilMs - OBSERVATORY_PROBE_COOLDOWN_MS;
  const progress = (nowMs - cooldownStartedAtMs) / OBSERVATORY_PROBE_COOLDOWN_MS;
  return Math.min(1, Math.max(0, progress));
}

export function getObservatoryProbeRemainingMs(
  state: ObservatoryProbeState,
  nowMs: number,
): number {
  const resolved = advanceObservatoryProbeState(state, nowMs);
  if (resolved.status === "active" && resolved.activeUntilMs != null) {
    return Math.max(0, resolved.activeUntilMs - nowMs);
  }
  if (resolved.status === "cooldown" && resolved.cooldownUntilMs != null) {
    return Math.max(0, resolved.cooldownUntilMs - nowMs);
  }
  return 0;
}
