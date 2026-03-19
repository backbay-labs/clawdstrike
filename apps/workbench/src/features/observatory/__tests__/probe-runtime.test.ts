import { describe, expect, it } from "vitest";
import {
  advanceObservatoryProbeState,
  canDispatchObservatoryProbe,
  createInitialObservatoryProbeState,
  dispatchObservatoryProbe,
  getObservatoryProbeCharge,
  getObservatoryProbeRemainingMs,
  OBSERVATORY_PROBE_ACTIVE_MS,
  OBSERVATORY_PROBE_COOLDOWN_MS,
} from "@/features/observatory/world/probeRuntime";

describe("observatory probe runtime", () => {
  it("createInitialObservatoryProbeState returns status ready with null targetStationId", () => {
    const state = createInitialObservatoryProbeState();
    expect(state.status).toBe("ready");
    expect(state.targetStationId).toBeNull();
  });

  it("dispatchObservatoryProbe sets status active with correct activeUntilMs", () => {
    const start = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(start, "signal", 0);
    expect(active.status).toBe("active");
    expect(active.targetStationId).toBe("signal");
    expect(active.activeUntilMs).toBe(OBSERVATORY_PROBE_ACTIVE_MS);
  });

  it("advanceObservatoryProbeState transitions active to cooldown after activeUntilMs", () => {
    const start = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(start, "signal", 0);
    const cooling = advanceObservatoryProbeState(active, OBSERVATORY_PROBE_ACTIVE_MS + 20);
    expect(cooling.status).toBe("cooldown");
    expect(cooling.targetStationId).toBe("signal");
  });

  it("advanceObservatoryProbeState transitions cooldown to ready after cooldownUntilMs", () => {
    const start = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(start, "signal", 0);
    const cooling = advanceObservatoryProbeState(active, OBSERVATORY_PROBE_ACTIVE_MS + 20);
    const ready = advanceObservatoryProbeState(
      cooling,
      OBSERVATORY_PROBE_ACTIVE_MS + OBSERVATORY_PROBE_COOLDOWN_MS + 40,
    );
    expect(ready).toEqual(createInitialObservatoryProbeState());
  });

  it("canDispatchObservatoryProbe returns false while active", () => {
    const start = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(start, "signal", 0);
    expect(canDispatchObservatoryProbe(active, 100)).toBe(false);
  });

  it("getObservatoryProbeCharge returns ~0.5 at halfway through cooldown", () => {
    const active = dispatchObservatoryProbe(createInitialObservatoryProbeState(), "targets", 0);
    const cooling = advanceObservatoryProbeState(active, OBSERVATORY_PROBE_ACTIVE_MS + 10);
    const charge = getObservatoryProbeCharge(
      cooling,
      OBSERVATORY_PROBE_ACTIVE_MS + OBSERVATORY_PROBE_COOLDOWN_MS * 0.5,
    );
    expect(charge).toBeCloseTo(0.5, 1);
  });

  // Full lifecycle test ported from huntronomer
  it("dispatches into an active window and then cools down before becoming ready", () => {
    const start = createInitialObservatoryProbeState();
    const active = dispatchObservatoryProbe(start, "signal", 100);

    expect(active.status).toBe("active");
    expect(active.targetStationId).toBe("signal");
    expect(canDispatchObservatoryProbe(active, 200)).toBe(false);

    const cooling = advanceObservatoryProbeState(active, 100 + OBSERVATORY_PROBE_ACTIVE_MS + 20);
    expect(cooling.status).toBe("cooldown");
    expect(cooling.targetStationId).toBe("signal");

    const ready = advanceObservatoryProbeState(
      cooling,
      100 + OBSERVATORY_PROBE_ACTIVE_MS + OBSERVATORY_PROBE_COOLDOWN_MS + 40,
    );
    expect(ready).toEqual(createInitialObservatoryProbeState());
    expect(canDispatchObservatoryProbe(ready, 1000)).toBe(true);
  });

  it("tracks charge and remaining time across active and cooldown states", () => {
    const active = dispatchObservatoryProbe(createInitialObservatoryProbeState(), "targets", 0);

    expect(getObservatoryProbeCharge(active, 400)).toBe(0);
    expect(getObservatoryProbeRemainingMs(active, 400)).toBeGreaterThan(0);

    const cooling = advanceObservatoryProbeState(active, OBSERVATORY_PROBE_ACTIVE_MS + 10);
    expect(cooling.status).toBe("cooldown");
    expect(getObservatoryProbeCharge(cooling, OBSERVATORY_PROBE_ACTIVE_MS + 10)).toBeCloseTo(0);
    expect(
      getObservatoryProbeCharge(
        cooling,
        OBSERVATORY_PROBE_ACTIVE_MS + OBSERVATORY_PROBE_COOLDOWN_MS * 0.5,
      ),
    ).toBeCloseTo(0.5, 1);
  });

  it("refuses dispatches without a target or while unavailable", () => {
    const idle = createInitialObservatoryProbeState();
    expect(dispatchObservatoryProbe(idle, null, 0)).toEqual(idle);

    const active = dispatchObservatoryProbe(idle, "run", 0);
    expect(dispatchObservatoryProbe(active, "receipts", 100)).toEqual(active);
  });
});
