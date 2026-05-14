import { useEffect, useRef } from "react";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import { useObservatoryStore } from "../stores/observatory-store";
import {
  deriveObservatoryTelemetry,
  type DerivedObservatoryTelemetry,
} from "../world/observatory-telemetry";

export function ObservatoryTelemetryBridge() {
  const connected = useHuntStore.use.connected();
  const events = useHuntStore.use.events();
  const baselines = useHuntStore.use.baselines();
  const investigations = useHuntStore.use.investigations();
  const patterns = useHuntStore.use.patterns();
  const observatoryActions = useObservatoryStore.use.actions();
  const previousTelemetryRef = useRef<DerivedObservatoryTelemetry | null>(null);

  useEffect(() => {
    const telemetry = deriveObservatoryTelemetry({
      baselines,
      connected,
      events,
      investigations,
      patterns,
      previousTelemetry: previousTelemetryRef.current,
    });
    previousTelemetryRef.current = telemetry;

    observatoryActions.setConnected(connected);
    observatoryActions.setSceneTelemetry({
      confidence: telemetry.confidence,
      likelyStationId: telemetry.likelyStationId,
      pressureLanes: telemetry.pressureLanes,
      roomReceiveState: telemetry.roomReceiveState,
      telemetrySnapshotMs: telemetry.telemetrySnapshotMs,
    });
    observatoryActions.setStations(telemetry.stations);
  }, [baselines, connected, events, investigations, observatoryActions, patterns]);

  return null;
}
