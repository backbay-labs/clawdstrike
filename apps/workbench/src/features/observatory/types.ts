export type ObservatoryStationKind =
  | "hunt"           // maps to /hunt pane route
  | "observatory"    // maps to /observatory pane route (Phase 3)
  | "nexus"          // maps to /nexus pane route (Phase 4)
  | "spirit-chamber"; // maps to /spirit-chamber pane route (Phase 2)

export interface ObservatoryStation {
  id: string;
  kind: ObservatoryStationKind;
  label: string;
  route: string; // workbench pane route to openApp to
  artifactCount: number;
}

export interface ObservatorySeamSummary {
  stationCount: number;
  artifactCount: number; // total across all stations — drives activity bar badge
  activeProbes: number;  // > 0 means hunt is live; drives badge liveness
}

export interface ObservatoryState {
  stations: ObservatoryStation[];
  seamSummary: ObservatorySeamSummary;
  connected: boolean; // true when linked to live hunt data
  actions: {
    setStations: (stations: ObservatoryStation[]) => void;
    updateSeamSummary: (summary: Partial<ObservatorySeamSummary>) => void;
    setConnected: (connected: boolean) => void;
    addArtifacts: (stationId: string, count: number) => void;
  };
}
