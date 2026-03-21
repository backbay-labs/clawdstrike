/**
 * ExplainabilityDrawerPanel.tsx — Phase 31 PNL-01
 *
 * Renders station explainability data in the left drawer:
 *   - Station label + kind subtitle (with station color accent border)
 *   - Pressure causes ranked list with score bars
 *   - Anomalies from station explanation causes
 *   - PROBE STATION button (disabled when probe not ready)
 *
 * Reads from: selectedStationId, stations, pressureLanes, probeState
 * Calls: dispatchObservatoryProbeCommand() on probe button click
 */

import { useObservatoryStore } from "../../../stores/observatory-store";
import { STATION_COLORS_HEX } from "../hud-constants";
import { dispatchObservatoryProbeCommand } from "../../../commands/observatory-command-actions";

// ---------------------------------------------------------------------------
// Section heading style (shared pattern)
// ---------------------------------------------------------------------------

const sectionHeadingStyle: React.CSSProperties = {
  fontSize: 10,
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  color: "var(--hud-text-muted)",
  marginBottom: 8,
  marginTop: 0,
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ExplainabilityDrawerPanel() {
  const selectedStationId = useObservatoryStore.use.selectedStationId();
  const stations = useObservatoryStore.use.stations();
  const pressureLanes = useObservatoryStore.use.pressureLanes();
  const probeState = useObservatoryStore.use.probeState();

  // Empty state: no station selected
  if (selectedStationId === null) {
    return (
      <div
        data-testid="explainability-empty-state"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: "var(--hud-text-muted)",
          fontSize: 13,
          fontStyle: "italic",
          fontFamily: "inherit",
          textAlign: "center",
          padding: "0 16px",
        }}
      >
        Select a station to inspect
      </div>
    );
  }

  const selectedStation = stations.find((s) => s.id === selectedStationId);
  const stationColor = STATION_COLORS_HEX[selectedStationId] ?? "var(--hud-accent)";
  const anomalyCauses = selectedStation?.explanation?.causes.filter(
    (c) => c.kind === "anomaly",
  ) ?? [];

  // Sort pressure lanes by rank ascending
  const sortedLanes = [...pressureLanes].sort((a, b) => a.rank - b.rank);

  const probeReady = probeState.status === "ready";

  return (
    <div
      data-testid="explainability-drawer-panel"
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 16,
        padding: 0,
        height: "100%",
        overflowY: "auto",
        fontFamily: "inherit",
      }}
    >
      {/* Header: station label + kind */}
      <div
        style={{
          borderLeft: `4px solid ${stationColor}`,
          paddingLeft: 12,
          paddingTop: 4,
          paddingBottom: 4,
        }}
      >
        <div
          style={{
            fontSize: 16,
            fontWeight: 600,
            color: "var(--hud-text)",
            lineHeight: 1.3,
          }}
        >
          {selectedStation?.label ?? selectedStationId}
        </div>
        <div
          style={{
            fontSize: 11,
            color: "var(--hud-text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            marginTop: 2,
          }}
        >
          {selectedStation?.kind ?? "station"}
        </div>
      </div>

      {/* Pressure Causes section */}
      <div>
        <div style={sectionHeadingStyle}>Pressure Causes</div>
        {sortedLanes.length === 0 ? (
          <div
            style={{
              fontSize: 12,
              color: "var(--hud-text-muted)",
              fontStyle: "italic",
            }}
          >
            No pressure data
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {sortedLanes.map((lane) => (
              <div
                key={lane.stationId}
                style={{ display: "flex", alignItems: "center", gap: 8 }}
              >
                {/* Rank number */}
                <span
                  style={{
                    fontSize: 11,
                    color: "var(--hud-text-muted)",
                    width: 20,
                    flexShrink: 0,
                    textAlign: "right",
                  }}
                >
                  {lane.rank}
                </span>
                {/* Lane label */}
                <span
                  style={{
                    fontSize: 13,
                    color: "var(--hud-text)",
                    flex: 1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {lane.label}
                </span>
                {/* Score bar */}
                <div
                  style={{
                    width: 48,
                    height: 3,
                    borderRadius: 2,
                    background: "rgba(255,255,255,0.08)",
                    flexShrink: 0,
                    position: "relative",
                  }}
                >
                  <div
                    style={{
                      position: "absolute",
                      left: 0,
                      top: 0,
                      height: "100%",
                      borderRadius: 2,
                      width: `${Math.min(lane.score * 100, 100)}%`,
                      background: "var(--hud-accent)",
                      opacity: lane.score,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Anomalies section */}
      <div>
        <div style={sectionHeadingStyle}>Anomalies</div>
        {anomalyCauses.length === 0 ? (
          <div
            style={{
              fontSize: 12,
              color: "var(--hud-text-muted)",
              fontStyle: "italic",
            }}
          >
            No anomalies detected
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {anomalyCauses.map((cause) => (
              <div key={cause.id}>
                <div
                  style={{
                    fontSize: 13,
                    color: "var(--hud-text)",
                    fontWeight: 500,
                  }}
                >
                  {cause.label}
                </div>
                <div
                  style={{
                    fontSize: 11,
                    color: "var(--hud-text-muted)",
                    marginTop: 2,
                    lineHeight: 1.4,
                  }}
                >
                  {cause.summary}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Spacer to push button to bottom */}
      <div style={{ flex: 1 }} />

      {/* Probe button */}
      <button
        type="button"
        onClick={dispatchObservatoryProbeCommand}
        disabled={!probeReady}
        style={{
          width: "100%",
          height: 36,
          background: "var(--hud-accent)",
          color: "#000",
          fontWeight: 600,
          fontSize: 12,
          fontFamily: "inherit",
          border: "none",
          borderRadius: "var(--hud-radius, 8px)",
          cursor: probeReady ? "pointer" : "not-allowed",
          opacity: probeReady ? 1 : 0.4,
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          transition: "opacity 150ms ease",
          flexShrink: 0,
        }}
      >
        PROBE STATION
      </button>
    </div>
  );
}
