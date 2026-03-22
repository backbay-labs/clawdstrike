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
          flexDirection: "column",
          gap: 16,
          height: "100%",
          fontFamily: "inherit",
          padding: 0,
        }}
      >
        {/* Station section placeholder */}
        <div
          style={{
            borderLeft: "4px solid rgba(255,255,255,0.08)",
            paddingLeft: 12,
            paddingTop: 4,
            paddingBottom: 4,
          }}
        >
          <div style={{ ...sectionHeadingStyle, marginBottom: 4 }}>STATION</div>
          <div style={{ fontSize: 12, color: "var(--hud-text-muted)", fontStyle: "italic" }}>
            No station selected
          </div>
        </div>

        {/* Pressure section placeholder */}
        <div>
          <div style={sectionHeadingStyle}>PRESSURE LANES</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {[1, 2, 3].map((i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 11, color: "var(--hud-text-muted)", width: 20, textAlign: "right" }}>{i}</span>
                <span style={{ flex: 1, height: 8, borderRadius: 4, background: "rgba(255,255,255,0.04)" }} />
                <div style={{ width: 48, height: 3, borderRadius: 2, background: "rgba(255,255,255,0.04)" }} />
              </div>
            ))}
          </div>
        </div>

        {/* Anomalies section placeholder */}
        <div>
          <div style={sectionHeadingStyle}>ANOMALIES</div>
          <div style={{ fontSize: 12, color: "var(--hud-text-muted)", fontStyle: "italic" }}>
            No anomalies to display
          </div>
        </div>

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* Hint */}
        <div
          style={{
            fontSize: 12,
            color: "var(--hud-text-muted)",
            textAlign: "center",
            padding: "12px 8px",
            borderTop: "1px solid rgba(255,255,255,0.04)",
            lineHeight: 1.5,
          }}
        >
          Click a station or press E while hovering
        </div>
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
