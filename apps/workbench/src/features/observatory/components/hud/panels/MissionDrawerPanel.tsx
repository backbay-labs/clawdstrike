/**
 * MissionDrawerPanel.tsx — Phase 31 PNL-02
 *
 * Renders the active mission state in the left drawer:
 *   - Status badge (IN PROGRESS / COMPLETED)
 *   - Mission briefing text
 *   - Objectives list with completion checkmarks
 *   - Progress bar (completed/total ratio)
 *
 * Reads from: mission (ObservatoryMissionLoopState | null)
 */

import { useObservatoryStore } from "../../../stores/observatory-store";

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

export function MissionDrawerPanel() {
  const mission = useObservatoryStore.use.mission();

  // Empty state: no active mission
  if (mission === null) {
    return (
      <div
        data-testid="mission-empty-state"
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 16,
          height: "100%",
          fontFamily: "inherit",
          padding: 0,
        }}
      >
        {/* Briefing section placeholder */}
        <div>
          <div style={sectionHeadingStyle}>BRIEFING</div>
          <div
            style={{
              fontSize: 12,
              color: "var(--hud-text-muted)",
              fontStyle: "italic",
              lineHeight: 1.5,
            }}
          >
            No mission briefing available
          </div>
        </div>

        {/* Objectives section placeholder */}
        <div>
          <div style={sectionHeadingStyle}>OBJECTIVES</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[1, 2, 3].map((i) => (
              <div key={i} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ fontSize: 14, color: "var(--hud-text-muted)" }}>{"\u25CB"}</span>
                <span style={{ flex: 1, height: 8, borderRadius: 4, background: "rgba(255,255,255,0.04)" }} />
              </div>
            ))}
          </div>
        </div>

        {/* Narrative section placeholder */}
        <div>
          <div style={sectionHeadingStyle}>NARRATIVE</div>
          <div
            style={{
              fontSize: 12,
              color: "var(--hud-text-muted)",
              fontStyle: "italic",
              lineHeight: 1.5,
            }}
          >
            Mission narrative will appear here
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
          Start a mission from the command palette
        </div>
      </div>
    );
  }

  const completedCount = mission.completedObjectiveIds.length;
  const totalCount = mission.objectives.length;
  const progressPct = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;
  const isCompleted = mission.status === "completed";

  return (
    <div
      data-testid="mission-drawer-panel"
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
      {/* Status badge */}
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <span
          style={{
            background: isCompleted
              ? "rgba(100,255,100,0.15)"
              : "rgba(74,170,255,0.15)",
            color: "var(--hud-accent)",
            fontSize: 10,
            padding: "2px 8px",
            borderRadius: 10,
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            fontFamily: "inherit",
          }}
        >
          {isCompleted ? "Completed" : "In Progress"}
        </span>
      </div>

      {/* Briefing section */}
      <div>
        <div style={sectionHeadingStyle}>Mission Briefing</div>
        <div
          style={{
            fontSize: 13,
            color: "var(--hud-text)",
            lineHeight: 1.5,
          }}
        >
          {mission.briefing}
        </div>
      </div>

      {/* Objectives section */}
      <div>
        <div style={sectionHeadingStyle}>Objectives</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {mission.objectives.map((objective) => {
            const completed = mission.completedObjectiveIds.includes(
              objective.id,
            );
            return (
              <div
                key={objective.id}
                style={{ display: "flex", gap: 8, alignItems: "flex-start" }}
              >
                {/* Checkmark indicator */}
                <span
                  style={{
                    fontSize: 14,
                    color: completed
                      ? "var(--hud-accent)"
                      : "var(--hud-text-muted)",
                    flexShrink: 0,
                    marginTop: 1,
                    lineHeight: 1,
                  }}
                >
                  {completed ? "\u2713" : "\u25CB"}
                </span>
                <div style={{ flex: 1 }}>
                  {/* Objective title */}
                  <div
                    style={{
                      fontSize: 13,
                      color: "var(--hud-text)",
                      textDecoration: completed ? "line-through" : "none",
                      opacity: completed ? 0.5 : 1,
                      lineHeight: 1.3,
                    }}
                  >
                    {objective.title}
                  </div>
                  {/* Hint text */}
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--hud-text-muted)",
                      marginTop: 2,
                      lineHeight: 1.4,
                    }}
                  >
                    {objective.hint}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Spacer */}
      <div style={{ flex: 1 }} />

      {/* Progress bar */}
      <div
        style={{
          height: 3,
          background: "rgba(255,255,255,0.08)",
          borderRadius: 2,
          overflow: "hidden",
          flexShrink: 0,
        }}
      >
        <div
          style={{
            height: "100%",
            borderRadius: 2,
            background: "var(--hud-accent)",
            width: `${progressPct}%`,
            transition: "width 300ms ease",
          }}
        />
      </div>
    </div>
  );
}
