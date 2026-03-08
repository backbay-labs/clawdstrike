import { useCallback, useEffect, useState } from "react";

export interface HuntronomerLaunchOverlayProps {
  visible: boolean;
  onDismiss: () => void;
}

const EXIT_DURATION_MS = 420;

const capabilityLabels = [
  "Swarm orchestration",
  "Guarded execution",
  "Live telemetry",
] as const;

const briefingItems = [
  {
    label: "Mission Control",
    copy: "Direct autonomous hunt cells across active environments without losing operator authority.",
  },
  {
    label: "Threat Flow",
    copy: "Watch detections, approvals, and posture shifts converge into a single operational lane.",
  },
  {
    label: "Retask in Real Time",
    copy: "Escalate, contain, or redirect agents as signals sharpen and objectives change.",
  },
] as const;

export function HuntronomerLaunchOverlay({
  visible,
  onDismiss,
}: HuntronomerLaunchOverlayProps) {
  const [isExiting, setIsExiting] = useState(false);

  useEffect(() => {
    if (visible) setIsExiting(false);
  }, [visible]);

  const handleDismiss = useCallback(() => {
    if (isExiting) return;
    setIsExiting(true);
    window.setTimeout(() => onDismiss(), EXIT_DURATION_MS);
  }, [isExiting, onDismiss]);

  useEffect(() => {
    if (!visible || isExiting) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Enter" || event.key === "Escape") {
        event.preventDefault();
        handleDismiss();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [handleDismiss, isExiting, visible]);

  if (!visible) return null;

  return (
    <div
      className={`huntronomer-launch ${isExiting ? "huntronomer-launch--exiting" : ""}`}
      role="dialog"
      aria-modal="true"
      aria-label="Open Huntronomer"
      onClick={handleDismiss}
    >
      <div className="huntronomer-launch__wallpaper" />
      <div className="huntronomer-launch__veil" />
      <div className="huntronomer-launch__mesh" />

      <div className="huntronomer-launch__frame" onClick={(event) => event.stopPropagation()}>
        <section className="huntronomer-launch__hero">
          <div className="huntronomer-launch__eyebrow">Autonomous Threat Hunting Command</div>
          <h1 className="huntronomer-launch__title">Huntronomer</h1>
          <p className="huntronomer-launch__strap">
            Direct and manage autonomous threat hunting agent swarms.
          </p>
          <p className="huntronomer-launch__summary">
            Turn live signals into coordinated hunts, keep operator approvals in the loop, and
            steer every strikecell from a single command deck.
          </p>

          <div className="huntronomer-launch__capabilities" aria-label="Key capabilities">
            {capabilityLabels.map((label) => (
              <span key={label} className="huntronomer-launch__capability">
                {label}
              </span>
            ))}
          </div>

          <div className="huntronomer-launch__actions">
            <button
              type="button"
              className="origin-focus-ring huntronomer-launch__primary"
              onClick={handleDismiss}
            >
              Open Command Deck
            </button>
            <div className="huntronomer-launch__hint">Press Enter or Esc to continue</div>
          </div>
        </section>

        <aside className="huntronomer-launch__briefing">
          <div className="huntronomer-launch__briefing-label">Operational Brief</div>
          <div className="huntronomer-launch__briefing-title">
            Operator-directed swarms across every active hunt lane.
          </div>
          <div className="huntronomer-launch__briefing-grid">
            <div className="huntronomer-launch__metric">
              <span className="huntronomer-launch__metric-label">Mode</span>
              <strong>Operator Directed</strong>
            </div>
            <div className="huntronomer-launch__metric">
              <span className="huntronomer-launch__metric-label">Telemetry</span>
              <strong>Live + Guarded</strong>
            </div>
            <div className="huntronomer-launch__metric">
              <span className="huntronomer-launch__metric-label">Objective</span>
              <strong>Threat Hunting</strong>
            </div>
          </div>

          <div className="huntronomer-launch__briefing-items">
            {briefingItems.map((item) => (
              <div key={item.label} className="huntronomer-launch__briefing-item">
                <div className="huntronomer-launch__briefing-item-label">{item.label}</div>
                <p>{item.copy}</p>
              </div>
            ))}
          </div>
        </aside>
      </div>
    </div>
  );
}

export default HuntronomerLaunchOverlay;
