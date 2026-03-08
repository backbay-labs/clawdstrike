/**
 * DockSystem - Main container for the dock/capsule system
 *
 * Renders:
 * - Floating capsules (output, events, artifacts, inspector, terminal)
 * - Session rail at the bottom
 * - Shelf panel when opened
 */

import { clsx } from "clsx";
import {
  type ReactNode,
  type PointerEvent as ReactPointerEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { Capsule } from "./Capsule";
import { useDock } from "./DockContext";
import { SessionRail } from "./SessionRail";
import type { CapsuleViewMode, DockCapsuleState, ShelfMode } from "./types";
import { useDockDemo } from "./useDockDemo";

// =============================================================================
// Design Tokens
// =============================================================================

// =============================================================================
// Minimal Line Icons (no emojis)
// =============================================================================

/** Action type icon - minimal line style */
function ActionTypeIcon({ type }: { type: string }) {
  const iconProps = {
    width: 14,
    height: 14,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  switch (type) {
    case "decision":
      // Balance/scale icon
      return (
        <svg {...iconProps} className="action-type-icon">
          <path d="M8 2v12M4 5l8 0M2 8l4-3v6l-4-3M14 8l-4-3v6l4-3" />
        </svg>
      );
    case "question":
      // Question mark
      return (
        <svg {...iconProps} className="action-type-icon">
          <circle cx="8" cy="8" r="6" />
          <path d="M6 6a2 2 0 1 1 2 2v1.5M8 12v.5" />
        </svg>
      );
    case "approval":
      // Checkmark circle
      return (
        <svg {...iconProps} className="action-type-icon">
          <circle cx="8" cy="8" r="6" />
          <path d="M5.5 8l2 2 3.5-4" />
        </svg>
      );
    case "input":
      // Text cursor
      return (
        <svg {...iconProps} className="action-type-icon">
          <path d="M6 3h4M6 13h4M8 3v10" />
        </svg>
      );
    case "review":
      // Eye icon
      return (
        <svg {...iconProps} className="action-type-icon">
          <path d="M2 8s2.5-4 6-4 6 4 6 4-2.5 4-6 4-6-4-6-4" />
          <circle cx="8" cy="8" r="2" />
        </svg>
      );
    default:
      // Default diamond
      return (
        <svg {...iconProps} className="action-type-icon">
          <path d="M8 2l6 6-6 6-6-6z" />
        </svg>
      );
  }
}

// =============================================================================
// Shelf Panel
// =============================================================================

interface ShelfPanelProps {
  mode: ShelfMode;
  onClose: () => void;
  children?: ReactNode;
}

const shelfTitles: Record<ShelfMode, string> = {
  events: "Policy Workbench",
  output: "Echoes",
  artifacts: "Relics",
};

type ShelfBounds = {
  x: number;
  y: number;
  width: number;
  height: number;
};

function isFiniteShelfBounds(value: ShelfBounds): boolean {
  return (
    Number.isFinite(value.x) &&
    Number.isFinite(value.y) &&
    Number.isFinite(value.width) &&
    Number.isFinite(value.height)
  );
}

const SHELF_MARGIN_PX = 10;
const SHELF_MIN_WIDTH_PX = 760;
const SHELF_MIN_HEIGHT_PX = 320;
const SHELF_MAX_WIDTH_PX = 1680;
const SHELF_MAX_HEIGHT_PX = 960;
const SHELF_RAIL_HEIGHT_PX = 52;

function getNavRailWidthPx(): number {
  if (typeof window === "undefined") return 220;
  const cssValue = window
    .getComputedStyle(document.documentElement)
    .getPropertyValue("--nav-rail-width")
    .trim();
  const parsed = Number.parseInt(cssValue, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 220;
}

function clamp(value: number, min: number, max: number): number {
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

function clampShelfBounds(next: ShelfBounds): ShelfBounds {
  if (typeof window === "undefined") return next;
  const navRailWidth = getNavRailWidthPx();
  const maxWidth = clamp(
    window.innerWidth - navRailWidth - SHELF_MARGIN_PX * 2,
    SHELF_MIN_WIDTH_PX,
    SHELF_MAX_WIDTH_PX,
  );
  const maxHeight = clamp(
    window.innerHeight - SHELF_RAIL_HEIGHT_PX - SHELF_MARGIN_PX * 3,
    SHELF_MIN_HEIGHT_PX,
    SHELF_MAX_HEIGHT_PX,
  );
  const width = clamp(next.width, SHELF_MIN_WIDTH_PX, maxWidth);
  const height = clamp(next.height, SHELF_MIN_HEIGHT_PX, maxHeight);
  const minX = navRailWidth + SHELF_MARGIN_PX;
  const maxX = window.innerWidth - SHELF_MARGIN_PX - width;
  const minY = SHELF_MARGIN_PX;
  const maxY = window.innerHeight - SHELF_RAIL_HEIGHT_PX - SHELF_MARGIN_PX - height;

  return {
    x: clamp(next.x, minX, maxX),
    y: clamp(next.y, minY, maxY),
    width,
    height,
  };
}

function defaultShelfBounds(): ShelfBounds {
  if (typeof window === "undefined") {
    return { x: 240, y: 130, width: 1200, height: 520 };
  }
  const navRailWidth = getNavRailWidthPx();
  const usableWidth = window.innerWidth - navRailWidth - SHELF_MARGIN_PX * 2;
  const width = clamp(usableWidth * 0.94, SHELF_MIN_WIDTH_PX, SHELF_MAX_WIDTH_PX);
  const height = clamp(
    window.innerHeight * 0.62,
    SHELF_MIN_HEIGHT_PX,
    Math.min(SHELF_MAX_HEIGHT_PX, window.innerHeight - SHELF_RAIL_HEIGHT_PX - SHELF_MARGIN_PX * 3),
  );
  const x = navRailWidth + SHELF_MARGIN_PX;
  const y = window.innerHeight - SHELF_RAIL_HEIGHT_PX - SHELF_MARGIN_PX - height;
  return clampShelfBounds({ x, y, width, height });
}

function expandedShelfBounds(): ShelfBounds {
  if (typeof window === "undefined") {
    return { x: 228, y: 8, width: 1520, height: 760 };
  }
  const navRailWidth = getNavRailWidthPx();
  return clampShelfBounds({
    x: navRailWidth + 8,
    y: 8,
    width: window.innerWidth - navRailWidth - 16,
    height: window.innerHeight - SHELF_RAIL_HEIGHT_PX - 16,
  });
}

function ShelfPanel({ mode, onClose, children }: ShelfPanelProps) {
  const [bounds, setBounds] = useState<ShelfBounds>(() => defaultShelfBounds());
  const [expanded, setExpanded] = useState(false);
  const previousBoundsRef = useRef<ShelfBounds | null>(null);
  const dragRef = useRef<{ offsetX: number; offsetY: number } | null>(null);
  const resizeRef = useRef<{
    startX: number;
    startY: number;
    width: number;
    height: number;
  } | null>(null);

  useEffect(() => {
    if (!isFiniteShelfBounds(bounds)) {
      setBounds(defaultShelfBounds());
      return;
    }
    const onResize = () => {
      setBounds((current) => {
        if (expanded) return expandedShelfBounds();
        return clampShelfBounds(current);
      });
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- bounds is read only for the finite check guard; the resize handler uses the setBounds updater form
  }, [expanded]);

  useEffect(() => {
    const onPointerMove = (event: PointerEvent) => {
      if (dragRef.current) {
        const next = clampShelfBounds({
          x: event.clientX - dragRef.current.offsetX,
          y: event.clientY - dragRef.current.offsetY,
          width: bounds.width,
          height: bounds.height,
        });
        setBounds(next);
        return;
      }
      if (resizeRef.current) {
        const next = clampShelfBounds({
          x: bounds.x,
          y: bounds.y,
          width: resizeRef.current.width + (event.clientX - resizeRef.current.startX),
          height: resizeRef.current.height + (event.clientY - resizeRef.current.startY),
        });
        setBounds(next);
      }
    };

    const onPointerUp = () => {
      dragRef.current = null;
      resizeRef.current = null;
    };

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
    };
  }, [bounds]);

  const handleHeaderPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("[data-shelf-control='true']")) return;
    if (expanded) return;
    dragRef.current = {
      offsetX: event.clientX - bounds.x,
      offsetY: event.clientY - bounds.y,
    };
    event.preventDefault();
  };

  const handleResizePointerDown = (event: ReactPointerEvent<HTMLButtonElement>) => {
    resizeRef.current = {
      startX: event.clientX,
      startY: event.clientY,
      width: bounds.width,
      height: bounds.height,
    };
    event.preventDefault();
    event.stopPropagation();
  };

  const handleToggleExpand = () => {
    if (expanded) {
      setExpanded(false);
      setBounds(previousBoundsRef.current ?? defaultShelfBounds());
      previousBoundsRef.current = null;
      return;
    }
    previousBoundsRef.current = bounds;
    setExpanded(true);
    setBounds(expandedShelfBounds());
  };

  const normalizedBounds = isFiniteShelfBounds(bounds)
    ? clampShelfBounds(bounds)
    : defaultShelfBounds();
  const showCompactHeader = mode === "events";

  const content = (
    <div
      className={clsx("dock-shelf-panel", expanded ? "dock-shelf-panel--expanded" : undefined)}
      data-testid={`dock-shelf-panel-${mode}`}
      style={{
        left: `${normalizedBounds.x}px`,
        top: `${normalizedBounds.y}px`,
        width: `${normalizedBounds.width}px`,
        height: `${normalizedBounds.height}px`,
        right: "auto",
        bottom: "auto",
      }}
    >
      <div className="dock-shelf-header" onPointerDown={handleHeaderPointerDown}>
        <div className="dock-shelf-header-title-wrap">
          {showCompactHeader ? null : <h3 className="dock-shelf-title">{shelfTitles[mode]}</h3>}
          <span className="dock-shelf-drag-hint">
            {showCompactHeader ? "Drag panel" : "Drag to move"}
          </span>
        </div>
        <div className="dock-shelf-header-actions">
          <button
            type="button"
            data-shelf-control="true"
            className="dock-shelf-expand"
            onClick={handleToggleExpand}
            title={expanded ? "Restore panel" : "Expand panel"}
          >
            {expanded ? "Restore" : "Expand"}
          </button>
          <button
            type="button"
            data-shelf-control="true"
            className="dock-shelf-close"
            onClick={onClose}
            title="Close"
          >
            <svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
              <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" />
            </svg>
          </button>
        </div>
      </div>
      <div
        className={clsx(
          "dock-shelf-content",
          mode === "events" ? "dock-shelf-content--events" : undefined,
        )}
      >
        {children || (
          <div className="dock-shelf-empty">
            <span className="dock-shelf-empty-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                <path
                  d="M12 3l9 9-9 9-9-9 9-9z"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  opacity="0.8"
                />
              </svg>
            </span>
            <span>
              {mode === "events" && "Policy Workbench is unavailable"}
              {mode === "output" && "No echoes yet"}
              {mode === "artifacts" && "No relics discovered"}
            </span>
          </div>
        )}
      </div>
      {!expanded ? (
        <button
          type="button"
          data-shelf-control="true"
          className="dock-shelf-resize-handle"
          aria-label="Resize shelf panel"
          onPointerDown={handleResizePointerDown}
        />
      ) : null}
    </div>
  );

  if (typeof document === "undefined") return content;
  return createPortal(content, document.body);
}

// =============================================================================
// Demo Shelf Content
// =============================================================================

const DEMO_CHRONICLE = [
  { type: "kernel", message: "Kernel awakened, scanning beads graph", time: "2m ago", icon: "hex" },
  {
    type: "dispatch",
    message: "Issue #42 routed to Claude Opus",
    time: "1m 45s ago",
    icon: "route",
  },
  {
    type: "workcell",
    message: "Workcell wc-8a3f manifested for #42",
    time: "1m 30s ago",
    icon: "branch",
  },
  { type: "dispatch", message: "Issue #43 routed to Codex", time: "1m 15s ago", icon: "route" },
  { type: "forge", message: "World generation: enchanted_forest", time: "1m ago", icon: "world" },
  { type: "gate", message: "Gate passed: terrain_quality", time: "45s ago", icon: "check" },
  { type: "gate", message: "Gate passed: flora_density", time: "30s ago", icon: "check" },
  { type: "proof", message: "Proof submitted for #43", time: "20s ago", icon: "scroll" },
  { type: "verify", message: "Verification passed for #43", time: "10s ago", icon: "seal" },
  { type: "merge", message: "PR #126 merged to main", time: "5s ago", icon: "merge" },
];

const DEMO_ECHOES = `[14:23:15] Kernel awakened
[14:23:16] Scanning beads graph...
[14:23:17] Found 3 pending issues
[14:23:18] Issue #42: auth-refactor [high] -> routing to claude
[14:23:19] Issue #43: quick-fix [low] -> routing to codex
[14:23:20] Issue #44: docs-update [low] -> queued
[14:23:21] Spawning workcell wc-8a3f for #42...
[14:23:22] Workcell ready: /workcells/wc-8a3f
[14:23:23] Claude agent initialized
[14:23:24] Reading codebase context...
[14:23:30] Found 3 files requiring changes
[14:23:35] Generating patch for auth/middleware.ts
[14:23:40] Generating patch for auth/session.ts
[14:23:45] Generating patch for tests/auth.test.ts
[14:23:50] Running quality gates...
[14:23:55] pytest: 47 passed, 0 failed
[14:24:00] mypy: no errors
[14:24:02] ruff: no issues
[14:24:05] All gates passed
[14:24:06] Submitting proof...`;

const DEMO_RELICS = [
  { name: "auth-refactor-patch.diff", type: "patch", size: "2.4kb", time: "2m ago" },
  { name: "enchanted_forest.glb", type: "asset", size: "14.2mb", time: "5m ago" },
  { name: "terrain_heightmap.png", type: "texture", size: "1.1mb", time: "5m ago" },
  { name: "flora_placement.json", type: "data", size: "342kb", time: "4m ago" },
  { name: "proof-43.json", type: "proof", size: "8.2kb", time: "1m ago" },
  { name: "gate-report-42.json", type: "report", size: "12.1kb", time: "30s ago" },
];

function ChronicleIcon({ type }: { type: string }) {
  const iconProps = {
    width: 14,
    height: 14,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
  };
  switch (type) {
    case "kernel":
      return (
        <svg {...iconProps}>
          <path d="M8 2l5 3v6l-5 3-5-3V5z" />
        </svg>
      );
    case "dispatch":
      return (
        <svg {...iconProps}>
          <path d="M2 8h12M10 4l4 4-4 4" />
        </svg>
      );
    case "workcell":
      return (
        <svg {...iconProps}>
          <path d="M4 4v8M4 8h4v4M12 4v8" />
        </svg>
      );
    case "forge":
      return (
        <svg {...iconProps}>
          <circle cx="8" cy="8" r="5" />
          <path d="M8 5v6M5 8h6" />
        </svg>
      );
    case "gate":
      return (
        <svg {...iconProps}>
          <path d="M5 8l2 2 4-4" />
          <circle cx="8" cy="8" r="6" />
        </svg>
      );
    case "proof":
      return (
        <svg {...iconProps}>
          <path d="M4 2h8v12H4z" />
          <path d="M6 5h4M6 8h4M6 11h2" />
        </svg>
      );
    case "verify":
      return (
        <svg {...iconProps}>
          <path d="M8 2l2 2-4 8-2-2z" />
          <circle cx="5" cy="12" r="2" />
        </svg>
      );
    case "merge":
      return (
        <svg {...iconProps}>
          <path d="M4 4v8M12 4v4c0 2-2 4-4 4h-4" />
          <circle cx="4" cy="4" r="1.5" fill="currentColor" />
          <circle cx="12" cy="4" r="1.5" fill="currentColor" />
        </svg>
      );
    default:
      return (
        <svg {...iconProps}>
          <circle cx="8" cy="8" r="2" fill="currentColor" />
        </svg>
      );
  }
}

function RelicIcon({ type }: { type: string }) {
  const iconProps = {
    width: 16,
    height: 16,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
  };
  switch (type) {
    case "patch":
      return (
        <svg {...iconProps}>
          <path d="M4 2h8v12H4z" />
          <path d="M6 5h4M6 8h4M6 11h2" />
        </svg>
      );
    case "asset":
      return (
        <svg {...iconProps}>
          <path d="M3 3h10v10H3z" />
          <path d="M3 10l3-3 2 2 3-3 2 2" />
        </svg>
      );
    case "texture":
      return (
        <svg {...iconProps}>
          <rect x="3" y="3" width="10" height="10" rx="1" />
          <path d="M3 8h10M8 3v10" />
        </svg>
      );
    case "data":
      return (
        <svg {...iconProps}>
          <path d="M4 2h5l3 3v9H4z" />
          <path d="M9 2v3h3" />
        </svg>
      );
    case "proof":
      return (
        <svg {...iconProps}>
          <path d="M8 2l6 4v4l-6 4-6-4V6z" />
        </svg>
      );
    case "report":
      return (
        <svg {...iconProps}>
          <path d="M4 2h8v12H4z" />
          <path d="M6 5h4M6 7h4M6 9h4M6 11h2" />
        </svg>
      );
    default:
      return (
        <svg {...iconProps}>
          <path d="M4 2h8v12H4z" />
        </svg>
      );
  }
}

function DemoChronicleContent() {
  return (
    <div className="shelf-chronicle">
      {DEMO_CHRONICLE.map((event, i) => (
        <div key={i} className="chronicle-entry">
          <span className="chronicle-icon">
            <ChronicleIcon type={event.type} />
          </span>
          <span className="chronicle-type">{event.type}</span>
          <span className="chronicle-message">{event.message}</span>
          <span className="chronicle-time">{event.time}</span>
        </div>
      ))}
    </div>
  );
}

function DemoEchoesContent() {
  return (
    <div className="shelf-echoes">
      <pre className="echoes-log">{DEMO_ECHOES}</pre>
    </div>
  );
}

function DemoRelicsContent() {
  return (
    <div className="shelf-relics">
      {DEMO_RELICS.map((relic, i) => (
        <div key={i} className="relic-entry">
          <span className="relic-icon">
            <RelicIcon type={relic.type} />
          </span>
          <div className="relic-info">
            <span className="relic-name">{relic.name}</span>
            <span className="relic-meta">
              {relic.type} - {relic.size}
            </span>
          </div>
          <span className="relic-time">{relic.time}</span>
        </div>
      ))}
    </div>
  );
}

function getDemoShelfContent(mode: ShelfMode) {
  switch (mode) {
    case "events":
      return <DemoChronicleContent />;
    case "output":
      return <DemoEchoesContent />;
    case "artifacts":
      return <DemoRelicsContent />;
    default:
      return null;
  }
}

// =============================================================================
// Capsule Content Renderers
// =============================================================================

interface CapsuleContentProps {
  capsule: DockCapsuleState;
}

function OutputContent({ capsule }: CapsuleContentProps) {
  const output = capsule.sourceData as string | undefined;
  return (
    <div className="capsule-content-output">
      <pre className="capsule-output-log">{output || "Awaiting echoes from the void..."}</pre>
    </div>
  );
}

function EventsContent({ capsule }: CapsuleContentProps) {
  const events = capsule.sourceData as
    | Array<{ type: string; message: string; timestamp: string }>
    | undefined;
  return (
    <div className="capsule-content-events">
      {events?.length ? (
        <ul className="capsule-events-list">
          {events.map((event, i) => (
            <li key={i} className="capsule-event-item">
              <span className="capsule-event-type">{event.type}</span>
              <span className="capsule-event-message">{event.message}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="capsule-empty">Policy workbench is idle</div>
      )}
    </div>
  );
}

function ArtifactContent({ capsule }: CapsuleContentProps) {
  return (
    <div className="capsule-content-artifact">
      <div className="capsule-artifact-preview">
        <span className="capsule-artifact-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
            <path d="M4 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V4.5L9.5 0H4zm5.5 0v3a1.5 1.5 0 0 0 1.5 1.5h3L9.5 0z" />
          </svg>
        </span>
        <span className="capsule-artifact-path">{capsule.sourceId || "Unknown artifact"}</span>
      </div>
    </div>
  );
}

function InspectorContent({ capsule }: CapsuleContentProps) {
  const data = capsule.sourceData as Record<string, unknown> | undefined;
  return (
    <div className="capsule-content-inspector">
      <pre className="capsule-inspector-json">
        {data ? JSON.stringify(data, null, 2) : "No data"}
      </pre>
    </div>
  );
}

function TerminalContent({ capsule }: CapsuleContentProps) {
  return (
    <div className="capsule-content-terminal">
      <div className="capsule-terminal-placeholder">Terminal: {capsule.sourceId || capsule.id}</div>
    </div>
  );
}

// =============================================================================
// Action Content - Agent Decisions/Questions
// =============================================================================

interface ActionData {
  type: "decision" | "question" | "approval" | "input" | "review";
  priority: "critical" | "high" | "normal" | "low";
  description: string;
  agentName?: string;
  options?: Array<{ id: string; label: string; description?: string; variant?: string }>;
  inputPlaceholder?: string;
  timeout?: number;
  createdAt?: string;
}

function ActionContent({ capsule }: CapsuleContentProps) {
  const action = capsule.sourceData as ActionData | undefined;

  if (!action) {
    return <div className="capsule-content-action capsule-empty">No visions from the oracle</div>;
  }

  const priorityClass = `action-priority-${action.priority}`;

  return (
    <div className={`capsule-content-action ${priorityClass}`}>
      {/* Action Header */}
      <div className="action-header">
        <ActionTypeIcon type={action.type} />
        <span className="action-agent">{action.agentName || "Agent"}</span>
        {action.priority === "critical" && <span className="action-urgent-badge">Urgent</span>}
      </div>

      {/* Description */}
      <div className="action-description">{action.description}</div>

      {/* Options for decision/approval types */}
      {action.options && action.options.length > 0 && (
        <div className="action-options">
          {action.options.map((opt) => (
            <button
              key={opt.id}
              type="button"
              className={`action-option-btn ${opt.variant === "primary" ? "primary" : ""} ${opt.variant === "destructive" ? "destructive" : ""}`}
            >
              <span className="action-option-label">{opt.label}</span>
              {opt.description && <span className="action-option-desc">{opt.description}</span>}
            </button>
          ))}
        </div>
      )}

      {/* Input for input type */}
      {action.type === "input" && (
        <div className="action-input-area">
          <input
            type="text"
            className="action-input"
            placeholder={action.inputPlaceholder || "Enter your response..."}
          />
          <button type="button" className="action-submit-btn">
            Submit
          </button>
        </div>
      )}

      {/* Timeout indicator */}
      {action.timeout && (
        <div className="action-timeout">
          <div className="action-timeout-bar" />
          <span className="action-timeout-text">Waiting for response...</span>
        </div>
      )}
    </div>
  );
}

// =============================================================================
// Chat Content - Messaging
// =============================================================================

interface ChatData {
  messages: Array<{
    id: string;
    role: "user" | "agent" | "system";
    content: string;
    timestamp: string;
    agentName?: string;
  }>;
  channelName?: string;
  isTyping?: boolean;
}

function ChatContent({ capsule }: CapsuleContentProps) {
  const chat = capsule.sourceData as ChatData | undefined;

  return (
    <div className="capsule-content-chat">
      {chat?.messages?.length ? (
        <>
          <div className="chat-messages">
            {chat.messages.map((msg) => (
              <div key={msg.id} className={`chat-message chat-message-${msg.role}`}>
                {msg.role === "agent" && (
                  <span className="chat-message-agent">{msg.agentName || "Agent"}</span>
                )}
                <div className="chat-message-content">{msg.content}</div>
                <span className="chat-message-time">
                  {new Date(msg.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </div>
            ))}
          </div>
          {chat.isTyping && (
            <div className="chat-typing">
              <span className="chat-typing-dots">
                <span />
                <span />
                <span />
              </span>
              Agent is typing...
            </div>
          )}
          <div className="chat-input-area">
            <input type="text" className="chat-input" placeholder="Whisper to the agents..." />
            <button type="button" className="chat-send-btn">
              <svg viewBox="0 0 16 16" fill="currentColor" width="16" height="16">
                <path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11z" />
              </svg>
            </button>
          </div>
        </>
      ) : (
        <div className="capsule-empty">Silence in the ether</div>
      )}
    </div>
  );
}

// =============================================================================
// Social Content - Connections
// =============================================================================

interface SocialData {
  connections: Array<{
    id: string;
    name: string;
    avatar?: string;
    status: "online" | "away" | "offline";
    lastSeen?: string;
  }>;
  pendingRequests?: number;
}

function SocialContent({ capsule }: CapsuleContentProps) {
  const social = capsule.sourceData as SocialData | undefined;

  return (
    <div className="capsule-content-social">
      {social?.pendingRequests && social.pendingRequests > 0 && (
        <div className="social-pending-banner">
          <span className="social-pending-count">{social.pendingRequests}</span>
          pending request{social.pendingRequests > 1 ? "s" : ""}
        </div>
      )}
      {social?.connections?.length ? (
        <div className="social-connections">
          {social.connections.map((conn) => (
            <div key={conn.id} className="social-connection-item">
              <div className={`social-avatar social-status-${conn.status}`}>
                {conn.avatar ? (
                  <img src={conn.avatar} alt={conn.name} />
                ) : (
                  <span className="social-avatar-placeholder">
                    {conn.name.charAt(0).toUpperCase()}
                  </span>
                )}
              </div>
              <div className="social-connection-info">
                <span className="social-connection-name">{conn.name}</span>
                <span className="social-connection-status">
                  {conn.status === "online"
                    ? "Online"
                    : conn.status === "away"
                      ? "Away"
                      : conn.lastSeen || "Offline"}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="capsule-empty">The coven awaits new members</div>
      )}
    </div>
  );
}

// =============================================================================
// Season Pass Content
// =============================================================================

interface SeasonPassData {
  isPremium?: boolean;
}

function SeasonPassContent({ capsule }: CapsuleContentProps) {
  const data = capsule.sourceData as SeasonPassData | undefined;

  return (
    <div className="capsule-content-season-pass">
      <div className="capsule-empty">
        Season pass is not wired in this build{data?.isPremium ? " (premium)" : ""}.
      </div>
    </div>
  );
}

function getCapsuleContent(capsule: DockCapsuleState): ReactNode {
  switch (capsule.kind) {
    case "output":
      return <OutputContent capsule={capsule} />;
    case "events":
      return <EventsContent capsule={capsule} />;
    case "artifact":
      return <ArtifactContent capsule={capsule} />;
    case "inspector":
      return <InspectorContent capsule={capsule} />;
    case "terminal":
      return <TerminalContent capsule={capsule} />;
    case "action":
      return <ActionContent capsule={capsule} />;
    case "chat":
      return <ChatContent capsule={capsule} />;
    case "social":
      return <SocialContent capsule={capsule} />;
    case "season_pass":
      return <SeasonPassContent capsule={capsule} />;
    case "kernel_agent":
      return <div className="capsule-empty">Kernel agent capsule is not wired yet.</div>;
    default:
      return null;
  }
}

// =============================================================================
// Capsule Stack Layout
// =============================================================================

interface CapsuleStackProps {
  capsules: DockCapsuleState[];
  onClose: (id: string) => void;
  onMinimize: (id: string) => void;
  onToggleViewMode: (id: string, mode: CapsuleViewMode) => void;
}

function CapsuleStack({ capsules, onClose, onMinimize, onToggleViewMode }: CapsuleStackProps) {
  return (
    <div className="dock-capsule-stack">
      {capsules.map((capsule, index) => (
        <div
          key={capsule.id}
          className="dock-capsule-wrapper"
          style={{
            zIndex: 100 + index,
            marginLeft: index > 0 ? 8 : 0,
          }}
        >
          <Capsule
            capsule={capsule}
            onClose={onClose}
            onMinimize={onMinimize}
            onToggleViewMode={onToggleViewMode}
          >
            {getCapsuleContent(capsule)}
          </Capsule>
        </div>
      ))}
    </div>
  );
}

// =============================================================================
// DockSystem Component
// =============================================================================

interface DockSystemProps {
  /** Custom shelf content renderer */
  renderShelfContent?: (mode: ShelfMode) => ReactNode;
  /** Events count for session rail badge */
  eventsCount?: number;
  /** Callback when a session is opened */
  onOpenSession?: (id: string) => void;
  /** Callback when a session is closed */
  onCloseSession?: (id: string) => void;
  /** Enable demo mode with sample data */
  demoMode?: boolean;
  /** Additional class name */
  className?: string;
}

export function DockSystem({
  renderShelfContent,
  eventsCount = 0,
  onOpenSession,
  onCloseSession,
  demoMode = false,
  className,
}: DockSystemProps) {
  // Enable demo mode with sample Oracle/Whisper/Coven data
  useDockDemo(
    demoMode
      ? {
          showOracle: true,
          showWhisper: true,
          showCoven: true,
          showSessions: true,
          oracleCount: 3,
          whisperCount: 2,
        }
      : {
          showOracle: false,
          showWhisper: false,
          showCoven: false,
          showSessions: false,
        },
  );

  const { visibleCapsules, shelf, closeCapsule, minimizeCapsule, setViewMode, closeShelf } =
    useDock();

  let customShelfContent: ReactNode | undefined;
  if (shelf.isOpen && shelf.mode) {
    try {
      customShelfContent = renderShelfContent?.(shelf.mode);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown shelf render error";
      customShelfContent = (
        <div className="dock-shelf-empty">
          <span>Failed to render shelf content</span>
          <span className="dock-shelf-empty-detail">{message}</span>
        </div>
      );
    }
  }

  const handleToggleViewMode = useCallback(
    (id: string, mode: CapsuleViewMode) => {
      setViewMode(id, mode);
    },
    [setViewMode],
  );

  const shelfContent =
    shelf.isOpen && shelf.mode ? (
      <ShelfPanel key={`shelf:${shelf.mode}`} mode={shelf.mode} onClose={closeShelf}>
        {customShelfContent || (demoMode && getDemoShelfContent(shelf.mode))}
      </ShelfPanel>
    ) : null;

  return (
    <div className={`dock-system ${className ?? ""}`}>
      {/* Floating capsules area */}
      <div className="dock-capsules-area">
        <CapsuleStack
          capsules={visibleCapsules}
          onClose={closeCapsule}
          onMinimize={minimizeCapsule}
          onToggleViewMode={handleToggleViewMode}
        />
      </div>

      {/* Shelf panel (slides up from bottom) */}
      {shelfContent}

      {/* Session rail (always visible at bottom) */}
      <SessionRail
        eventsCount={eventsCount}
        onOpenSession={onOpenSession}
        onCloseSession={onCloseSession}
      />
    </div>
  );
}

// =============================================================================
// Export index
// =============================================================================

export { Capsule, CapsuleTab } from "./Capsule";
export { DockProvider, useCapsule, useCapsulesByKind, useDock } from "./DockContext";
export { SessionRail } from "./SessionRail";
export type * from "./types";

export default DockSystem;
