/**
 * Capsule - Floating window component
 *
 * Ported from Origin desktop dock system.
 */

import { AnimatePresence, motion } from "motion/react";
import {
  type CSSProperties,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  useCallback,
  useState,
} from "react";
import type { CapsuleKind, CapsuleViewMode, DockCapsuleState } from "./types";

const timing = {
  fast: { duration: 0.15, ease: "easeOut" as const },
  normal: { duration: 0.2, ease: "easeOut" as const },
  spring: { type: "spring" as const, damping: 25, stiffness: 300 },
};

const kindStyles: Record<CapsuleKind, { accent: string; icon: string }> = {
  output: { accent: "var(--color-sdr-accent-green)", icon: "terminal" },
  events: { accent: "var(--origin-steel-bright)", icon: "activity" },
  artifact: { accent: "var(--color-sdr-accent-amber)", icon: "file" },
  inspector: { accent: "var(--origin-steel)", icon: "inspect" },
  terminal: { accent: "var(--origin-gold)", icon: "prompt" },
  action: { accent: "var(--color-sdr-accent-orange)", icon: "action" },
  chat: { accent: "var(--origin-gold)", icon: "chat" },
  social: { accent: "var(--origin-steel-bright)", icon: "social" },
  season_pass: { accent: "var(--origin-gold)", icon: "trophy" },
  kernel_agent: { accent: "var(--origin-gold)", icon: "kernel" },
};

function CapsuleIcon({ kind, className }: { kind: CapsuleKind; className?: string }) {
  const baseClass = `capsule-icon ${className ?? ""}`;

  switch (kind) {
    case "output":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M2 3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3zm2 1v2h2V4H4zm0 4v2h8V8H4zm0 4v1h8v-1H4zm6-8v2h2V4h-2z" />
        </svg>
      );
    case "events":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M8 2a.5.5 0 0 1 .5.5v5h5a.5.5 0 0 1 0 1h-5v5a.5.5 0 0 1-1 0v-5h-5a.5.5 0 0 1 0-1h5v-5A.5.5 0 0 1 8 2z" />
          <circle cx="3" cy="3" r="1.5" />
          <circle cx="13" cy="3" r="1.5" />
          <circle cx="3" cy="13" r="1.5" />
          <circle cx="13" cy="13" r="1.5" />
        </svg>
      );
    case "artifact":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M4 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V4.5L9.5 0H4zm5.5 0v3a1.5 1.5 0 0 0 1.5 1.5h3L9.5 0z" />
        </svg>
      );
    case "inspector":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0z" />
          <path d="M0 8s3-5.5 8-5.5S16 8 16 8s-3 5.5-8 5.5S0 8 0 8zm8 3.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z" />
        </svg>
      );
    case "terminal":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M6 9a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3A.5.5 0 0 1 6 9zM3.854 4.146a.5.5 0 1 0-.708.708L4.793 6.5 3.146 8.146a.5.5 0 1 0 .708.708l2-2a.5.5 0 0 0 0-.708l-2-2z" />
          <path d="M2 1a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2H2z" />
        </svg>
      );
    case "action":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM7.5 4h1v5h-1V4zm0 6.5h1V12h-1v-1.5z" />
        </svg>
      );
    case "chat":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M2 2.5A2.5 2.5 0 0 1 4.5 0h7A2.5 2.5 0 0 1 14 2.5v5A2.5 2.5 0 0 1 11.5 10H7.4L4 12.8V10H4.5A2.5 2.5 0 0 1 2 7.5v-5z" />
        </svg>
      );
    case "social":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M5.5 8a2.5 2.5 0 1 1 0-5 2.5 2.5 0 0 1 0 5zm5 0a2 2 0 1 1 0-4 2 2 0 0 1 0 4z" />
          <path d="M1 14c0-2.2 2.1-4 4.5-4S10 11.8 10 14v1H1v-1zm9.5-3c1.9 0 3.5 1.3 3.5 3v1h-3v-1c0-1.1-.4-2.1-1.1-2.9.2 0 .4-.1.6-.1z" />
        </svg>
      );
    case "season_pass":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M4 2h8v5a4 4 0 1 1-8 0V2z" />
          <path d="M4 4H2a1 1 0 0 0-1 1v1a2 2 0 0 0 2 2h1" />
          <path d="M12 4h2a1 1 0 0 1 1 1v1a2 2 0 0 1-2 2h-1" />
          <path d="M6 14h4M8 11v3" />
        </svg>
      );
    case "kernel_agent":
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M8 1l5.5 3.18v6.36L8 13.72l-5.5-3.18V4.18L8 1z" />
          <circle cx="8" cy="7.5" r="2" fill="var(--color-bg-primary)" />
        </svg>
      );
    default:
      return (
        <svg className={baseClass} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <path d="M8 2l6 6-6 6-6-6z" />
        </svg>
      );
  }
}

interface CapsuleProps {
  capsule: DockCapsuleState;
  onClose: (id: string) => void;
  onMinimize: (id: string) => void;
  onToggleViewMode: (id: string, mode: CapsuleViewMode) => void;
  onMaximize?: (id: string) => void;
  children?: ReactNode;
  className?: string;
}

export function Capsule({
  capsule,
  onClose,
  onMinimize,
  onToggleViewMode,
  onMaximize,
  children,
  className,
}: CapsuleProps) {
  const [isHovered, setIsHovered] = useState(false);
  const isCompact = capsule.viewMode === "compact";
  const style = kindStyles[capsule.kind];

  const handleHeaderClick = useCallback(() => {
    onToggleViewMode(capsule.id, isCompact ? "expanded" : "compact");
  }, [capsule.id, isCompact, onToggleViewMode]);

  const handleClose = useCallback(
    (e: ReactMouseEvent) => {
      e.stopPropagation();
      onClose(capsule.id);
    },
    [capsule.id, onClose],
  );

  const handleMinimize = useCallback(
    (e: ReactMouseEvent) => {
      e.stopPropagation();
      onMinimize(capsule.id);
    },
    [capsule.id, onMinimize],
  );

  const handleMaximize = useCallback(
    (e: ReactMouseEvent) => {
      e.stopPropagation();
      onMaximize?.(capsule.id);
    },
    [capsule.id, onMaximize],
  );

  return (
    <motion.div
      layout="position"
      initial={false}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.96, y: 8 }}
      transition={timing.spring}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`dock-capsule ${isHovered ? "hovered" : ""} ${className ?? ""}`}
      style={
        {
          "--capsule-accent": style.accent,
          width: isCompact ? 220 : 320,
          height: isCompact ? 48 : 360,
        } as CSSProperties
      }
    >
      <motion.div
        className="capsule-glow"
        initial={false}
        animate={{ opacity: isHovered ? 0.4 : 0, scale: isHovered ? 1.05 : 0.95 }}
        transition={timing.normal}
      />

      <div className="capsule-header" onClick={handleHeaderClick}>
        <div className="capsule-header-left">
          <div className="capsule-icon-wrapper">
            <CapsuleIcon kind={capsule.kind} className="capsule-kind-icon" />
          </div>
          <div className="capsule-title-group">
            <span className="capsule-title">{capsule.title}</span>
            {capsule.subtitle ? <span className="capsule-subtitle">{capsule.subtitle}</span> : null}
          </div>
          {capsule.badgeCount ? (
            <span className="capsule-badge">
              {capsule.badgeCount > 99 ? "99+" : capsule.badgeCount}
            </span>
          ) : null}
        </div>

        <div className="capsule-header-actions">
          <button
            type="button"
            className="capsule-action-btn"
            onClick={handleMinimize}
            title="Minimize to dock"
          >
            <svg viewBox="0 0 16 16" fill="currentColor" width="12" height="12" aria-hidden="true">
              <path d="M3 8a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9A.5.5 0 0 1 3 8z" />
            </svg>
          </button>
          {onMaximize ? (
            <button
              type="button"
              className="capsule-action-btn"
              onClick={handleMaximize}
              title="Maximize"
            >
              <svg
                viewBox="0 0 16 16"
                fill="currentColor"
                width="12"
                height="12"
                aria-hidden="true"
              >
                <path d="M1.5 1a.5.5 0 0 0-.5.5v4a.5.5 0 0 1-1 0v-4A1.5 1.5 0 0 1 1.5 0h4a.5.5 0 0 1 0 1h-4zM10 .5a.5.5 0 0 1 .5-.5h4A1.5 1.5 0 0 1 16 1.5v4a.5.5 0 0 1-1 0v-4a.5.5 0 0 0-.5-.5h-4a.5.5 0 0 1-.5-.5zM.5 10a.5.5 0 0 1 .5.5v4a.5.5 0 0 0 .5.5h4a.5.5 0 0 1 0 1h-4A1.5 1.5 0 0 1 0 14.5v-4a.5.5 0 0 1 .5-.5zm15 0a.5.5 0 0 1 .5.5v4a1.5 1.5 0 0 1-1.5 1.5h-4a.5.5 0 0 1 0-1h4a.5.5 0 0 0 .5-.5v-4a.5.5 0 0 1 .5-.5z" />
              </svg>
            </button>
          ) : null}
          <button
            type="button"
            className="capsule-action-btn close"
            onClick={handleClose}
            title="Close"
          >
            <svg viewBox="0 0 16 16" fill="currentColor" width="12" height="12" aria-hidden="true">
              <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" />
            </svg>
          </button>
        </div>
      </div>

      <AnimatePresence>
        {capsule.viewMode !== "compact" ? (
          <motion.div
            className="capsule-body"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={timing.normal}
          >
            {children}
          </motion.div>
        ) : null}
      </AnimatePresence>
    </motion.div>
  );
}

interface CapsuleTabProps {
  capsule: DockCapsuleState;
  isActive?: boolean;
  onRestore: (id: string) => void;
  onClose: (id: string) => void;
}

export function CapsuleTab({ capsule, isActive, onRestore, onClose }: CapsuleTabProps) {
  const [isHovered, setIsHovered] = useState(false);
  const style = kindStyles[capsule.kind];

  return (
    <motion.div
      initial={false}
      animate={{ opacity: 1, scale: 1, y: isHovered ? -2 : 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={timing.fast}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`capsule-tab ${isActive ? "active" : ""} ${isHovered ? "hovered" : ""}`}
      style={{ "--capsule-accent": style.accent } as CSSProperties}
    >
      {isActive ? <div className="capsule-tab-active-indicator" /> : null}

      <button
        type="button"
        className="capsule-tab-main"
        onClick={() => onRestore(capsule.id)}
        title={capsule.title}
      >
        <div className="capsule-tab-icon">
          <CapsuleIcon kind={capsule.kind} />
        </div>
        <span className="capsule-tab-title">{capsule.title}</span>

        {capsule.badgeCount ? (
          <span className="capsule-tab-badge">
            {capsule.badgeCount > 9 ? "9+" : capsule.badgeCount}
          </span>
        ) : null}
      </button>

      <AnimatePresence>
        {isHovered ? (
          <motion.button
            type="button"
            initial={{ opacity: 0, width: 0 }}
            animate={{ opacity: 1, width: "auto" }}
            exit={{ opacity: 0, width: 0 }}
            transition={timing.fast}
            className="capsule-tab-close"
            onClick={(e) => {
              e.stopPropagation();
              onClose(capsule.id);
            }}
            title="Close"
          >
            <svg viewBox="0 0 16 16" fill="currentColor" width="10" height="10" aria-hidden="true">
              <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" />
            </svg>
          </motion.button>
        ) : null}
      </AnimatePresence>
    </motion.div>
  );
}

export default Capsule;
