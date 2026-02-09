/**
 * SessionRail - Bottom activity bar
 *
 * Shows active sessions (runs, builds, terminals) and minimized capsules.
 * Provides quick access to notifications and shelf panels.
 * Includes dial menus for quick access to agentic capsules (Oracle, Whisper, Coven).
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";
import { useDock } from "./DockContext";
import { CapsuleTab } from "./Capsule";
import type { SessionItem, ShelfMode, CapsuleKind } from "./types";

// =============================================================================
// Design Tokens
// =============================================================================

const timing = {
  fast: { duration: 0.15, ease: "easeOut" as const },
  normal: { duration: 0.2, ease: "easeOut" as const },
  spring: { type: "spring" as const, damping: 24, stiffness: 300 },
};

// =============================================================================
// Icons
// =============================================================================

function ActivityIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
      <path d="M6 2a.5.5 0 0 1 .47.33L10 12.036l1.53-4.208A.5.5 0 0 1 12 7.5h3.5a.5.5 0 0 1 0 1h-3.15l-1.88 5.17a.5.5 0 0 1-.94 0L6 3.964 4.47 8.171A.5.5 0 0 1 4 8.5H.5a.5.5 0 0 1 0-1h3.15l1.88-5.17A.5.5 0 0 1 6 2z" />
    </svg>
  );
}

function TerminalIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
      <path d="M6 9a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3A.5.5 0 0 1 6 9zM3.854 4.146a.5.5 0 1 0-.708.708L4.793 6.5 3.146 8.146a.5.5 0 1 0 .708.708l2-2a.5.5 0 0 0 0-.708l-2-2z" />
      <path d="M2 1a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2H2z" />
    </svg>
  );
}

function BuildIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
      <path d="M1 0L0 1l2.2 3.081a1 1 0 0 0 .815.419h.07a1 1 0 0 1 .708.293l2.675 2.675-2.617 2.654A3.003 3.003 0 0 0 0 13a3 3 0 1 0 5.878-.851l2.654-2.617.968.968-.305.914a1 1 0 0 0 .242 1.023l3.27 3.27a.997.997 0 0 0 1.414 0l1.586-1.586a.997.997 0 0 0 0-1.414l-3.27-3.27a1 1 0 0 0-1.023-.242L10.5 9.5l-.96-.96 2.68-2.643A3.005 3.005 0 0 0 16 3c0-.269-.035-.53-.102-.777l-2.14 2.141L12 4l-.364-1.757L13.777.102a3 3 0 0 0-3.675 3.68L7.462 6.46 4.793 3.793a1 1 0 0 1-.293-.707v-.071a1 1 0 0 0-.419-.814L1 0z" />
    </svg>
  );
}

function EventsIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
      <path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h12zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H2z" />
      <path d="M3 4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9A.5.5 0 0 1 3 4zm0 4a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9A.5.5 0 0 1 3 8zm0 4a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5z" />
    </svg>
  );
}

function ArtifactsIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
      <path d="M1 2.5A1.5 1.5 0 0 1 2.5 1h3A1.5 1.5 0 0 1 7 2.5v3A1.5 1.5 0 0 1 5.5 7h-3A1.5 1.5 0 0 1 1 5.5v-3zM2.5 2a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3zm6.5.5A1.5 1.5 0 0 1 10.5 1h3A1.5 1.5 0 0 1 15 2.5v3A1.5 1.5 0 0 1 13.5 7h-3A1.5 1.5 0 0 1 9 5.5v-3zm1.5-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3zM1 10.5A1.5 1.5 0 0 1 2.5 9h3A1.5 1.5 0 0 1 7 10.5v3A1.5 1.5 0 0 1 5.5 15h-3A1.5 1.5 0 0 1 1 13.5v-3zm1.5-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3zm6.5.5A1.5 1.5 0 0 1 10.5 9h3a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-1.5 1.5h-3A1.5 1.5 0 0 1 9 13.5v-3zm1.5-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3z" />
    </svg>
  );
}

function OutputIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
      <path d="M5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-1 0v-9A.5.5 0 0 1 5 3zm5.5.5a.5.5 0 0 0-1 0v9a.5.5 0 0 0 1 0v-9z" />
      <path d="M0 4.5A1.5 1.5 0 0 1 1.5 3h13A1.5 1.5 0 0 1 16 4.5v7a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 0 11.5v-7zM1.5 4a.5.5 0 0 0-.5.5v7a.5.5 0 0 0 .5.5h13a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.5-.5h-13z" />
    </svg>
  );
}

// Runic Icons for agentic UI - mystical Cyntra aesthetic

/** Oracle - Eye symbol for agent decisions/prophecies */
function OracleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="16" height="16">
      <path d="M12 5C7 5 2.73 8.11 1 12c1.73 3.89 6 7 11 7s9.27-3.11 11-7c-1.73-3.89-6-7-11-7z" />
      <circle cx="12" cy="12" r="3" />
      <circle cx="12" cy="12" r="1" fill="currentColor" />
    </svg>
  );
}

/** Whisper - Speech rune for agent communication */
function WhisperIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="16" height="16">
      <path d="M21 12c0 4.418-4.03 8-9 8-1.6 0-3.11-.36-4.41-1L3 21l1.5-4.5C3.56 15.18 3 13.64 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
      <path d="M9 10h6M9 14h4" />
    </svg>
  );
}

/** Coven - Connected nodes for agent collective */
function CovenIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="16" height="16">
      <circle cx="12" cy="12" r="2" />
      <circle cx="12" cy="5" r="2" />
      <circle cx="6" cy="17" r="2" />
      <circle cx="18" cy="17" r="2" />
      <path d="M12 7v3M10.27 13.5L7.5 15.5M13.73 13.5l2.77 2" />
    </svg>
  );
}

// =============================================================================
// Session Pill Component
// =============================================================================

interface SessionPillProps {
  session: SessionItem;
  onOpen?: (id: string) => void;
  onClose?: (id: string) => void;
}

function SessionPill({ session, onOpen, onClose }: SessionPillProps) {
  const [isHovered, setIsHovered] = useState(false);

  const statusClass = useMemo(() => {
    switch (session.status) {
      case "running":
        return "status-running";
      case "success":
        return "status-success";
      case "error":
        return "status-error";
      default:
        return "status-idle";
    }
  }, [session.status]);

  const Icon = useMemo(() => {
    switch (session.kind) {
      case "run":
        return ActivityIcon;
      case "terminal":
        return TerminalIcon;
      case "build":
        return BuildIcon;
    }
  }, [session.kind]);

  return (
    <div
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`session-pill ${statusClass} ${isHovered ? "hovered" : ""}`}
    >
      <button
        type="button"
        className="session-pill-main"
        onClick={() => onOpen?.(session.id)}
      >
        <span className="session-pill-status" />
        <Icon className="session-pill-icon" />
        <span className="session-pill-title">{session.title}</span>

        {session.progress !== undefined && session.status === "running" && (
          <div className="session-pill-progress">
            <div
              className="session-pill-progress-bar"
              style={{ width: `${session.progress * 100}%` }}
            />
          </div>
        )}
      </button>

      {/* Close button on hover */}
      {isHovered && onClose && (
        <button
          type="button"
          className="session-pill-close"
          onClick={(e) => {
            e.stopPropagation();
            onClose(session.id);
          }}
          title="Close"
        >
          <svg viewBox="0 0 16 16" fill="currentColor" width="10" height="10">
            <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" />
          </svg>
        </button>
      )}
    </div>
  );
}

// =============================================================================
// Shelf Button Component
// =============================================================================

interface ShelfButtonProps {
  icon: ReactNode;
  label: string;
  mode: ShelfMode;
  badgeCount?: number;
  isActive?: boolean;
  onClick?: () => void;
}

function ShelfButton({ icon, label, mode: _mode, badgeCount, isActive, onClick }: ShelfButtonProps) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <button
      type="button"
      className={`shelf-button ${isActive ? "active" : ""}`}
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      title={label}
      aria-pressed={isActive}
    >
      <motion.div
        className="shelf-button-glow"
        initial={false}
        animate={{
          opacity: isHovered && !isActive ? 0.4 : 0,
          scale: isHovered ? 1.05 : 0.95,
        }}
        transition={timing.normal}
      />

      {icon}

      {badgeCount ? (
        <span className="shelf-button-badge">
          {badgeCount > 9 ? "9+" : badgeCount}
        </span>
      ) : null}
    </button>
  );
}

// =============================================================================
// Agentic Button Component
// =============================================================================

interface AgenticButtonProps {
  icon: ReactNode;
  label: string;
  variant: "action" | "chat" | "social";
  badgeCount?: number;
  isActive?: boolean;
  hasCritical?: boolean;
  onClick?: () => void;
}

function AgenticButton({ icon, label, variant, badgeCount, isActive, hasCritical, onClick }: AgenticButtonProps) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <button
      type="button"
      className={`agentic-button agentic-button-${variant} ${isActive ? "active" : ""} ${hasCritical ? "critical" : ""}`}
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      title={label}
      aria-pressed={isActive}
    >
      <motion.div
        className="agentic-button-glow"
        initial={false}
        animate={{
          opacity: isHovered && !isActive ? 0.4 : 0,
          scale: isHovered ? 1.05 : 0.95,
        }}
        transition={timing.normal}
      />

      {icon}

      {badgeCount ? (
        <span className={`agentic-button-badge ${hasCritical ? "critical" : ""}`}>
          {badgeCount > 9 ? "9+" : badgeCount}
        </span>
      ) : null}
    </button>
  );
}

// =============================================================================
// Dial Menu Component - Quick Actions Menu
// =============================================================================

interface DialMenuItem {
  id: string;
  title: string;
  subtitle?: string;
  badgeCount?: number;
  priority?: "critical" | "high" | "normal" | "low";
  kind: CapsuleKind;
}

interface DialMenuProps {
  isOpen: boolean;
  variant: "oracle" | "whisper" | "coven";
  items: DialMenuItem[];
  onClose: () => void;
  onSelectItem: (id: string) => void;
}

function DialMenu({ isOpen, variant, items, onClose, onSelectItem }: DialMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on click outside or escape
  useEffect(() => {
    if (!isOpen) return;

    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        const target = e.target as HTMLElement;
        if (!target.closest(".agentic-button")) {
          onClose();
        }
      }
    };

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };

    const timeout = setTimeout(() => {
      document.addEventListener("mousedown", handleClickOutside);
    }, 50);
    document.addEventListener("keydown", handleEscape);

    return () => {
      clearTimeout(timeout);
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [isOpen, onClose]);

  const config = {
    oracle: { title: "Oracle Visions", empty: "No visions awaiting", icon: <OracleIcon /> },
    whisper: { title: "Whisper Channels", empty: "Silence in the ether", icon: <WhisperIcon /> },
    coven: { title: "The Coven", empty: "The coven is quiet", icon: <CovenIcon /> },
  };

  if (!isOpen) return null;

  return (
    <div ref={menuRef} className={`dial-menu dial-menu-${variant}`}>
      {/* Header */}
      <div className="dial-menu-header">
        <span className="dial-menu-icon">{config[variant].icon}</span>
        <span className="dial-menu-title">{config[variant].title}</span>
        {items.length > 0 && <span className="dial-menu-count">{items.length}</span>}
      </div>

      {/* Items */}
      <div className="dial-menu-items">
        {items.length > 0 ? (
          items.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`dial-menu-item ${item.priority === "critical" ? "critical" : ""}`}
              onClick={() => {
                onSelectItem(item.id);
                onClose();
              }}
            >
              <div className="dial-item-content">
                <span className="dial-item-title">{item.title}</span>
                {item.subtitle && <span className="dial-item-subtitle">{item.subtitle}</span>}
              </div>
              {item.badgeCount !== undefined && item.badgeCount > 0 && (
                <span className={`dial-item-badge ${item.priority === "critical" ? "critical" : ""}`}>
                  {item.badgeCount}
                </span>
              )}
              <span className="dial-item-arrow">
                <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M6 4l4 4-4 4" />
                </svg>
              </span>
            </button>
          ))
        ) : (
          <div className="dial-menu-empty">{config[variant].empty}</div>
        )}
      </div>
    </div>
  );
}

// =============================================================================
// Session Rail Component
// =============================================================================

interface SessionRailProps {
  onOpenSession?: (id: string) => void;
  onCloseSession?: (id: string) => void;
  eventsCount?: number;
  className?: string;
}

export function SessionRail({
  onOpenSession,
  onCloseSession,
  eventsCount = 0,
  className,
}: SessionRailProps) {
  const {
    sessions,
    capsules,
    minimizedCapsules,
    shelf,
    restoreCapsule,
    closeCapsule,
    toggleShelf,
    closeShelf,
  } = useDock();

  const [activeDial, setActiveDial] = useState<"oracle" | "whisper" | "coven" | null>(null);

  // Get capsules by type for dial menus
  const oracleCapsules = useMemo(() =>
    capsules.filter((c) => c.kind === "action"),
    [capsules]
  );

  const whisperCapsules = useMemo(() =>
    capsules.filter((c) => c.kind === "chat"),
    [capsules]
  );

  const covenCapsules = useMemo(() =>
    capsules.filter((c) => c.kind === "social"),
    [capsules]
  );

  // Convert capsules to dial menu items
  const oracleItems: DialMenuItem[] = useMemo(() =>
    oracleCapsules.map((c) => ({
      id: c.id,
      title: c.title,
      subtitle: c.subtitle,
      badgeCount: c.badgeCount,
      priority: (c.sourceData as { priority?: "critical" | "high" | "normal" | "low" })?.priority,
      kind: c.kind,
    })),
    [oracleCapsules]
  );

  const whisperItems: DialMenuItem[] = useMemo(() =>
    whisperCapsules.map((c) => ({
      id: c.id,
      title: c.title,
      subtitle: c.subtitle,
      badgeCount: c.badgeCount,
      kind: c.kind,
    })),
    [whisperCapsules]
  );

  const covenItems: DialMenuItem[] = useMemo(() =>
    covenCapsules.map((c) => ({
      id: c.id,
      title: c.title,
      subtitle: c.subtitle,
      badgeCount: c.badgeCount,
      kind: c.kind,
    })),
    [covenCapsules]
  );

  // Check for critical actions
  const hasCriticalActions = oracleItems.some((item) => item.priority === "critical");

  // Total badge counts
  const oracleBadgeCount = oracleItems.reduce((sum, item) => sum + (item.badgeCount || 0), 0) || oracleItems.length;
  const whisperBadgeCount = whisperItems.reduce((sum, item) => sum + (item.badgeCount || 0), 0) || whisperItems.length;
  const covenBadgeCount = covenItems.reduce((sum, item) => sum + (item.badgeCount || 0), 0) || covenItems.length;

  const handleDialToggle = useCallback((dial: "oracle" | "whisper" | "coven") => {
    setActiveDial((prev) => (prev === dial ? null : dial));
  }, []);

  const handleDialClose = useCallback(() => {
    setActiveDial(null);
  }, []);

  const handleDialSelect = useCallback((id: string) => {
    restoreCapsule(id);
    setActiveDial(null);
  }, [restoreCapsule]);

  const handleRestoreCapsule = useCallback(
    (id: string) => {
      restoreCapsule(id);
    },
    [restoreCapsule]
  );

  const handleCloseCapsule = useCallback(
    (id: string) => {
      closeCapsule(id);
    },
    [closeCapsule]
  );

  const hasSessions = sessions.length > 0;
  const hasCapsules = minimizedCapsules.length > 0;

  return (
    <nav
      className={`session-rail ${className ?? ""}`}
      aria-label="Session Rail"
    >
      {/* Agentic Controls (left side) - The Trinity with Dial Menus */}
      <div className="session-rail-agentic">
        <div className="agentic-dial-wrapper">
          <AgenticButton
            icon={<OracleIcon />}
            label="Oracle - Agent Decisions"
            variant="action"
            badgeCount={oracleBadgeCount > 0 ? oracleBadgeCount : undefined}
            hasCritical={hasCriticalActions}
            isActive={activeDial === "oracle"}
            onClick={() => handleDialToggle("oracle")}
          />
          <DialMenu
            isOpen={activeDial === "oracle"}
            variant="oracle"
            items={oracleItems}
            onClose={handleDialClose}
            onSelectItem={handleDialSelect}
          />
        </div>

        <div className="agentic-dial-wrapper">
          <AgenticButton
            icon={<WhisperIcon />}
            label="Whisper - Agent Channel"
            variant="chat"
            badgeCount={whisperBadgeCount > 0 ? whisperBadgeCount : undefined}
            isActive={activeDial === "whisper"}
            onClick={() => handleDialToggle("whisper")}
          />
          <DialMenu
            isOpen={activeDial === "whisper"}
            variant="whisper"
            items={whisperItems}
            onClose={handleDialClose}
            onSelectItem={handleDialSelect}
          />
        </div>

        <div className="agentic-dial-wrapper">
          <AgenticButton
            icon={<CovenIcon />}
            label="Coven - Agent Collective"
            variant="social"
            badgeCount={covenBadgeCount > 0 ? covenBadgeCount : undefined}
            isActive={activeDial === "coven"}
            onClick={() => handleDialToggle("coven")}
          />
          <DialMenu
            isOpen={activeDial === "coven"}
            variant="coven"
            items={covenItems}
            onClose={handleDialClose}
            onSelectItem={handleDialSelect}
          />
        </div>

        {/* Divider */}
        <div className="session-rail-divider-vertical" />
      </div>

      {/* Main dock area */}
      <div className="session-rail-dock">
        {/* Sessions */}
        <div className="session-rail-sessions">
          {sessions.map((session) => (
            <SessionPill
              key={session.id}
              session={session}
              onOpen={onOpenSession}
              onClose={onCloseSession}
            />
          ))}

          {!hasSessions && (
            <span className="session-rail-empty">No active sessions</span>
          )}
        </div>

        {/* Divider between sessions and capsules */}
        {hasSessions && hasCapsules && (
          <div className="session-rail-divider">
            <div className="session-rail-divider-line" />
          </div>
        )}

        {/* Minimized capsules */}
        <div className="session-rail-capsules">
          <AnimatePresence mode="popLayout">
            {minimizedCapsules.map((capsule) => (
              <CapsuleTab
                key={capsule.id}
                capsule={capsule}
                onRestore={handleRestoreCapsule}
                onClose={handleCloseCapsule}
              />
            ))}
          </AnimatePresence>
        </div>
      </div>

      {/* Status pod (right side) */}
      <div className={`session-rail-status-pod ${shelf.isOpen ? "shelf-open" : ""}`}>
        {/* Shelf mode indicator when open */}
        <AnimatePresence>
          {shelf.isOpen && shelf.mode && (
            <motion.div
              initial={{ opacity: 0, x: 8 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 8 }}
              transition={timing.fast}
              className="shelf-indicator"
            >
              <span className="shelf-indicator-label">
                {shelf.mode === "events" && "Chronicle"}
                {shelf.mode === "output" && "Echoes"}
                {shelf.mode === "artifacts" && "Relics"}
              </span>
              <button
                type="button"
                className="shelf-indicator-close"
                onClick={closeShelf}
                title="Close shelf"
              >
                <svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14">
                  <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" />
                </svg>
              </button>
              <div className="shelf-indicator-divider" />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Shelf buttons - The Archives */}
        <ShelfButton
          icon={<EventsIcon />}
          label="Chronicle - Event Stream"
          mode="events"
          badgeCount={eventsCount}
          isActive={shelf.isOpen && shelf.mode === "events"}
          onClick={() => toggleShelf("events")}
        />

        <ShelfButton
          icon={<OutputIcon />}
          label="Echoes - Output Log"
          mode="output"
          isActive={shelf.isOpen && shelf.mode === "output"}
          onClick={() => toggleShelf("output")}
        />

        <ShelfButton
          icon={<ArtifactsIcon />}
          label="Relics - Artifacts"
          mode="artifacts"
          isActive={shelf.isOpen && shelf.mode === "artifacts"}
          onClick={() => toggleShelf("artifacts")}
        />
      </div>
    </nav>
  );
}

export default SessionRail;
