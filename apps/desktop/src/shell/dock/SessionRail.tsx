/**
 * SessionRail - Bottom activity bar
 *
 * Shows active sessions (runs, builds, terminals) and minimized capsules.
 * Provides quick access to notifications and shelf panels.
 * Includes dial menus for Commands, Whisper channels, and Coven capsules.
 */

import { AnimatePresence, motion } from "motion/react";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useOpenClaw } from "@/context/OpenClawContext";
import { isTauri, openclawGatewayProbe } from "@/services/tauri";
import {
  dispatchShellExecuteHotCommand,
  dispatchShellFocusAgentSession,
  dispatchShellOpenCommandPalette,
} from "../events";
import { CapsuleTab } from "./Capsule";
import { useDock } from "./DockContext";
import {
  type HotCommand,
  type HotCommandScope,
  loadHotCommands,
  markHotCommandUsed,
  removeHotCommand,
  resolveHotCommandAction,
  saveHotCommands,
  sortHotCommands,
  upsertHotCommand,
} from "./hotCommands";
import type { CapsuleKind, SessionItem, ShelfMode } from "./types";

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
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      width="16"
      height="16"
    >
      <path d="M12 5C7 5 2.73 8.11 1 12c1.73 3.89 6 7 11 7s9.27-3.11 11-7c-1.73-3.89-6-7-11-7z" />
      <circle cx="12" cy="12" r="3" />
      <circle cx="12" cy="12" r="1" fill="currentColor" />
    </svg>
  );
}

/** Whisper - Speech rune for agent communication */
function WhisperIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      width="16"
      height="16"
    >
      <path d="M21 12c0 4.418-4.03 8-9 8-1.6 0-3.11-.36-4.41-1L3 21l1.5-4.5C3.56 15.18 3 13.64 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
      <path d="M9 10h6M9 14h4" />
    </svg>
  );
}

/** Coven - Connected nodes for agent collective */
function CovenIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      width="16"
      height="16"
    >
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
      <button type="button" className="session-pill-main" onClick={() => onOpen?.(session.id)}>
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

function ShelfButton({
  icon,
  label,
  mode: _mode,
  badgeCount,
  isActive,
  onClick,
}: ShelfButtonProps) {
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
        <span className="shelf-button-badge">{badgeCount > 9 ? "9+" : badgeCount}</span>
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

function AgenticButton({
  icon,
  label,
  variant,
  badgeCount,
  isActive,
  hasCritical,
  onClick,
}: AgenticButtonProps) {
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
  variant: "whisper" | "coven";
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
                <span
                  className={`dial-item-badge ${item.priority === "critical" ? "critical" : ""}`}
                >
                  {item.badgeCount}
                </span>
              )}
              <span className="dial-item-arrow">
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 16 16"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
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

interface CommandsDialMenuProps {
  isOpen: boolean;
  commands: HotCommand[];
  feedbackMessage: string | null;
  onClose: () => void;
  onExecuteCommand: (command: HotCommand) => void;
  onSaveCommand: (input: {
    id?: string;
    title: string;
    description?: string;
    command: string;
    scope: HotCommandScope;
    pinned: boolean;
  }) => void;
  onDeleteCommand: (id: string) => void;
  onTogglePinned: (command: HotCommand) => void;
}

function CommandsDialMenu({
  isOpen,
  commands,
  feedbackMessage,
  onClose,
  onExecuteCommand,
  onSaveCommand,
  onDeleteCommand,
  onTogglePinned,
}: CommandsDialMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const [showComposer, setShowComposer] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [command, setCommand] = useState("");
  const [scope, setScope] = useState<HotCommandScope>("global");
  const [pinned, setPinned] = useState(false);

  const resetComposer = useCallback(() => {
    setEditingId(null);
    setTitle("");
    setDescription("");
    setCommand("");
    setScope("global");
    setPinned(false);
    setShowComposer(false);
  }, []);

  const beginCreate = useCallback(() => {
    setEditingId(null);
    setTitle("");
    setDescription("");
    setCommand("");
    setScope("global");
    setPinned(false);
    setShowComposer(true);
  }, []);

  const beginEdit = useCallback((entry: HotCommand) => {
    setEditingId(entry.id);
    setTitle(entry.title);
    setDescription(entry.description ?? "");
    setCommand(entry.command);
    setScope(entry.scope);
    setPinned(entry.pinned);
    setShowComposer(true);
  }, []);

  useEffect(() => {
    if (!isOpen) {
      resetComposer();
      return;
    }
    const handleClickOutside = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) {
        const target = event.target as HTMLElement;
        if (!target.closest(".agentic-button")) {
          onClose();
        }
      }
    };
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
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
  }, [isOpen, onClose, resetComposer]);

  if (!isOpen) return null;

  return (
    <div ref={menuRef} className="dial-menu dial-menu-oracle">
      <div className="dial-menu-header">
        <span className="dial-menu-icon">
          <OracleIcon />
        </span>
        <span className="dial-menu-title">Commands</span>
        {commands.length > 0 ? <span className="dial-menu-count">{commands.length}</span> : null}
        <button
          type="button"
          className="dial-command-add"
          onClick={() => (showComposer ? resetComposer() : beginCreate())}
        >
          {showComposer ? "Cancel" : "Add"}
        </button>
      </div>

      {feedbackMessage ? <div className="dial-command-feedback">{feedbackMessage}</div> : null}

      {showComposer ? (
        <form
          className="dial-command-composer"
          onSubmit={(event) => {
            event.preventDefault();
            onSaveCommand({
              id: editingId ?? undefined,
              title,
              description,
              command,
              scope,
              pinned,
            });
            resetComposer();
          }}
        >
          <input
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            placeholder="Command title"
            className="dial-command-input"
          />
          <input
            value={command}
            onChange={(event) => setCommand(event.target.value)}
            placeholder="Route or keyword (example: /operations?tab=fleet)"
            className="dial-command-input"
          />
          <input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Description (optional)"
            className="dial-command-input"
          />
          <div className="dial-command-controls">
            <div className="dial-command-scope" role="group" aria-label="Command scope">
              {(["global", "nexus", "operations"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => setScope(option)}
                  className={`dial-command-scope-option ${scope === option ? "active" : ""}`}
                >
                  {option}
                </button>
              ))}
            </div>
            <label className="dial-command-checkbox">
              <input
                type="checkbox"
                checked={pinned}
                onChange={(event) => setPinned(event.target.checked)}
              />
              Pin
            </label>
            <button type="submit" className="dial-command-submit">
              {editingId ? "Update" : "Save"}
            </button>
          </div>
        </form>
      ) : null}

      <div className="dial-menu-items">
        {commands.length === 0 ? (
          <div className="dial-menu-empty">No commands configured</div>
        ) : (
          commands.map((entry) => (
            <div key={entry.id} className="dial-command-row">
              <div className="dial-command-row-main">
                <button
                  type="button"
                  className="dial-command-launch"
                  onClick={() => onExecuteCommand(entry)}
                >
                  <div className="dial-item-content">
                    <span className="dial-item-title">{entry.title}</span>
                    <span className="dial-item-subtitle">{entry.command}</span>
                    {entry.description ? (
                      <span className="dial-command-description">{entry.description}</span>
                    ) : null}
                  </div>
                </button>
                <div className="dial-command-row-meta">
                  <span className="dial-item-badge">{entry.scope}</span>
                  {entry.pinned ? <span className="dial-command-pin-flag">Pinned</span> : null}
                </div>
                <div className="dial-command-row-actions">
                  <button
                    type="button"
                    className="dial-command-action"
                    onClick={() => beginEdit(entry)}
                    title={`Edit ${entry.title}`}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="dial-command-action"
                    onClick={() => onTogglePinned(entry)}
                    title={entry.pinned ? `Unpin ${entry.title}` : `Pin ${entry.title}`}
                  >
                    {entry.pinned ? "Unpin" : "Pin"}
                  </button>
                  <button
                    type="button"
                    className="dial-command-action dial-command-action--danger"
                    onClick={() => onDeleteCommand(entry.id)}
                    title={`Delete ${entry.title}`}
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

type OpenClawSessionListResponse = {
  sessions?: Array<{
    key?: string;
    displayName?: string;
    updatedAt?: number;
    status?: string;
  }>;
};

type ProbeCovenEntry = {
  id: string;
  title: string;
  subtitle: string;
};

function normalizeSessionLabel(sessionKey: string, fallback?: string): string {
  if (fallback && fallback.trim()) return fallback.trim();
  const match = /^agent:([^:]+):/.exec(sessionKey);
  if (match?.[1]) return `Agent ${match[1]}`;
  return sessionKey.replace(/^agent:/, "");
}

function parseAgentIdFromSessionKey(sessionKey: string): string | null {
  const match = /^agent:([^:]+):/.exec(sessionKey);
  return match?.[1] ?? null;
}

function extractOpenClawSessionKey(id: string): string | null {
  let value = id;
  if (value.startsWith("openclaw:session:")) value = value.slice("openclaw:session:".length);
  if (value.startsWith("openclaw:probe:")) return value.slice("openclaw:probe:".length) || null;
  if (!value.startsWith("openclaw:")) return null;
  const key = value.slice("openclaw:".length);
  if (!key) return null;
  if (key.startsWith("node:") || key.startsWith("presence:") || key.startsWith("approval:"))
    return null;
  return key;
}

function normalizeNodeLabel(input: unknown): string {
  if (typeof input === "string" && input.trim()) return input.trim();
  return "Node";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object") return null;
  return value as Record<string, unknown>;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function parseProbeSessions(payload: unknown): {
  sessions: SessionItem[];
  coven: ProbeCovenEntry[];
} {
  const root = asRecord(payload);
  if (!root) return { sessions: [], coven: [] };

  const sessionMap = new Map<string, { item: SessionItem; updatedAt: number }>();
  const covenByAgent = new Map<string, number>();

  const registerCoven = (agentIdInput: unknown, countHint?: number) => {
    const agentId = normalizeNodeLabel(agentIdInput);
    const existing = covenByAgent.get(agentId) ?? 0;
    if (typeof countHint === "number" && Number.isFinite(countHint)) {
      covenByAgent.set(agentId, Math.max(existing, Math.max(0, Math.floor(countHint))));
      return;
    }
    covenByAgent.set(agentId, existing + 1);
  };

  const upsertSession = (row: Record<string, unknown>, agentHint?: string) => {
    const rowAgentId =
      typeof row.agentId === "string"
        ? row.agentId
        : typeof row.agent_id === "string"
          ? row.agent_id
          : undefined;
    const fallbackAgentId = normalizeNodeLabel(rowAgentId ?? agentHint ?? "unknown");
    const sessionId =
      typeof row.sessionId === "string"
        ? row.sessionId
        : typeof row.session_id === "string"
          ? row.session_id
          : undefined;
    const key =
      typeof row.key === "string"
        ? row.key
        : typeof row.sessionKey === "string"
          ? row.sessionKey
          : typeof row.session_key === "string"
            ? row.session_key
            : sessionId
              ? `agent:${fallbackAgentId}:session:${sessionId}`
              : "";
    if (!key) return;

    const updatedAt =
      asNumber(row.updatedAt) ?? asNumber(row.updated_at) ?? asNumber(row.ts) ?? Date.now();
    const ageMs = asNumber(row.age) ?? Math.max(0, Date.now() - updatedAt);
    const existing = sessionMap.get(key);
    if (existing && existing.updatedAt >= updatedAt) return;

    const displayName =
      typeof row.displayName === "string"
        ? row.displayName
        : typeof row.title === "string"
          ? row.title
          : undefined;
    const status: SessionItem["status"] = ageMs < 30 * 60_000 ? "running" : "idle";
    sessionMap.set(key, {
      updatedAt,
      item: {
        id: `openclaw:probe:${key}`,
        kind: "run",
        title: normalizeSessionLabel(key, displayName),
        status,
        route: "/nexus",
      },
    });

    const parsedAgent = /^agent:([^:]+):/.exec(key)?.[1];
    registerCoven(rowAgentId ?? agentHint ?? parsedAgent);
  };

  const ingestRecentRows = (value: unknown, agentHint?: string) => {
    const rows = Array.isArray(value) ? value : [];
    rows.forEach((row) => {
      const rec = asRecord(row);
      if (!rec) return;
      upsertSession(rec, agentHint);
    });
  };

  const ingestProbeScope = (scope: Record<string, unknown>) => {
    const sessionsRecord = asRecord(scope.sessions);
    ingestRecentRows(sessionsRecord?.recent);

    const summaryRecord = asRecord(scope.summary);
    const summarySessions = asRecord(summaryRecord?.sessions);
    ingestRecentRows(summarySessions?.recent);

    const agents = Array.isArray(scope.agents) ? scope.agents : [];
    agents.forEach((agent, agentIndex) => {
      const rec = asRecord(agent);
      if (!rec) return;
      const agentId = normalizeNodeLabel(rec.agentId ?? rec.name ?? `agent-${agentIndex + 1}`);
      const agentSessions = asRecord(rec.sessions);
      const recentRows = Array.isArray(agentSessions?.recent) ? agentSessions.recent : [];
      const total = asNumber(agentSessions?.count) ?? recentRows.length;
      registerCoven(agentId, total ?? undefined);
      ingestRecentRows(recentRows, agentId);
    });

    const summaryAgents = Array.isArray(summaryRecord?.agents) ? summaryRecord?.agents : [];
    summaryAgents.forEach((agent) => {
      const rec = asRecord(agent);
      if (!rec) return;
      const agentId = normalizeNodeLabel(rec.agentId ?? rec.name);
      const total = asNumber(rec.count) ?? asNumber(rec.sessions);
      registerCoven(agentId, total ?? undefined);
    });
  };

  const targets = Array.isArray(root.targets) ? root.targets : [];
  const activeScopes: Record<string, unknown>[] = [];
  const passiveScopes: Record<string, unknown>[] = [];

  targets.forEach((target) => {
    const rec = asRecord(target);
    if (!rec) return;
    const bucket = rec.active === true ? activeScopes : passiveScopes;
    const health = asRecord(rec.health);
    const summary = asRecord(rec.summary);
    if (health) bucket.push(health);
    if (summary) bucket.push(summary);
  });

  const rootHealth = asRecord(root.health);
  const rootSummary = asRecord(root.summary);
  const scopes = [
    ...activeScopes,
    ...(rootHealth ? [rootHealth] : []),
    ...(rootSummary ? [rootSummary] : []),
    ...passiveScopes,
  ];

  scopes.forEach((scope) => ingestProbeScope(scope));

  const sessions = Array.from(sessionMap.values())
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map((entry) => entry.item)
    .slice(0, 8);

  const coven = Array.from(covenByAgent.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([agentId, count], index) => ({
      id: `openclaw:probe-agent:${agentId}:${index}`,
      title: agentId,
      subtitle: `${count} session${count === 1 ? "" : "s"} tracked`,
    }))
    .slice(0, 24);

  return { sessions, coven };
}

function buildRuntimeFallbackSessions(
  runtime:
    | {
        nodes?: Array<{ nodeId?: string; displayName?: string; connected?: boolean }>;
        presence?: unknown[];
        execApprovalQueue?: Array<{ id: string; request: { command: string } }>;
      }
    | null
    | undefined,
): SessionItem[] {
  const sessions: SessionItem[] = [];

  const connectedNodes = (runtime?.nodes ?? [])
    .filter((node) => node.connected !== false)
    .slice(0, 5);
  for (const node of connectedNodes) {
    const nodeId = typeof node.nodeId === "string" ? node.nodeId : "";
    if (!nodeId) continue;
    sessions.push({
      id: `openclaw:node:${nodeId}`,
      kind: "run",
      title: `Node · ${normalizeNodeLabel(node.displayName ?? node.nodeId)}`,
      status: "running",
      route: "/operations?tab=fleet",
    });
  }

  const presenceRows = Array.isArray(runtime?.presence) ? runtime.presence : [];
  for (let i = 0; i < presenceRows.length && sessions.length < 7; i++) {
    const rec = asRecord(presenceRows[i]);
    const source = rec?.client ?? rec?.id ?? rec?.session_key ?? rec?.sessionKey;
    const label = normalizeNodeLabel(source);
    sessions.push({
      id: `openclaw:presence:${i}:${label}`,
      kind: "run",
      title: `Presence · ${label}`,
      status: "running",
      route: "/operations?tab=fleet",
    });
  }

  const approvals = runtime?.execApprovalQueue ?? [];
  if (approvals.length > 0 && sessions.length < 8) {
    const approval = approvals[0];
    sessions.push({
      id: `openclaw:approval:${approval.id}`,
      kind: "run",
      title: `Approval · ${normalizeNodeLabel(approval.request.command)}`,
      status: "error",
      route: "/operations?tab=fleet",
    });
  }

  return sessions.slice(0, 8);
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
  const oc = useOpenClaw();
  const tauriAvailable = isTauri();
  const runtime = oc.runtimeByGatewayId[oc.activeGatewayId];
  const {
    sessions: dockSessions,
    capsules,
    minimizedCapsules,
    shelf,
    openShelf,
    restoreCapsule,
    closeCapsule,
    closeShelf,
  } = useDock();

  const [activeDial, setActiveDial] = useState<"oracle" | "whisper" | "coven" | null>(null);
  const [hotCommands, setHotCommands] = useState<HotCommand[]>(() => loadHotCommands());
  const [commandFeedback, setCommandFeedback] = useState<string | null>(null);
  const [liveSessions, setLiveSessions] = useState<SessionItem[]>([]);
  const [probeSessions, setProbeSessions] = useState<SessionItem[]>([]);
  const [probeCovenEntries, setProbeCovenEntries] = useState<ProbeCovenEntry[]>([]);

  useEffect(() => {
    saveHotCommands(hotCommands);
  }, [hotCommands]);

  useEffect(() => {
    if (activeDial !== "oracle") return;
    setHotCommands(loadHotCommands());
  }, [activeDial]);

  useEffect(() => {
    if (runtime?.status !== "connected") {
      setLiveSessions([]);
      return;
    }

    const fallbackSessions = buildRuntimeFallbackSessions(runtime);
    let cancelled = false;
    let inFlight = false;
    let sessionsMethodUnsupported = false;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      try {
        if (sessionsMethodUnsupported) {
          if (!cancelled) setLiveSessions(fallbackSessions);
          return;
        }

        const response = await oc.request<OpenClawSessionListResponse>("sessions.list");
        const rows = Array.isArray(response.sessions) ? response.sessions : [];
        const mapped = rows
          .reduce<SessionItem[]>((acc, session) => {
            const key = typeof session.key === "string" ? session.key : "";
            if (!key) return acc;

            const statusRaw =
              typeof session.status === "string" ? session.status.toLowerCase() : "running";
            const status: SessionItem["status"] =
              statusRaw === "error"
                ? "error"
                : statusRaw === "completed" || statusRaw === "success"
                  ? "success"
                  : "running";

            acc.push({
              id: `openclaw:${key}`,
              kind: "run",
              title: normalizeSessionLabel(key, session.displayName),
              status,
              route: "/nexus",
            });

            return acc;
          }, [])
          .slice(0, 8);

        if (!cancelled) setLiveSessions(mapped.length > 0 ? mapped : fallbackSessions);
      } catch (error) {
        const message = error instanceof Error ? error.message.toLowerCase() : "";
        if (message.includes("unknown method") || message.includes("method not found")) {
          sessionsMethodUnsupported = true;
        }
        if (!cancelled) setLiveSessions(fallbackSessions);
      } finally {
        inFlight = false;
      }
    }

    void tick();
    const timer = window.setInterval(() => void tick(), 7000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [oc, runtime]);

  useEffect(() => {
    if (!tauriAvailable) return;

    let cancelled = false;
    let inFlight = false;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      try {
        const probe = await openclawGatewayProbe(2400);
        const parsed = parseProbeSessions(probe);
        if (!cancelled) {
          setProbeSessions(parsed.sessions);
          setProbeCovenEntries(parsed.coven);
        }
      } catch {
        if (!cancelled && runtime?.status !== "connected") {
          setProbeSessions([]);
          setProbeCovenEntries([]);
        }
      } finally {
        inFlight = false;
      }
    }

    void tick();
    const timer = window.setInterval(() => void tick(), 18_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [liveSessions.length, runtime?.status, tauriAvailable]);

  // Get capsules by type for dial menus
  const whisperCapsules = useMemo(() => capsules.filter((c) => c.kind === "chat"), [capsules]);

  const covenCapsules = useMemo(() => capsules.filter((c) => c.kind === "social"), [capsules]);

  // Convert capsules to dial menu items (fallback when OpenClaw is disconnected)
  const whisperCapsuleItems: DialMenuItem[] = useMemo(
    () =>
      whisperCapsules.map((c) => ({
        id: c.id,
        title: c.title,
        subtitle: c.subtitle,
        badgeCount: c.badgeCount,
        kind: c.kind,
      })),
    [whisperCapsules],
  );

  const covenCapsuleItems: DialMenuItem[] = useMemo(
    () =>
      covenCapsules.map((c) => ({
        id: c.id,
        title: c.title,
        subtitle: c.subtitle,
        badgeCount: c.badgeCount,
        kind: c.kind,
      })),
    [covenCapsules],
  );

  const sessionSource = liveSessions.length > 0 ? liveSessions : probeSessions;

  const whisperLiveItems: DialMenuItem[] = useMemo(
    () =>
      sessionSource.map((session) => ({
        id: `openclaw:session:${session.id}`,
        title: session.title,
        subtitle: "Active daemon session",
        badgeCount: session.status === "error" ? 1 : 0,
        priority: session.status === "error" ? "critical" : "normal",
        kind: "chat",
      })),
    [sessionSource],
  );

  const covenLiveItems: DialMenuItem[] = useMemo(() => {
    const nodes = (runtime?.nodes ?? []).filter((node) => node.connected !== false);
    if (nodes.length > 0) {
      return nodes.slice(0, 24).map((node, index) => {
        const nodeId = typeof node.nodeId === "string" ? node.nodeId : `node-${index}`;
        const label = normalizeNodeLabel(node.displayName ?? node.nodeId);
        const detailParts = [node.platform, node.version].filter(
          (value): value is string => typeof value === "string" && value.trim().length > 0,
        );
        return {
          id: `openclaw:node:${nodeId}`,
          title: label,
          subtitle: detailParts.length > 0 ? detailParts.join(" · ") : "Connected node",
          kind: "social" as const,
        };
      });
    }

    if (probeCovenEntries.length > 0) {
      return probeCovenEntries.map((entry) => ({
        id: entry.id,
        title: entry.title,
        subtitle: entry.subtitle,
        kind: "social" as const,
      }));
    }

    const presenceRows = Array.isArray(runtime?.presence) ? runtime?.presence : [];
    return presenceRows.slice(0, 24).map((row, index) => ({
      id: `openclaw:presence:${index}`,
      title: normalizeNodeLabel(
        (row as Record<string, unknown>)?.client ?? (row as Record<string, unknown>)?.id,
      ),
      subtitle: "Presence heartbeat",
      kind: "social" as const,
    }));
  }, [probeCovenEntries, runtime?.nodes, runtime?.presence]);

  const whisperItems = whisperLiveItems.length > 0 ? whisperLiveItems : whisperCapsuleItems;
  const covenItems = covenLiveItems.length > 0 ? covenLiveItems : covenCapsuleItems;
  const visibleSessions =
    liveSessions.length > 0
      ? liveSessions
      : probeSessions.length > 0
        ? probeSessions
        : dockSessions;

  // Total badge counts
  const oracleBadgeCount = hotCommands.length;
  const whisperBadgeCount =
    whisperItems.reduce((sum, item) => sum + (item.badgeCount || 0), 0) || whisperItems.length;
  const covenBadgeCount =
    covenItems.reduce((sum, item) => sum + (item.badgeCount || 0), 0) || covenItems.length;

  const handleDialToggle = useCallback((dial: "oracle" | "whisper" | "coven") => {
    setActiveDial((prev) => (prev === dial ? null : dial));
  }, []);

  const handleDialClose = useCallback(() => {
    setActiveDial(null);
  }, []);

  const handleDialSelect = useCallback(
    (id: string) => {
      const sessionKey = extractOpenClawSessionKey(id);
      if (sessionKey) {
        dispatchShellFocusAgentSession({
          sessionKey,
          agentId: parseAgentIdFromSessionKey(sessionKey) ?? undefined,
        });
      }
      if (id.startsWith("openclaw:session:")) {
        window.location.hash = "#/nexus";
        setActiveDial(null);
        return;
      }
      if (id.startsWith("openclaw:probe-agent:")) {
        window.location.hash = "#/nexus";
        setActiveDial(null);
        return;
      }
      if (
        id.startsWith("openclaw:node:") ||
        id.startsWith("openclaw:presence:") ||
        id.startsWith("openclaw:approval:")
      ) {
        window.location.hash = "#/operations?tab=fleet";
        setActiveDial(null);
        return;
      }
      restoreCapsule(id);
      setActiveDial(null);
    },
    [restoreCapsule],
  );

  const handleExecuteHotCommand = useCallback((command: HotCommand) => {
    const action = resolveHotCommandAction(command.command);
    if (action.kind === "invalid") {
      setCommandFeedback(action.reason);
      return;
    }

    if (action.kind === "navigate") {
      window.location.hash = `#${action.path}`;
      setCommandFeedback(`Navigated to ${action.path}`);
    } else if (action.kind === "palette") {
      dispatchShellOpenCommandPalette();
      setCommandFeedback("Opened command palette");
    } else {
      dispatchShellExecuteHotCommand({ id: command.id, payload: action.payload });
      setCommandFeedback(`Dispatched: ${action.payload}`);
    }

    setHotCommands((previous) => markHotCommandUsed(previous, command.id));
    window.setTimeout(() => setCommandFeedback(null), 1200);
  }, []);

  const handleSaveHotCommand = useCallback(
    (input: {
      id?: string;
      title: string;
      description?: string;
      command: string;
      scope: HotCommandScope;
      pinned: boolean;
    }) => {
      setHotCommands((previous) => upsertHotCommand(previous, input));
      setCommandFeedback(input.id ? "Command updated" : "Command saved");
      window.setTimeout(() => setCommandFeedback(null), 1200);
    },
    [],
  );

  const handleDeleteHotCommand = useCallback((id: string) => {
    setHotCommands((previous) => removeHotCommand(previous, id));
    setCommandFeedback("Command removed");
    window.setTimeout(() => setCommandFeedback(null), 1200);
  }, []);

  const handleTogglePinned = useCallback((entry: HotCommand) => {
    setHotCommands((previous) =>
      sortHotCommands(
        previous.map((candidate) =>
          candidate.id === entry.id
            ? { ...candidate, pinned: !candidate.pinned, updatedAt: Date.now() }
            : candidate,
        ),
      ),
    );
  }, []);

  const handleRestoreCapsule = useCallback(
    (id: string) => {
      restoreCapsule(id);
    },
    [restoreCapsule],
  );

  const handleCloseCapsule = useCallback(
    (id: string) => {
      closeCapsule(id);
    },
    [closeCapsule],
  );

  const handleToggleShelf = useCallback(
    (mode: ShelfMode) => {
      setActiveDial(null);
      if (shelf.isOpen && shelf.mode === mode) {
        closeShelf();
        return;
      }
      openShelf(mode);
    },
    [closeShelf, openShelf, shelf.isOpen, shelf.mode],
  );

  const handleOpenSessionPill = useCallback(
    (id: string) => {
      const sessionKey = extractOpenClawSessionKey(id);
      if (sessionKey) {
        dispatchShellFocusAgentSession({
          sessionKey,
          agentId: parseAgentIdFromSessionKey(sessionKey) ?? undefined,
        });
      }
      if (
        id.startsWith("openclaw:node:") ||
        id.startsWith("openclaw:presence:") ||
        id.startsWith("openclaw:approval:")
      ) {
        window.location.hash = "#/operations?tab=fleet";
        return;
      }
      if (id.startsWith("openclaw:")) {
        window.location.hash = "#/nexus";
        return;
      }
      onOpenSession?.(id);
    },
    [onOpenSession],
  );

  const handleCloseSessionPill = useCallback(
    (id: string) => {
      if (id.startsWith("openclaw:")) return;
      onCloseSession?.(id);
    },
    [onCloseSession],
  );

  const hasSessions = visibleSessions.length > 0;
  const hasCapsules = minimizedCapsules.length > 0;

  return (
    <nav className={`session-rail ${className ?? ""}`} aria-label="Session Rail">
      {/* Agentic Controls (left side) - The Trinity with Dial Menus */}
      <div className="session-rail-agentic">
        <div className="agentic-dial-wrapper">
          <AgenticButton
            icon={<OracleIcon />}
            label="Commands - Hot command launcher"
            variant="action"
            badgeCount={oracleBadgeCount > 0 ? oracleBadgeCount : undefined}
            isActive={activeDial === "oracle"}
            onClick={() => handleDialToggle("oracle")}
          />
          <CommandsDialMenu
            isOpen={activeDial === "oracle"}
            commands={hotCommands}
            feedbackMessage={commandFeedback}
            onClose={handleDialClose}
            onExecuteCommand={handleExecuteHotCommand}
            onSaveCommand={handleSaveHotCommand}
            onDeleteCommand={handleDeleteHotCommand}
            onTogglePinned={handleTogglePinned}
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
          {visibleSessions.map((session) => (
            <SessionPill
              key={session.id}
              session={session}
              onOpen={handleOpenSessionPill}
              onClose={handleCloseSessionPill}
            />
          ))}

          {!hasSessions && <span className="session-rail-empty">No active sessions</span>}
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
                {shelf.mode === "events" && "Policy Workbench"}
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
          label="Policy Workbench"
          mode="events"
          badgeCount={eventsCount}
          isActive={shelf.isOpen && shelf.mode === "events"}
          onClick={() => handleToggleShelf("events")}
        />

        <ShelfButton
          icon={<OutputIcon />}
          label="Echoes - Output Log"
          mode="output"
          isActive={shelf.isOpen && shelf.mode === "output"}
          onClick={() => handleToggleShelf("output")}
        />

        <ShelfButton
          icon={<ArtifactsIcon />}
          label="Relics - Artifacts"
          mode="artifacts"
          isActive={shelf.isOpen && shelf.mode === "artifacts"}
          onClick={() => handleToggleShelf("artifacts")}
        />
      </div>
    </nav>
  );
}

export default SessionRail;
