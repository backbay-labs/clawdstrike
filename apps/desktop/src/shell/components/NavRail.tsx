/**
 * NavRail - Left sidebar navigation for SDR views
 */
import { clsx } from "clsx";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { GlitchText } from "@backbay/glia/primitives";
import type { AppId, PluginIcon } from "../plugins/types";
import { getPlugins } from "../plugins";
import {
  useSessions,
  useActiveSession,
  useSessionActions,
  useActiveApp,
} from "../sessions";
import type { Session } from "../sessions";

interface NavRailProps {
  activeAppId: AppId;
  onSelectApp: (appId: AppId) => void;
}

export function NavRail({ activeAppId, onSelectApp }: NavRailProps) {
  const plugins = getPlugins();
  const navigate = useNavigate();
  const sessions = useSessions({ archived: false });
  const activeSession = useActiveSession();
  const currentAppId = useActiveApp();
  const { createSession, setActiveSession, togglePin, archiveSession, deleteSession } =
    useSessionActions();

  const [sessionsExpanded, setSessionsExpanded] = useState(false);

  const handleSessionClick = useCallback(
    (session: Session) => {
      setActiveSession(session.id);
      navigate(`/${session.appId}/${session.id}`);
    },
    [setActiveSession, navigate]
  );

  const handleNewSession = useCallback(() => {
    const appId = currentAppId ?? activeAppId;
    const session = createSession(appId);
    navigate(`/${appId}/${session.id}`);
  }, [currentAppId, activeAppId, createSession, navigate]);

  return (
    <nav className="relative z-10 flex flex-col w-16 h-full bg-sdr-bg-secondary border-r border-sdr-border py-4">
      {/* App navigation */}
      <div className="flex flex-col gap-1 px-2">
        {plugins.map((plugin) => (
          <NavButton
            key={plugin.id}
            icon={plugin.icon}
            label={plugin.name}
            active={activeAppId === plugin.id}
            onClick={() => onSelectApp(plugin.id)}
          />
        ))}
      </div>

      <div className="flex-1" />

      {/* Sessions section */}
      <div className="px-2 mb-2">
        {/* Sessions toggle */}
        <button
          onClick={() => setSessionsExpanded(!sessionsExpanded)}
          title="Sessions"
          className={clsx(
            "flex items-center justify-center w-12 h-8 rounded-lg transition-colors mb-1",
            sessionsExpanded
              ? "bg-sdr-accent-blue/20 text-sdr-accent-blue"
              : "text-sdr-text-secondary hover:bg-sdr-bg-tertiary hover:text-sdr-text-primary"
          )}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
            <rect
              x="3"
              y="3"
              width="18"
              height="7"
              rx="2"
              stroke="currentColor"
              strokeWidth="2"
              fill="none"
            />
            <rect
              x="3"
              y="14"
              width="18"
              height="7"
              rx="2"
              stroke="currentColor"
              strokeWidth="2"
              fill="none"
            />
          </svg>
        </button>

        {/* Session pills */}
        {sessionsExpanded && (
          <div className="flex flex-col gap-1 max-h-40 overflow-y-auto">
            {sessions.map((session) => (
              <SessionPill
                key={session.id}
                session={session}
                isActive={activeSession?.id === session.id}
                onClick={() => handleSessionClick(session)}
                onPin={() => togglePin(session.id)}
                onArchive={() => archiveSession(session.id)}
                onDelete={() => deleteSession(session.id)}
              />
            ))}

            {/* New session button */}
            <button
              onClick={handleNewSession}
              title="New Session"
              className="flex items-center justify-center w-12 h-8 rounded-lg text-sdr-text-muted hover:bg-sdr-bg-tertiary hover:text-sdr-text-primary transition-colors"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 5v14M5 12h14"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
              </svg>
            </button>
          </div>
        )}
      </div>

      {/* Connection status indicator */}
      <div className="px-2">
        <div className="flex items-center justify-center w-12 h-12 rounded-lg">
          <ConnectionIndicator />
        </div>
      </div>
    </nav>
  );
}

interface SessionPillProps {
  session: Session;
  isActive: boolean;
  onClick: () => void;
  onPin: () => void;
  onArchive: () => void;
  onDelete: () => void;
}

function SessionPill({ session, isActive, onClick, onPin, onArchive, onDelete }: SessionPillProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [menuOpen]);

  const handleContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    setMenuOpen(true);
  };

  const initial = session.title.charAt(0).toUpperCase();
  const statusColor =
    session.status === "running"
      ? "bg-sdr-accent-green"
      : session.status === "error"
        ? "bg-sdr-accent-red"
        : "bg-sdr-text-muted";

  return (
    <div className="relative">
      <button
        onClick={onClick}
        onContextMenu={handleContextMenu}
        title={session.title}
        className={clsx(
          "flex items-center justify-center w-12 h-8 rounded-lg transition-colors relative",
          isActive
            ? "bg-sdr-accent-blue/20 text-sdr-accent-blue"
            : "text-sdr-text-secondary hover:bg-sdr-bg-tertiary hover:text-sdr-text-primary"
        )}
      >
        <span className="text-xs font-mono font-semibold">{initial}</span>
        {/* Status dot */}
        <span
          className={clsx("absolute top-1 right-1 w-1.5 h-1.5 rounded-full", statusColor)}
        />
        {/* Pin indicator */}
        {session.pinned && (
          <span className="absolute top-1 left-1 w-1.5 h-1.5 text-sdr-accent-amber">
            <svg width="6" height="6" viewBox="0 0 24 24" fill="currentColor">
              <circle cx="12" cy="12" r="10" />
            </svg>
          </span>
        )}
      </button>

      {/* Context menu */}
      {menuOpen && (
        <div
          ref={menuRef}
          className="absolute left-14 top-0 z-50 min-w-[120px] py-1 bg-sdr-bg-tertiary border border-sdr-border rounded-lg shadow-lg"
        >
          <ContextMenuItem
            label={session.pinned ? "Unpin" : "Pin"}
            onClick={() => {
              onPin();
              setMenuOpen(false);
            }}
          />
          <ContextMenuItem
            label="Archive"
            onClick={() => {
              onArchive();
              setMenuOpen(false);
            }}
          />
          <ContextMenuItem
            label="Delete"
            destructive
            onClick={() => {
              onDelete();
              setMenuOpen(false);
            }}
          />
        </div>
      )}
    </div>
  );
}

function ContextMenuItem({
  label,
  destructive,
  onClick,
}: {
  label: string;
  destructive?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "block w-full text-left px-3 py-1.5 text-xs transition-colors",
        destructive
          ? "text-sdr-accent-red hover:bg-sdr-accent-red/10"
          : "text-sdr-text-secondary hover:bg-sdr-bg-secondary hover:text-sdr-text-primary"
      )}
    >
      {label}
    </button>
  );
}

interface NavButtonProps {
  icon: PluginIcon;
  label: string;
  active: boolean;
  onClick: () => void;
}

function NavButton({ icon, label, active, onClick }: NavButtonProps) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={clsx(
        "flex items-center justify-center w-12 h-12 rounded-lg transition-colors",
        active
          ? "bg-sdr-accent-blue/20 text-sdr-accent-blue"
          : "text-sdr-text-secondary hover:bg-sdr-bg-tertiary hover:text-sdr-text-primary"
      )}
    >
      <NavIcon icon={icon} />
    </button>
  );
}

function NavIcon({ icon }: { icon: PluginIcon }) {
  const paths: Record<PluginIcon, ReactNode> = {
    activity: (
      <path
        d="M22 12h-4l-3 9L9 3l-3 9H2"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    ),
    shield: (
      <path
        d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    ),
    beaker: (
      <>
        <path
          d="M9 3h6v5l4 8H5l4-8V3"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
        <path d="M8 21h8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </>
    ),
    network: (
      <>
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" fill="none" />
        <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="2" fill="none" />
        <path d="M12 2v7M12 15v7M2 12h7M15 12h7" stroke="currentColor" strokeWidth="2" />
      </>
    ),
    store: (
      <>
        <path
          d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
        <path d="M9 22V12h6v10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </>
    ),
    workflow: (
      <>
        <rect x="4" y="4" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2" fill="none" />
        <rect x="14" y="4" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2" fill="none" />
        <rect x="4" y="14" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2" fill="none" />
        <rect x="14" y="14" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2" fill="none" />
        <path d="M10 7h4M7 10v4M17 10v4M10 17h4" stroke="currentColor" strokeWidth="2" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="2" fill="none" />
        <path
          d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9c.26.604.852.997 1.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
      </>
    ),
    radar: (
      <path
        d="M12 2a10 10 0 100 20 10 10 0 000-20M12 12V2M12 12l7 7"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    ),
    graph: (
      <path
        d="M4 8h4M16 8h4M8 8a4 4 0 108 0 4 4 0 00-8 0M12 12v4M8 20h8"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    ),
    topology: (
      <path
        d="M12 2v4M4 8h4M16 8h4M12 14v4M8 8l4 6M16 8l-4 6M4 8l8 10M20 8l-8 10"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    ),
    dashboard: (
      <path
        d="M3 3h8v8H3zM13 3h8v5h-8zM13 11h8v10h-8zM3 13h8v8H3z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    ),
  };

  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      {paths[icon]}
    </svg>
  );
}

function ConnectionIndicator() {
  return (
    <div className="flex flex-col items-center">
      <div className="relative">
        <div className="w-3 h-3 rounded-full bg-sdr-accent-green animate-pulse" />
        <div className="absolute inset-0 w-3 h-3 rounded-full bg-sdr-accent-green/50 animate-ping" />
      </div>
      <GlitchText
        variants={["HUSHD", "CONNECTED", "SECURE"]}
        className="text-[8px] text-sdr-accent-green mt-1"
      />
    </div>
  );
}
