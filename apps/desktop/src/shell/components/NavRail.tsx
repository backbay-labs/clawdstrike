/**
 * NavRail - Session-focused rail for Nexus strikecell work.
 */
import { clsx } from "clsx";
import { useNavigate } from "react-router-dom";
import { useConnectionStatus } from "@/context/ConnectionContext";
import type { StrikecellSessionKind } from "@/shell/sessions";
import { useActiveSession, useSessionActions, useSessions } from "@/shell/sessions";
import type { AppId } from "../plugins/types";
import { CyberNexusOrb } from "./CyberNexusOrb";

interface NavRailProps {
  activeAppId: AppId;
  onSelectApp: (appId: AppId) => void;
}

function sessionStatusClass(status: string): string {
  switch (status) {
    case "running":
      return "bg-sdr-accent-green shadow-[0_0_8px_rgba(61,191,132,0.55)]";
    case "error":
      return "bg-sdr-accent-red shadow-[0_0_8px_rgba(196,92,92,0.45)]";
    case "completed":
      return "bg-sdr-accent-blue shadow-[0_0_8px_rgba(88,129,214,0.4)]";
    default:
      return "bg-sdr-text-muted";
  }
}

function liveLabel(connectionStatus: string): string {
  if (connectionStatus === "connected") return "LIVE";
  if (connectionStatus === "connecting") return "SYNC";
  return "OFFLINE";
}

const STRIKECELL_SESSION_KINDS: StrikecellSessionKind[] = ["chat", "experiment", "red-team"];

function nextStrikecellKind(sessionCount: number): StrikecellSessionKind {
  return STRIKECELL_SESSION_KINDS[sessionCount % STRIKECELL_SESSION_KINDS.length];
}

function sessionKindLabel(kind: StrikecellSessionKind | undefined): string {
  if (kind === "experiment") return "experiment";
  if (kind === "red-team") return "red-team";
  return "chat";
}

function sessionKindClass(kind: StrikecellSessionKind | undefined): string {
  if (kind === "experiment") {
    return "border-[rgba(88,129,214,0.45)] text-sdr-accent-blue";
  }
  if (kind === "red-team") {
    return "border-[rgba(196,92,92,0.45)] text-sdr-accent-red";
  }
  return "border-[rgba(61,191,132,0.45)] text-sdr-accent-green";
}

export function NavRail({ activeAppId, onSelectApp }: NavRailProps) {
  const navigate = useNavigate();
  const connectionStatus = useConnectionStatus();
  const sessions = useSessions({ appId: "nexus", archived: false });
  const activeSession = useActiveSession();
  const { createSession, setActiveSession } = useSessionActions();

  const createStrikecellSession = () => {
    const sessionKind = nextStrikecellKind(sessions.length);
    const session = createSession("nexus", `Strikecell ${sessions.length + 1}`, null, {
      strikecellId: "nexus",
      strikecellKind: sessionKind,
    });
    setActiveSession(session.id);
    navigate(`/nexus/${session.id}`);
  };

  return (
    <nav
      className="relative z-20 flex h-full w-[220px] shrink-0 flex-col border-r bg-[linear-gradient(180deg,rgba(9,11,18,0.98)_0%,rgba(4,6,10,0.99)_100%)] px-3 py-3"
      style={{ borderRightColor: "rgba(213, 173, 87, 0.3)" }}
    >
      <div className="nexus-rail-orb-divider flex items-center gap-3 pb-2">
        <CyberNexusOrb />
        <div className="min-w-0">
          <div className="origin-label text-[9px] tracking-[0.16em]">Strikecell</div>
          <div className="text-[11px] font-mono uppercase text-sdr-text-secondary">Sessions</div>
        </div>
      </div>

      <div className="premium-panel premium-panel--rail mt-2 flex min-h-0 flex-1 flex-col rounded-[18px] px-2 py-2">
        <div className="mb-2 flex items-center justify-between gap-2 px-1">
          <span className="origin-label text-[9px] tracking-[0.14em]">Workspace</span>
          <button
            type="button"
            onClick={createStrikecellSession}
            className="origin-focus-ring premium-chip premium-chip--control px-2 py-0.5 text-[9px] font-mono uppercase tracking-[0.11em] text-sdr-text-secondary"
          >
            +
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto pb-1">
          {sessions.length === 0 ? (
            <div className="rounded-md border border-sdr-border/50 px-2 py-2 text-[11px] text-sdr-text-muted">
              No strikecell sessions.
            </div>
          ) : (
            sessions.map((session) => {
              const isActive = activeAppId === "nexus" && activeSession?.id === session.id;
              return (
                <button
                  key={session.id}
                  type="button"
                  onClick={() => {
                    setActiveSession(session.id);
                    navigate(`/nexus/${session.id}`);
                  }}
                  title={session.title}
                  data-active={isActive ? "true" : "false"}
                  className={clsx(
                    "origin-focus-ring strikecell-session-row w-full rounded-lg border px-2 py-1.5 text-left transition-colors",
                    isActive
                      ? "border-[color:var(--origin-gold)] bg-[rgba(213,173,87,0.12)]"
                      : "border-sdr-border/50 bg-[rgba(8,10,16,0.64)] hover:border-[rgba(213,173,87,0.55)]",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={clsx("h-2 w-2 rounded-full", sessionStatusClass(session.status))}
                    />
                    <span className="min-w-0 truncate text-[11px] font-mono uppercase tracking-[0.1em] text-sdr-text-primary">
                      {session.title}
                    </span>
                    <span
                      className={clsx(
                        "ml-auto rounded-full border px-1.5 py-0.5 text-[8px] font-mono uppercase tracking-[0.08em]",
                        sessionKindClass(session.strikecellKind),
                      )}
                    >
                      {sessionKindLabel(session.strikecellKind)}
                    </span>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      <div className="mt-3 flex items-center justify-end gap-2">
        <button
          type="button"
          title="Operations"
          aria-label={`Open operations ${liveLabel(connectionStatus)}`}
          onClick={() => onSelectApp("operations")}
          data-active={activeAppId === "operations" ? "true" : "false"}
          className="origin-focus-ring origin-status-sigil"
        >
          <span className="origin-status-sigil-core" aria-hidden="true">
            <span
              className={clsx(
                "origin-status-sigil-dot",
                connectionStatus === "connected"
                  ? "bg-sdr-accent-green shadow-[0_0_8px_rgba(61,191,132,0.65)]"
                  : connectionStatus === "connecting"
                    ? "bg-sdr-accent-amber shadow-[0_0_8px_rgba(212,168,75,0.65)]"
                    : "bg-sdr-accent-red shadow-[0_0_8px_rgba(196,92,92,0.55)]",
              )}
            />
          </span>
          <span className="origin-status-sigil-label">{liveLabel(connectionStatus)}</span>
        </button>
      </div>
    </nav>
  );
}
