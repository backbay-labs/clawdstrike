/**
 * StatusBar - 24px bottom status strip spanning full grid width.
 *
 * Layout: [Left: Shell mode + Lens] [Center: Connection + Posture] [Right: Sessions + KB mode]
 */
import { useConnectionStatus } from "@/context/ConnectionContext";
import { useSessions } from "@/shell/sessions";
import { useShell, useLens, useActiveHunt } from "./WorkbenchStateProvider";
import { useWorkbench } from "./WorkbenchStateProvider";

function connectionDotClass(status: string): string {
  if (status === "connected") return "bg-sdr-accent-green shadow-[0_0_4px_rgba(61,191,132,0.6)]";
  if (status === "connecting") return "bg-sdr-accent-amber shadow-[0_0_4px_rgba(212,168,75,0.6)]";
  return "bg-sdr-accent-red shadow-[0_0_4px_rgba(196,92,92,0.5)]";
}

function liveLabel(status: string): string {
  if (status === "connected") return "LIVE";
  if (status === "connecting") return "SYNC";
  return "OFFLINE";
}

function Dot() {
  return (
    <span className="mx-1.5 inline-block h-[3px] w-[3px] rounded-full bg-sdr-text-muted opacity-50" />
  );
}

export function StatusBar() {
  const shell = useShell();
  const { lens } = useLens();
  const { state } = useWorkbench();
  const activeHunt = useActiveHunt();
  const connectionStatus = useConnectionStatus();
  const sessions = useSessions({ archived: false });

  return (
    <footer
      className="relative z-[1] flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.1em]"
      style={{
        gridArea: "status",
        height: 24,
        background: "rgba(4,6,10,0.95)",
        borderTop: "1px solid var(--color-border-subtle, #212634)",
        padding: "0 12px",
      }}
    >
      {/* Left zone: Shell mode + Lens */}
      <div className="flex items-center">
        <span className="text-sdr-text-secondary">{shell.toUpperCase()}</span>
        <Dot />
        <span className="text-sdr-text-muted">{lens.charAt(0).toUpperCase() + lens.slice(1)}</span>
        {activeHunt && (
          <>
            <Dot />
            <span
              className="inline-block h-[6px] w-[6px] rounded-full"
              style={{ background: activeHunt.color }}
            />
            <span className="ml-1 text-sdr-text-muted">{activeHunt.title}</span>
          </>
        )}
      </div>

      {/* Center zone: Connection + Posture */}
      <div className="flex items-center">
        <span className={`inline-block h-[6px] w-[6px] rounded-full ${connectionDotClass(connectionStatus)}`} />
        <span className="ml-1.5 text-sdr-text-secondary">{liveLabel(connectionStatus)}</span>
        <Dot />
        <span className="text-sdr-text-muted">{state.posture.toUpperCase()}</span>
      </div>

      {/* Right zone: Sessions + KB mode */}
      <div className="flex items-center">
        <span className="text-sdr-text-muted">
          {sessions.length} {sessions.length === 1 ? "session" : "sessions"}
        </span>
        <Dot />
        <span className="text-sdr-text-muted">KB: NORMAL</span>
      </div>
    </footer>
  );
}
