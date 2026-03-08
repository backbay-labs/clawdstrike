import { useEffect, useRef, useState } from "react";
import type { ConnectionStatus } from "@/context/ConnectionContext";
import { isTauri } from "@/services/tauri";

function statusText(status: ConnectionStatus) {
  switch (status) {
    case "connected":
      return "LIVE";
    case "connecting":
      return "SYNCING";
    case "error":
      return "ERROR";
    default:
      return "OFFLINE";
  }
}

function MenuAction({
  label,
  onClick,
  destructive = false,
}: {
  label: string;
  onClick: () => void;
  destructive?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "origin-focus-ring flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-[11px] font-mono transition-colors",
        destructive
          ? "text-sdr-accent-red hover:bg-sdr-accent-red/10"
          : "text-sdr-text-secondary hover:bg-[rgba(213,173,87,0.08)] hover:text-sdr-text-primary",
      ].join(" ")}
    >
      {label}
    </button>
  );
}

export interface ProfileMenuProps {
  connectionStatus: ConnectionStatus;
  onOpenOperations: () => void;
  onOpenConnectionSettings: () => void;
  onOpenCommandPalette: () => void;
}

export function ProfileMenu({
  connectionStatus,
  onOpenOperations,
  onOpenConnectionSettings,
  onOpenCommandPalette,
}: ProfileMenuProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const tauri = isTauri();

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="relative" ref={rootRef}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="origin-focus-ring premium-chip premium-chip--control flex items-center gap-2 px-2.5 py-[4px] text-[10px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary"
        aria-expanded={open}
        aria-label="Open profile menu"
      >
        <span className="h-4 w-4 rounded-full border border-[rgba(213,173,87,0.65)] bg-[radial-gradient(circle_at_35%_30%,rgba(255,236,180,0.18)_0%,rgba(10,14,20,0.92)_70%)]" />
        Ops
      </button>

      {open ? (
        <div className="premium-panel premium-panel--dropdown absolute right-0 top-[calc(100%+8px)] z-[90] min-w-[220px] rounded-lg p-1.5">
          <div className="origin-label px-2 pt-1.5 pb-1 text-[10px] leading-[1.35]">Management</div>
          <div className="px-2 pb-1 text-[10px] font-mono uppercase tracking-[0.11em] text-sdr-text-muted">
            Status: {statusText(connectionStatus)}
          </div>
          <div className="premium-separator mb-1 h-px w-full" />
          <MenuAction
            label="Open Operations"
            onClick={() => {
              onOpenOperations();
              setOpen(false);
            }}
          />
          <MenuAction
            label="Connection Settings"
            onClick={() => {
              onOpenConnectionSettings();
              setOpen(false);
            }}
          />
          <MenuAction
            label="Command Palette"
            onClick={() => {
              onOpenCommandPalette();
              setOpen(false);
            }}
          />
          {tauri ? (
            <>
              <div className="premium-separator my-1 h-px w-full" />
              <MenuAction
                label="Quit App"
                destructive
                onClick={() => {
                  window.close();
                  setOpen(false);
                }}
              />
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
