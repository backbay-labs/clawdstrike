import * as React from "react";
import type {
  AgentActionTelemetry,
  AgentGlyphState,
} from "@/features/forensics/hooks/useAgentCognitionState";

type AgentOrbHudProps = {
  focusedGlyph: AgentGlyphState | null;
  focusedSessionKey: string | null;
  onClearFocus: () => void;
};

function formatTimestamp(value: number): string {
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatAge(value: number, now = Date.now()): string {
  const delta = Math.max(0, now - value);
  const seconds = Math.floor(delta / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function rowPolicyTone(action: AgentActionTelemetry): string {
  if (action.policyStatus === "denied" || action.policyStatus === "exception") {
    return "text-[rgba(251,96,126,0.92)]";
  }
  if (action.policyStatus === "approval-required") {
    return "text-[rgba(233,191,106,0.94)]";
  }
  return "text-[rgba(179,189,204,0.86)]";
}

export function AgentOrbHud({ focusedGlyph, focusedSessionKey, onClearFocus }: AgentOrbHudProps) {
  if (!focusedGlyph) return null;

  return (
    <div className="pointer-events-none absolute bottom-[60px] left-[92px] right-[92px] z-[30]">
      <div className="pointer-events-auto ml-auto w-[min(620px,100%)] rounded-xl border border-[rgba(213,173,87,0.26)] bg-[linear-gradient(180deg,rgba(9,13,20,0.9)_0%,rgba(6,9,15,0.95)_100%)] p-3 shadow-[0_20px_38px_rgba(0,0,0,0.45)] backdrop-blur-md">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-[rgba(213,173,87,0.9)]">
              Agent Trace
            </div>
            <div className="mt-0.5 text-sm font-mono text-sdr-text-primary">
              {focusedGlyph.label}
            </div>
          </div>
          <button
            type="button"
            onClick={onClearFocus}
            className="rounded border border-[rgba(213,173,87,0.38)] px-2 py-1 text-[10px] font-mono uppercase tracking-[0.1em] text-[rgba(236,223,188,0.94)] transition hover:border-[rgba(213,173,87,0.72)] hover:bg-[rgba(213,173,87,0.12)]"
          >
            Clear Focus
          </button>
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] font-mono uppercase tracking-[0.08em] text-sdr-text-secondary">
          <span className="rounded border border-[rgba(213,173,87,0.24)] px-2 py-1">
            {focusedGlyph.actionCount} actions
          </span>
          <span className="rounded border border-[rgba(213,173,87,0.24)] px-2 py-1">
            last {formatAge(focusedGlyph.latestAt)}
          </span>
          {focusedSessionKey ? (
            <span className="rounded border border-[rgba(213,173,87,0.24)] px-2 py-1 normal-case tracking-normal">
              {focusedSessionKey}
            </span>
          ) : null}
        </div>

        <div className="mt-2 max-h-[210px] overflow-y-auto rounded-lg border border-[rgba(213,173,87,0.18)] bg-[rgba(3,6,10,0.52)] px-2 py-1.5">
          {focusedGlyph.history.length === 0 ? (
            <p className="py-2 text-[11px] font-mono text-sdr-text-muted">
              No activity in the current telemetry window.
            </p>
          ) : (
            <ul className="space-y-1">
              {focusedGlyph.history.map((action) => (
                <li
                  key={action.id}
                  className="flex items-center gap-2 rounded px-1.5 py-1 text-[11px] font-mono text-sdr-text-secondary"
                >
                  <span className="shrink-0 text-[10px] text-sdr-text-muted">
                    {formatTimestamp(action.timestamp)}
                  </span>
                  <span className="shrink-0 rounded border border-[rgba(213,173,87,0.2)] px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-[rgba(213,173,87,0.9)]">
                    {action.kind}
                  </span>
                  <span className="truncate">{action.label}</span>
                  <span
                    className={`ml-auto shrink-0 text-[10px] uppercase tracking-[0.06em] ${rowPolicyTone(action)}`}
                  >
                    {action.policyStatus}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
