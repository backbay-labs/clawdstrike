import { useCallback, useEffect, useState } from "react";
import { fetchAuditEvents, type AuditEvent, type AuditFilters } from "../api/client";

const NOISE_SVG = `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E")`;

const glassPanel = {
  background: "rgba(4,8,16,0.94)",
  border: "1px solid rgba(34,211,238,0.12)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
} as const;

const glassInput = {
  background: "rgba(4,8,16,0.8)",
  border: "1px solid rgba(34,211,238,0.12)",
} as const;

export function AuditLog(_props: { windowId?: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<AuditFilters>({ limit: 50, offset: 0 });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchAuditEvents(filters);
      setEvents(data.events);
      setTotal(data.total);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => { load(); }, [load]);

  const page = Math.floor((filters.offset ?? 0) / (filters.limit ?? 50));
  const totalPages = Math.ceil(total / (filters.limit ?? 50));

  return (
    <div className="space-y-5" style={{ minHeight: "100%", color: "#e2e8f0" }}>
      <h1
        className="text-2xl tracking-wide"
        style={{ fontFamily: "var(--glia-font-display, 'Cinzel', serif)", color: "#22d3ee" }}
      >
        Audit Log
      </h1>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3">
        <FilterSelect
          label="Decision"
          value={filters.decision ?? ""}
          options={["", "allowed", "blocked"]}
          onChange={(v) => setFilters((f) => ({ ...f, decision: v || undefined, offset: 0 }))}
        />
        <FilterSelect
          label="Action Type"
          value={filters.action_type ?? ""}
          options={["", "file_access", "file_write", "egress", "shell", "mcp_tool", "patch"]}
          onChange={(v) => setFilters((f) => ({ ...f, action_type: v || undefined, offset: 0 }))}
        />
        <FilterInput
          label="Session ID"
          value={filters.session_id ?? ""}
          onChange={(v) => setFilters((f) => ({ ...f, session_id: v || undefined, offset: 0 }))}
        />
        <FilterInput
          label="Agent ID"
          value={filters.agent_id ?? ""}
          onChange={(v) => setFilters((f) => ({ ...f, agent_id: v || undefined, offset: 0 }))}
        />
        <button
          onClick={load}
          className="rounded px-4 py-1.5 text-xs uppercase tracking-widest transition-all duration-200"
          style={{
            ...glassPanel,
            color: "#22d3ee",
            fontFamily: "var(--glia-font-mono, monospace)",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.5)";
            e.currentTarget.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 12px rgba(34,211,238,0.15)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.12)";
            e.currentTarget.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.02)";
          }}
        >
          Refresh
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <p
          className="rounded px-4 py-2 text-sm"
          style={{
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.4)",
            boxShadow: "0 0 16px rgba(239,68,68,0.1), inset 0 1px 0 rgba(255,255,255,0.02)",
            color: "#ef4444",
            fontFamily: "var(--glia-font-mono, monospace)",
          }}
        >
          {error}
        </p>
      )}

      {/* Table glass panel */}
      <div
        className="relative overflow-x-auto rounded-lg"
        style={{ ...glassPanel }}
      >
        {/* Noise grain overlay */}
        <div
          className="pointer-events-none absolute inset-0 rounded-lg"
          style={{ backgroundImage: NOISE_SVG, backgroundRepeat: "repeat", opacity: 1 }}
        />

        <table className="relative w-full text-left text-sm" style={{ borderCollapse: "separate", borderSpacing: 0 }}>
          <thead>
            <tr
              style={{
                borderBottom: "1px solid transparent",
                backgroundImage: "linear-gradient(to right, rgba(34,211,238,0.0), rgba(34,211,238,0.12), rgba(34,211,238,0.0))",
                backgroundSize: "100% 1px",
                backgroundPosition: "bottom",
                backgroundRepeat: "no-repeat",
              }}
            >
              {["Time", "Action", "Target", "Decision", "Guard", "Session", "Agent"].map((h) => (
                <th
                  key={h}
                  className="px-4 py-3 text-[10px] uppercase"
                  style={{
                    fontFamily: "var(--glia-font-mono, monospace)",
                    letterSpacing: "0.1em",
                    color: "rgba(34,211,238,0.5)",
                    fontWeight: 500,
                  }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center" style={{ color: "rgba(34,211,238,0.3)", fontFamily: "var(--glia-font-mono, monospace)" }}>
                  Loading...
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center" style={{ color: "rgba(226,232,240,0.3)", fontFamily: "var(--glia-font-mono, monospace)" }}>
                  No events found
                </td>
              </tr>
            ) : (
              events.map((event) => (
                <tr
                  key={event.id}
                  className="transition-colors duration-150"
                  style={{ cursor: "default" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(34,211,238,0.04)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <td
                    className="whitespace-nowrap px-4 py-2.5 text-xs"
                    style={{ color: "rgba(226,232,240,0.4)", fontFamily: "var(--glia-font-mono, monospace)" }}
                  >
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                  <td
                    className="whitespace-nowrap px-4 py-2.5 text-sm"
                    style={{ fontFamily: "var(--glia-font-mono, monospace)", color: "#e2e8f0" }}
                  >
                    {event.action_type}
                  </td>
                  <td
                    className="max-w-xs truncate px-4 py-2.5 text-sm"
                    style={{ color: "rgba(226,232,240,0.5)" }}
                  >
                    {event.target ?? "-"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5">
                    <DecisionBadge decision={event.decision} />
                  </td>
                  <td
                    className="whitespace-nowrap px-4 py-2.5 text-sm"
                    style={{ color: "rgba(226,232,240,0.6)" }}
                  >
                    {event.guard ?? "-"}
                  </td>
                  <td
                    className="whitespace-nowrap px-4 py-2.5 text-xs"
                    style={{ color: "rgba(226,232,240,0.35)", fontFamily: "var(--glia-font-mono, monospace)" }}
                  >
                    {event.session_id?.slice(0, 12) ?? "-"}
                  </td>
                  <td
                    className="whitespace-nowrap px-4 py-2.5 text-xs"
                    style={{ color: "rgba(226,232,240,0.35)", fontFamily: "var(--glia-font-mono, monospace)" }}
                  >
                    {event.agent_id?.slice(0, 12) ?? "-"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm">
        <span
          style={{
            fontFamily: "var(--glia-font-mono, monospace)",
            fontSize: "11px",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            color: "rgba(226,232,240,0.4)",
          }}
        >
          {total} total events
        </span>
        <div className="flex items-center gap-2">
          <PaginationButton
            disabled={page === 0}
            onClick={() => setFilters((f) => ({ ...f, offset: Math.max(0, (f.offset ?? 0) - (f.limit ?? 50)) }))}
          >
            Previous
          </PaginationButton>
          <span
            className="px-2 py-1"
            style={{
              fontFamily: "var(--glia-font-mono, monospace)",
              fontSize: "11px",
              letterSpacing: "0.05em",
              color: "rgba(34,211,238,0.6)",
            }}
          >
            Page {page + 1} of {totalPages || 1}
          </span>
          <PaginationButton
            disabled={page + 1 >= totalPages}
            onClick={() => setFilters((f) => ({ ...f, offset: (f.offset ?? 0) + (f.limit ?? 50) }))}
          >
            Next
          </PaginationButton>
        </div>
      </div>
    </div>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  const isBlocked = decision === "blocked";
  return (
    <span
      className="inline-block rounded px-2 py-0.5 text-[11px] uppercase"
      style={{
        fontFamily: "var(--glia-font-mono, monospace)",
        letterSpacing: "0.08em",
        fontWeight: 600,
        color: isBlocked ? "#ef4444" : "#10b981",
        background: isBlocked ? "rgba(239,68,68,0.08)" : "rgba(16,185,129,0.08)",
        border: `1px solid ${isBlocked ? "rgba(239,68,68,0.25)" : "rgba(16,185,129,0.25)"}`,
        boxShadow: `0 0 8px ${isBlocked ? "rgba(239,68,68,0.1)" : "rgba(16,185,129,0.1)"}`,
      }}
    >
      {decision}
    </span>
  );
}

function PaginationButton({ disabled, onClick, children }: { disabled: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className="rounded px-3 py-1 text-xs uppercase tracking-wider transition-all duration-200 disabled:opacity-30"
      style={{
        ...glassPanel,
        fontFamily: "var(--glia-font-mono, monospace)",
        color: disabled ? "rgba(226,232,240,0.3)" : "#22d3ee",
        letterSpacing: "0.08em",
      }}
      onMouseEnter={(e) => {
        if (!disabled) {
          e.currentTarget.style.borderColor = "rgba(34,211,238,0.4)";
          e.currentTarget.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 10px rgba(34,211,238,0.1)";
        }
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "rgba(34,211,238,0.12)";
        e.currentTarget.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.02)";
      }}
    >
      {children}
    </button>
  );
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (v: string) => void }) {
  return (
    <label className="flex flex-col gap-1">
      <span
        className="text-[10px] uppercase"
        style={{
          fontFamily: "var(--glia-font-mono, monospace)",
          letterSpacing: "0.1em",
          color: "rgba(34,211,238,0.4)",
        }}
      >
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded px-2 py-1.5 text-sm transition-colors duration-200 outline-none"
        style={{
          ...glassInput,
          fontFamily: "var(--glia-font-mono, monospace)",
          color: "#e2e8f0",
        }}
        onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(34,211,238,0.4)"; }}
        onBlur={(e) => { e.currentTarget.style.borderColor = "rgba(34,211,238,0.12)"; }}
      >
        {options.map((o) => (
          <option key={o} value={o} style={{ background: "#0a0a0a" }}>{o || "All"}</option>
        ))}
      </select>
    </label>
  );
}

function FilterInput({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="flex flex-col gap-1">
      <span
        className="text-[10px] uppercase"
        style={{
          fontFamily: "var(--glia-font-mono, monospace)",
          letterSpacing: "0.1em",
          color: "rgba(34,211,238,0.4)",
        }}
      >
        {label}
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={`Filter by ${label.toLowerCase()}`}
        className="rounded px-2 py-1.5 text-sm transition-colors duration-200 outline-none placeholder:text-[rgba(100,116,139,0.5)]"
        style={{
          ...glassInput,
          fontFamily: "var(--glia-font-mono, monospace)",
          color: "#e2e8f0",
        }}
        onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(34,211,238,0.4)"; }}
        onBlur={(e) => { e.currentTarget.style.borderColor = "rgba(34,211,238,0.12)"; }}
      />
    </label>
  );
}
