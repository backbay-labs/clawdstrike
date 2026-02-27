import { useCallback, useEffect, useState } from "react";
import { fetchAuditEvents, type AuditEvent, type AuditFilters } from "../api/client";
import { NoiseGrain, GlassButton, Stamp } from "../components/ui";
import { EventDetailDrawer } from "../components/events/EventDetailDrawer";
import { EventBookmarks } from "../components/events/EventBookmarks";
import { exportAsCSV, exportAsJSON } from "../utils/exportData";
import { useDebouncedCallback } from "../hooks/useDebouncedCallback";

export function AuditLog(_props: { windowId?: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<AuditFilters>({ limit: 50, offset: 0 });
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

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

  const debouncedSetFilter = useDebouncedCallback(
    (key: string, value: string) => {
      setFilters((f) => ({ ...f, [key]: value || undefined, offset: 0 }));
    },
    300,
  );

  return (
    <div className="space-y-5" style={{ padding: 20, minHeight: "100%", color: "#e2e8f0", overflow: "auto", height: "100%" }}>
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
          onChange={(v) => debouncedSetFilter("session_id", v)}
        />
        <FilterInput
          label="Agent ID"
          onChange={(v) => debouncedSetFilter("agent_id", v)}
        />
        <GlassButton onClick={load}>Refresh</GlassButton>
        <GlassButton onClick={() => exportAsCSV(events as unknown as Record<string, unknown>[], "audit-events")}>
          Export CSV
        </GlassButton>
        <GlassButton onClick={() => exportAsJSON(events, "audit-events")}>
          Export JSON
        </GlassButton>
      </div>

      {/* Error banner */}
      {error && (
        <p
          className="font-mono rounded px-4 py-2 text-sm"
          style={{
            background: "rgba(194,59,59,0.08)",
            border: "1px solid rgba(194,59,59,0.4)",
            boxShadow: "0 0 16px rgba(194,59,59,0.1), inset 0 1px 0 rgba(255,255,255,0.02)",
            color: "#c23b3b",
          }}
        >
          {error}
        </p>
      )}

      {/* Table glass panel + drawer wrapper */}
      <div style={{ position: "relative" }}>
        <div className="glass-panel overflow-x-auto rounded-lg">
          <NoiseGrain />

          <table className="relative w-full text-left text-sm" style={{ borderCollapse: "separate", borderSpacing: 0 }}>
            <thead>
              <tr
                style={{
                  borderBottom: "1px solid transparent",
                  backgroundImage: "linear-gradient(to right, rgba(27,34,48,0.0), rgba(27,34,48,0.6), rgba(27,34,48,0.0))",
                  backgroundSize: "100% 1px",
                  backgroundPosition: "bottom",
                  backgroundRepeat: "no-repeat",
                }}
              >
                {["\u2606", "Time", "Action", "Target", "Decision", "Guard", "Session", "Agent"].map((h) => (
                  <th
                    key={h}
                    className="font-mono px-4 py-3 text-[10px] uppercase"
                    style={{
                      letterSpacing: "0.1em",
                      color: "rgba(154,167,181,0.6)",
                      fontWeight: 500,
                      width: h === "\u2606" ? "40px" : undefined,
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
                  <td colSpan={8} className="font-mono px-4 py-8 text-center" style={{ color: "rgba(154,167,181,0.4)" }}>
                    Loading...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="font-mono px-4 py-8 text-center" style={{ color: "rgba(226,232,240,0.3)" }}>
                    No events found
                  </td>
                </tr>
              ) : (
                events.map((event) => (
                  <tr
                    key={event.id}
                    className="hover-row"
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelectedEvent(event)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelectedEvent(event); } }}
                  >
                    <td className="whitespace-nowrap px-4 py-2.5" style={{ width: "40px" }}>
                      <EventBookmarks eventId={event.id} />
                    </td>
                    <td
                      className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
                      style={{ color: "rgba(226,232,240,0.4)" }}
                    >
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td
                      className="font-mono whitespace-nowrap px-4 py-2.5 text-sm"
                      style={{ color: "#e2e8f0" }}
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
                      <Stamp variant={event.decision === "blocked" ? "blocked" : "allowed"}>{event.decision}</Stamp>
                    </td>
                    <td
                      className="whitespace-nowrap px-4 py-2.5 text-sm"
                      style={{ color: "rgba(226,232,240,0.6)" }}
                    >
                      {event.guard ?? "-"}
                    </td>
                    <td
                      className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
                      style={{ color: "rgba(226,232,240,0.35)" }}
                    >
                      {event.session_id?.slice(0, 12) ?? "-"}
                    </td>
                    <td
                      className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
                      style={{ color: "rgba(226,232,240,0.35)" }}
                    >
                      {event.agent_id?.slice(0, 12) ?? "-"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm">
        <span
          className="font-mono"
          style={{
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
            className="font-mono px-2 py-1"
            style={{
              fontSize: "11px",
              letterSpacing: "0.05em",
              color: "rgba(214,177,90,0.6)",
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

function PaginationButton({ disabled, onClick, children }: { disabled: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className="glass-panel hover-glass-button font-mono rounded px-3 py-1 text-xs uppercase tracking-wider disabled:opacity-30"
      style={{
        color: disabled ? "rgba(154,167,181,0.4)" : "#d6b15a",
        letterSpacing: "0.08em",
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
        className="font-mono text-[10px] uppercase"
        style={{
          letterSpacing: "0.1em",
          color: "rgba(214,177,90,0.5)",
        }}
      >
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="glass-input font-mono rounded px-2 py-1.5 text-sm outline-none"
        style={{ color: "#e2e8f0" }}
      >
        {options.map((o) => (
          <option key={o} value={o} style={{ background: "#0b0d10" }}>{o || "All"}</option>
        ))}
      </select>
    </label>
  );
}

function FilterInput({ label, onChange }: { label: string; onChange: (v: string) => void }) {
  const [value, setValue] = useState("");
  return (
    <label className="flex flex-col gap-1">
      <span
        className="font-mono text-[10px] uppercase"
        style={{
          letterSpacing: "0.1em",
          color: "rgba(214,177,90,0.5)",
        }}
      >
        {label}
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          onChange(e.target.value);
        }}
        placeholder={`Filter by ${label.toLowerCase()}`}
        className="glass-input font-mono rounded px-2 py-1.5 text-sm outline-none placeholder:text-[rgba(100,116,139,0.5)]"
        style={{ color: "#e2e8f0" }}
      />
    </label>
  );
}
