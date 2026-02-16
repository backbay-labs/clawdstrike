import { useCallback, useEffect, useState } from "react";
import { fetchAuditEvents, type AuditEvent, type AuditFilters } from "../api/client";

export function AuditLog() {
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
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Audit Log</h1>

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
          className="rounded bg-gray-700 px-3 py-1.5 text-sm hover:bg-gray-600"
        >
          Refresh
        </button>
      </div>

      {error && <p className="rounded bg-red-900/50 px-4 py-2 text-red-300">{error}</p>}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 bg-gray-900 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Decision</th>
              <th className="px-4 py-3">Guard</th>
              <th className="px-4 py-3">Session</th>
              <th className="px-4 py-3">Agent</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">Loading...</td></tr>
            ) : events.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">No events found</td></tr>
            ) : (
              events.map((event) => (
                <tr key={event.id}>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-gray-500">
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 font-mono">{event.action_type}</td>
                  <td className="max-w-xs truncate px-4 py-2 text-gray-400">{event.target ?? "-"}</td>
                  <td className="whitespace-nowrap px-4 py-2">
                    <span className={event.decision === "blocked" ? "text-red-400" : "text-green-400"}>
                      {event.decision}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-4 py-2">{event.guard ?? "-"}</td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-gray-500">
                    {event.session_id?.slice(0, 12) ?? "-"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-gray-500">
                    {event.agent_id?.slice(0, 12) ?? "-"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400">
        <span>{total} total events</span>
        <div className="flex gap-2">
          <button
            disabled={page === 0}
            onClick={() => setFilters((f) => ({ ...f, offset: Math.max(0, (f.offset ?? 0) - (f.limit ?? 50)) }))}
            className="rounded bg-gray-800 px-3 py-1 disabled:opacity-40"
          >
            Previous
          </button>
          <span className="px-2 py-1">Page {page + 1} of {totalPages || 1}</span>
          <button
            disabled={page + 1 >= totalPages}
            onClick={() => setFilters((f) => ({ ...f, offset: (f.offset ?? 0) + (f.limit ?? 50) }))}
            className="rounded bg-gray-800 px-3 py-1 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

function FilterSelect({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (v: string) => void }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-gray-400">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-gray-200"
      >
        {options.map((o) => (
          <option key={o} value={o}>{o || "All"}</option>
        ))}
      </select>
    </label>
  );
}

function FilterInput({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-gray-400">
      {label}
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={`Filter by ${label.toLowerCase()}`}
        className="rounded border border-gray-700 bg-gray-800 px-2 py-1.5 text-sm text-gray-200 placeholder-gray-600"
      />
    </label>
  );
}
