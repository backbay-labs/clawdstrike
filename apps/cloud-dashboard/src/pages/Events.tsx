import { useSharedSSE } from "../context/SSEContext";
import type { SSEEvent } from "../hooks/useSSE";

export function Events() {
  const { events, connected } = useSharedSSE();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Event Stream</h1>
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`} />
          <span className="text-sm text-gray-400">
            {connected ? "Connected" : "Disconnected"} &middot; {events.length} events
          </span>
        </div>
      </div>

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 bg-gray-900 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Guard</th>
              <th className="px-4 py-3">Decision</th>
              <th className="px-4 py-3">Session</th>
              <th className="px-4 py-3">Agent</th>
              <th className="px-4 py-3">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {events.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                  Waiting for events...
                </td>
              </tr>
            ) : (
              events.map((event, i) => <EventTableRow key={i} event={event} />)
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EventTableRow({ event }: { event: SSEEvent }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;
  return (
    <tr className={isViolation ? "bg-red-950/20" : ""}>
      <td className="whitespace-nowrap px-4 py-2">
        <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${
          isViolation ? "bg-red-900/50 text-red-300" : "bg-green-900/50 text-green-300"
        }`}>
          {event.event_type}
        </span>
      </td>
      <td className="whitespace-nowrap px-4 py-2 font-mono">{event.action_type ?? "-"}</td>
      <td className="max-w-xs truncate px-4 py-2 text-gray-400">{event.target ?? "-"}</td>
      <td className="whitespace-nowrap px-4 py-2">{event.guard ?? "-"}</td>
      <td className="whitespace-nowrap px-4 py-2">
        {event.allowed === false ? (
          <span className="text-red-400">blocked</span>
        ) : event.allowed === true ? (
          <span className="text-green-400">allowed</span>
        ) : (
          "-"
        )}
      </td>
      <td className="whitespace-nowrap px-4 py-2 text-xs text-gray-500">
        {event.session_id ? event.session_id.slice(0, 12) : "-"}
      </td>
      <td className="whitespace-nowrap px-4 py-2 text-xs text-gray-500">
        {event.agent_id ? event.agent_id.slice(0, 12) : "-"}
      </td>
      <td className="whitespace-nowrap px-4 py-2 text-xs text-gray-500">
        {new Date(event.timestamp).toLocaleTimeString()}
      </td>
    </tr>
  );
}
