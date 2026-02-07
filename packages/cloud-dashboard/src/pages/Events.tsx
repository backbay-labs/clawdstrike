import { useSSE } from "../hooks/useSSE";

interface SecurityEvent {
  guard_name: string;
  verdict: string;
  agent_id: string;
  target: string;
  timestamp: string;
}

export function Events() {
  const { events, connected } = useSSE<SecurityEvent>("/api/events/stream");

  return (
    <div>
      <h1>Event Stream</h1>
      <p>Status: {connected ? "Connected" : "Disconnected"}</p>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Guard</th>
            <th>Verdict</th>
            <th>Agent</th>
            <th>Target</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, i) => (
            <tr key={i}>
              <td>{event.timestamp}</td>
              <td>{event.guard_name}</td>
              <td>{event.verdict}</td>
              <td>{event.agent_id}</td>
              <td>{event.target}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
