import { useAgents } from "../hooks/useAgents";

export function Dashboard() {
  const { agents, loading } = useAgents();

  const activeCount = agents.filter((a) => a.status === "active").length;

  return (
    <div>
      <h1>ClawdStrike Cloud</h1>
      <div>
        <div>
          <h2>Active Agents</h2>
          <p>{loading ? "..." : activeCount}</p>
        </div>
        <div>
          <h2>Total Agents</h2>
          <p>{loading ? "..." : agents.length}</p>
        </div>
      </div>
      <nav>
        <ul>
          <li><a href="/agents">Agent Fleet</a></li>
          <li><a href="/events">Event Stream</a></li>
          <li><a href="/policies">Policies</a></li>
          <li><a href="/alerts">Alerts</a></li>
          <li><a href="/compliance">Compliance</a></li>
          <li><a href="/settings">Settings</a></li>
        </ul>
      </nav>
    </div>
  );
}
