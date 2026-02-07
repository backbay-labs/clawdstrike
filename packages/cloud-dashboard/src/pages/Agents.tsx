import { useAgents } from "../hooks/useAgents";

export function Agents() {
  const { agents, loading, error, refresh } = useAgents();

  return (
    <div>
      <h1>Agent Fleet</h1>
      <button onClick={refresh}>Refresh</button>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {loading ? (
        <p>Loading agents...</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Name</th>
              <th>Status</th>
              <th>Role</th>
              <th>Trust Level</th>
              <th>Last Heartbeat</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id}>
                <td>{agent.agent_id}</td>
                <td>{agent.name}</td>
                <td>{agent.status}</td>
                <td>{agent.role}</td>
                <td>{agent.trust_level}</td>
                <td>{agent.last_heartbeat_at ?? "never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
