import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../api/client";

interface AlertConfig {
  id: string;
  name: string;
  channel: string;
  severity_threshold: string;
  enabled: boolean;
}

export function Alerts() {
  const [alerts, setAlerts] = useState<AlertConfig[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiFetch<AlertConfig[]>("/alerts");
      setAlerts(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div>
      <h1>Alert Configuration</h1>
      <button onClick={refresh}>Refresh</button>
      {loading ? (
        <p>Loading...</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Channel</th>
              <th>Severity</th>
              <th>Enabled</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td>{a.name}</td>
                <td>{a.channel}</td>
                <td>{a.severity_threshold}</td>
                <td>{a.enabled ? "Yes" : "No"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
