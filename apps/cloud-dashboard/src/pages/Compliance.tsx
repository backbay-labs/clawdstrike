import { useState } from "react";
import { apiFetch } from "../api/client";

export function Compliance() {
  const [retentionDays, setRetentionDays] = useState(30);
  const [message, setMessage] = useState<string | null>(null);

  async function handleExport(format: string) {
    const from = new Date(Date.now() - 30 * 86400000).toISOString();
    const to = new Date().toISOString();
    window.open(`/api/compliance/export?from=${from}&to=${to}&format=${format}`);
  }

  async function handleUpdateRetention() {
    try {
      await apiFetch("/compliance/retention", {
        method: "PUT",
        body: JSON.stringify({ retention_days: retentionDays }),
      });
      setMessage("Retention policy updated");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Failed");
    }
  }

  return (
    <div>
      <h1>Compliance</h1>
      <section>
        <h2>Audit Export</h2>
        <button onClick={() => handleExport("json")}>Export JSON</button>
        <button onClick={() => handleExport("csv")}>Export CSV</button>
        <button onClick={() => handleExport("cef")}>Export CEF</button>
      </section>
      <section>
        <h2>Data Retention</h2>
        <label>
          Retention days:
          <input
            type="number"
            value={retentionDays}
            onChange={(e) => setRetentionDays(Number(e.target.value))}
            min={1}
            max={730}
          />
        </label>
        <button onClick={handleUpdateRetention}>Update</button>
        {message && <p>{message}</p>}
      </section>
    </div>
  );
}
