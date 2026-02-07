import { useState } from "react";
import { apiFetch } from "../api/client";

export function Policies() {
  const [yaml, setYaml] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleDeploy() {
    setError(null);
    setResult(null);
    try {
      const res = await apiFetch<{ deployment_id: string; agent_count: number }>(
        "/policies/deploy",
        {
          method: "POST",
          body: JSON.stringify({ policy_yaml: yaml }),
        },
      );
      setResult(`Deployed ${res.deployment_id} to ${res.agent_count} agents`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Deploy failed");
    }
  }

  return (
    <div>
      <h1>Policy Management</h1>
      <textarea
        value={yaml}
        onChange={(e) => setYaml(e.target.value)}
        rows={20}
        cols={80}
        placeholder="Paste policy YAML here..."
      />
      <br />
      <button onClick={handleDeploy}>Deploy Policy</button>
      {result && <p style={{ color: "green" }}>{result}</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
}
