import { useCallback, useEffect, useState } from "react";
import { fetchPolicy, type PolicyResponse } from "../api/client";

export function Policies() {
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchPolicy();
      setPolicy(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policy");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Active Policy</h1>
        <button onClick={load} className="rounded bg-gray-700 px-3 py-1.5 text-sm hover:bg-gray-600">
          Reload
        </button>
      </div>

      {error && <p className="rounded bg-red-900/50 px-4 py-2 text-red-300">{error}</p>}

      {loading ? (
        <p className="text-gray-500">Loading...</p>
      ) : policy ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <InfoCard label="Name" value={policy.name ?? "default"} />
            <InfoCard label="Version" value={policy.version ?? "-"} />
            <InfoCard label="Hash" value={policy.policy_hash ? policy.policy_hash.slice(0, 16) + "..." : "-"} />
            <InfoCard label="Source" value={policy.source ? `${policy.source.kind}${policy.source.path ? `: ${policy.source.path}` : ""}` : "local"} />
          </div>

          {policy.yaml && (
            <div>
              <h2 className="mb-2 text-lg font-semibold">Policy YAML</h2>
              <pre className="max-h-[600px] overflow-auto rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm text-gray-300">
                {policy.yaml}
              </pre>
            </div>
          )}

          {!!policy.policy && !policy.yaml && (
            <div>
              <h2 className="mb-2 text-lg font-semibold">Policy Configuration</h2>
              <pre className="max-h-[600px] overflow-auto rounded-lg border border-gray-800 bg-gray-900 p-4 text-sm text-gray-300">
                {JSON.stringify(policy.policy, null, 2)}
              </pre>
            </div>
          )}
        </div>
      ) : (
        <p className="text-gray-500">No policy loaded</p>
      )}
    </div>
  );
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
      <p className="text-xs text-gray-400">{label}</p>
      <p className="mt-0.5 font-mono text-sm text-white">{value}</p>
    </div>
  );
}
