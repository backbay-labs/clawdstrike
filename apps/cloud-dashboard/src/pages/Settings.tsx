import { useState } from "react";

export function Settings() {
  const [hushdUrl, setHushdUrl] = useState(() => localStorage.getItem("hushd_url") || "");
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("hushd_api_key") || "");
  const [saved, setSaved] = useState(false);

  function handleSave() {
    if (hushdUrl) {
      localStorage.setItem("hushd_url", hushdUrl);
    } else {
      localStorage.removeItem("hushd_url");
    }
    if (apiKey) {
      localStorage.setItem("hushd_api_key", apiKey);
    } else {
      localStorage.removeItem("hushd_api_key");
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <section className="max-w-lg space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold">Connection</h2>

        <label className="flex flex-col gap-1 text-sm text-gray-400">
          hushd URL (leave empty for Vite proxy)
          <input
            type="text"
            value={hushdUrl}
            onChange={(e) => setHushdUrl(e.target.value)}
            placeholder="http://localhost:9876"
            className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
          />
        </label>

        <label className="flex flex-col gap-1 text-sm text-gray-400">
          API Key (optional)
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Bearer token for hushd"
            className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-gray-200 placeholder-gray-600"
          />
        </label>

        <div className="flex items-center gap-3">
          <button
            onClick={handleSave}
            className="rounded bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500"
          >
            Save
          </button>
          {saved && <span className="text-sm text-green-400">Saved!</span>}
        </div>
      </section>

      <section className="max-w-lg rounded-lg border border-gray-800 bg-gray-900 p-6">
        <h2 className="mb-2 text-lg font-semibold">About</h2>
        <p className="text-sm text-gray-400">
          ClawdStrike Dashboard v0.1.0 &mdash; Local-first security monitoring for hushd.
        </p>
      </section>
    </div>
  );
}
