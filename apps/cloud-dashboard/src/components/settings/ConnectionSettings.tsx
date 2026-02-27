import { useState } from "react";
import { notifySSEConfigChanged } from "../../hooks/useSSE";
import { NoiseGrain, GlassButton } from "../ui";

const INPUT_FOCUS_CSS =
  "glass-input font-body rounded-md px-3 py-2 text-sm outline-none transition-colors duration-150 focus:ring-1 placeholder:text-[rgba(100,116,139,0.5)]";

const focusRingStyle = {
  "--tw-ring-color": "rgba(214,177,90,0.4)",
} as React.CSSProperties;

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="font-mono text-[10px]"
      style={{
        color: "rgba(214,177,90,0.55)",
        textTransform: "uppercase",
        letterSpacing: "0.1em",
      }}
    >
      {children}
    </span>
  );
}

export function ConnectionSettings() {
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
    notifySSEConfigChanged();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <section className="glass-panel max-w-3xl space-y-5 p-6">
      <NoiseGrain />
      <h2
        className="font-display relative z-10 text-lg tracking-wide"
        style={{ color: "#fff" }}
      >
        Connection
      </h2>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>hushd URL (leave empty for Vite proxy)</FieldLabel>
        <input
          type="text"
          value={hushdUrl}
          onChange={(e) => setHushdUrl(e.target.value)}
          placeholder="http://localhost:9876"
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        />
      </label>

      <label className="relative z-10 flex flex-col gap-1.5">
        <FieldLabel>API Key (optional)</FieldLabel>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="Bearer token for hushd"
          className={INPUT_FOCUS_CSS}
          style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
        />
      </label>

      <div className="relative z-10 flex items-center gap-3">
        <GlassButton onClick={handleSave}>Save Connection</GlassButton>
        {saved && (
          <span className="text-sm" style={{ color: "#2daa6a" }}>
            Saved!
          </span>
        )}
      </div>
    </section>
  );
}
