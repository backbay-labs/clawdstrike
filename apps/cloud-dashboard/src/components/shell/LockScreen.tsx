import { useState } from "react";
import { NoiseGrain, GlassButton } from "../ui";

export function LockScreen({ locked, onUnlock }: { locked: boolean; onUnlock: (apiKey?: string) => void }) {
  const [apiKey, setApiKey] = useState("");

  if (!locked) return null;

  const handleSubmit = () => { onUnlock(apiKey || undefined); setApiKey(""); };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "radial-gradient(ellipse 80% 60% at 50% 40%, rgba(214,177,90,0.02) 0%, transparent 70%), #000",
      }}
    >
      <NoiseGrain opacity={0.03} />
      <div style={{ position: "relative", zIndex: 2, display: "flex", flexDirection: "column", alignItems: "center", gap: 24 }}>
        <img
          src={`${import.meta.env.BASE_URL}clawdstrike-logo.png`}
          alt="ClawdStrike"
          draggable={false}
          style={{ height: 64, opacity: 0.8 }}
        />
        <div
          className="glass-panel"
          style={{
            padding: 32,
            width: 320,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 16,
            border: "1px solid var(--gold-edge)",
            boxShadow: "0 0 40px rgba(214,177,90,0.06)",
          }}
        >
          <NoiseGrain />
          <span className="font-mono relative z-10" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.15em", color: "var(--gold)" }}>
            Locked
          </span>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") handleSubmit(); }}
            placeholder="Enter API key to unlock"
            className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none relative z-10"
            style={{ color: "var(--text)", width: "100%" }}
          />
          <div className="relative z-10">
            <GlassButton variant="primary" onClick={handleSubmit}>Unlock</GlassButton>
          </div>
        </div>
      </div>
    </div>
  );
}
