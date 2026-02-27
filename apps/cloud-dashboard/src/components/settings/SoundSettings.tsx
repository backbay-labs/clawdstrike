import { useState } from "react";

export function SoundSettings() {
  const [enabled, setEnabled] = useState(
    () => localStorage.getItem("cs_sounds_enabled") === "true",
  );

  function handleToggle() {
    const next = !enabled;
    setEnabled(next);
    localStorage.setItem("cs_sounds_enabled", String(next));
    window.dispatchEvent(new Event("clawdstrike:sound-changed"));
  }

  return (
    <div className="relative z-10 space-y-3">
      <label className="flex items-center gap-3" style={{ cursor: "pointer" }}>
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          onClick={handleToggle}
          className="rounded-full transition-colors duration-200"
          style={{
            width: 40,
            height: 22,
            background: enabled ? "rgba(214,177,90,0.4)" : "rgba(27,34,48,0.8)",
            border: "1px solid rgba(214,177,90,0.25)",
            position: "relative",
            cursor: "pointer",
            flexShrink: 0,
          }}
        >
          <span
            className="block rounded-full transition-transform duration-200"
            style={{
              width: 16,
              height: 16,
              background: enabled ? "#d6b15a" : "rgba(229,231,235,0.4)",
              position: "absolute",
              top: 2,
              left: 2,
              transform: enabled ? "translateX(18px)" : "translateX(0)",
            }}
          />
        </button>
        <span
          className="font-mono text-[10px]"
          style={{
            color: "rgba(214,177,90,0.55)",
            textTransform: "uppercase",
            letterSpacing: "0.1em",
          }}
        >
          Sound Effects
        </span>
      </label>
      <p
        className="font-body text-xs"
        style={{ color: "rgba(229,231,235,0.4)" }}
      >
        Plays short tones for events: a low buzz for violations, a click for allowed checks, and a
        sweep on status changes. Uses Web Audio (no files loaded).
      </p>
    </div>
  );
}
