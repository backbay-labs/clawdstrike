import { useState } from "react";
import { WALLPAPERS } from "../../state/wallpapers";

const WALLPAPER_CHANGED_EVENT = "clawdstrike:wallpaper-changed";

export function WallpaperPicker() {
  const [selected, setSelected] = useState(
    () => localStorage.getItem("cs_wallpaper") || "default",
  );

  function handleSelect(id: string) {
    setSelected(id);
    localStorage.setItem("cs_wallpaper", id);
    window.dispatchEvent(new Event(WALLPAPER_CHANGED_EVENT));
  }

  return (
    <div className="relative z-10">
      <p
        className="font-mono mb-3 text-[10px]"
        style={{
          color: "rgba(214,177,90,0.55)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
        }}
      >
        Choose Wallpaper
      </p>
      <div className="grid grid-cols-4 gap-3">
        {WALLPAPERS.map((wp) => (
          <button
            key={wp.id}
            type="button"
            onClick={() => handleSelect(wp.id)}
            className="rounded-md transition-all duration-200"
            style={{
              width: 60,
              height: 40,
              background: wp.gradient,
              border:
                selected === wp.id
                  ? "2px solid #d6b15a"
                  : "2px solid rgba(27,34,48,0.5)",
              cursor: "pointer",
              boxShadow:
                selected === wp.id ? "0 0 8px rgba(214,177,90,0.2)" : "none",
            }}
            title={wp.name}
          />
        ))}
      </div>
      <p
        className="font-body mt-2 text-xs"
        style={{ color: "rgba(229,231,235,0.4)" }}
      >
        {WALLPAPERS.find((w) => w.id === selected)?.name ?? "Default"}
      </p>
    </div>
  );
}
