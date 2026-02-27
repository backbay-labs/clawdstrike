import { useState, useRef, useEffect, useCallback } from "react";
import { useDesktopOS } from "@backbay/glia-desktop";
import { desktopIcons, PROCESS_ICONS } from "../../state/processRegistry";

export function StartMenu() {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { processes } = useDesktopOS();

  const toggle = useCallback(() => setOpen((v) => !v), []);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  // Close on Escape
  useEffect(() => {
    if (!open) return;
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [open]);

  return (
    <div ref={menuRef} style={{ position: "relative", height: "100%", zIndex: 100 }}>
      {/* Start button — clawdstrike masthead */}
      <button
        type="button"
        onClick={toggle}
        className="start-menu-btn"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          padding: "0 16px",
          border: "none",
          background: open
            ? "linear-gradient(180deg, rgba(214,177,90,0.14) 0%, rgba(214,177,90,0.06) 100%)"
            : "transparent",
          borderRight: "1px solid rgba(27,34,48,0.5)",
          cursor: "pointer",
          transition: "all 0.2s ease",
          position: "relative",
        }}
      >
        <img
          src={`${import.meta.env.BASE_URL}clawdstrike-logo.png`}
          alt="ClawdStrike"
          draggable={false}
          style={{
            height: 42,
            width: "auto",
            opacity: open ? 1 : 0.8,
            transition: "all 0.2s ease",
            filter: open ? "brightness(1.2)" : "brightness(1)",
          }}
        />
        {/* Subtle gold underline indicator when open */}
        {open && (
          <div
            style={{
              position: "absolute",
              bottom: 0,
              left: 16,
              right: 16,
              height: 2,
              borderRadius: 1,
              background: "var(--gold)",
              opacity: 0.5,
            }}
          />
        )}
      </button>

      {/* Launcher popup */}
      {open && (
        <div
          style={{
            position: "absolute",
            bottom: "100%",
            left: 0,
            marginBottom: 6,
            width: 240,
            background: "rgba(11,13,16,0.97)",
            border: "1px solid var(--gold-edge)",
            borderRadius: "var(--radius-window)",
            boxShadow:
              "0 -8px 32px rgba(0,0,0,0.6), 0 0 1px rgba(214,177,90,0.2), inset 0 1px 0 rgba(255,255,255,0.03)",
            padding: "8px 0",
            backdropFilter: "blur(16px)",
          }}
        >
          {desktopIcons.map((icon) => {
            const def = processes.getDefinition(icon.processId);
            const sigil = PROCESS_ICONS[icon.processId];

            return (
              <button
                key={icon.id}
                type="button"
                onClick={() => {
                  processes.launch(icon.processId);
                  setOpen(false);
                }}
                className="hover-row"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  width: "100%",
                  padding: "8px 16px",
                  border: "none",
                  background: "transparent",
                  cursor: "pointer",
                  textAlign: "left",
                  borderRadius: 0,
                }}
              >
                <span
                  style={{
                    width: 28,
                    height: 28,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    background:
                      "linear-gradient(180deg, var(--graphite), var(--obsidian))",
                    border: "1px solid var(--gold-edge)",
                    borderRadius: 8,
                    flexShrink: 0,
                  }}
                >
                  {sigil}
                </span>
                <div style={{ minWidth: 0 }}>
                  <div
                    className="font-mono"
                    style={{
                      fontSize: 12,
                      fontWeight: 500,
                      letterSpacing: "0.04em",
                      color: "var(--text)",
                    }}
                  >
                    {def?.name ?? icon.label}
                  </div>
                  {def?.description && (
                    <div
                      className="font-body"
                      style={{
                        fontSize: 10,
                        color: "var(--muted)",
                        opacity: 0.6,
                        marginTop: 1,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {def.description}
                    </div>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
