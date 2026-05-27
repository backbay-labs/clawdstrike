import { type SidebarVariant, useShellPreferences } from "../../state/useShellPreferences";

interface VariantOption {
  value: SidebarVariant;
  label: string;
  description: string;
}

const VARIANT_OPTIONS: VariantOption[] = [
  {
    value: "rail",
    label: "Icon Rail",
    description: "64px icon-only column. Maximum canvas space; tooltips on hover.",
  },
  {
    value: "expanded",
    label: "Expanded",
    description: "Icon + label nav column. Balanced density for routine ops.",
  },
  {
    value: "twopane",
    label: "Two-Pane",
    description: "Wide panel with a secondary context drawer. Deep-dive sessions.",
  },
];

export function SidebarSettings() {
  const sidebarVariant = useShellPreferences((s) => s.sidebarVariant);
  const setSidebarVariant = useShellPreferences((s) => s.setSidebarVariant);

  return (
    <div className="relative z-10 space-y-3">
      <p
        className="font-mono text-[10px]"
        style={{
          color: "rgba(214,177,90,0.55)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
        }}
      >
        Sidebar Layout
      </p>
      {/*
       * role="radiogroup" + hidden native radios: real radio semantics for
       * keyboard navigation and screen readers, fully custom visual treatment.
       */}
      <div role="radiogroup" aria-label="Sidebar layout" className="space-y-2">
        {VARIANT_OPTIONS.map((option) => {
          const active = sidebarVariant === option.value;
          const radioId = `sidebar-variant-${option.value}`;
          return (
            <label
              key={option.value}
              htmlFor={radioId}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 12,
                padding: "10px 12px 10px 14px",
                borderRadius: 9,
                border: active ? "1px solid rgba(214,177,90,0.35)" : "1px solid rgba(27,34,48,0.5)",
                background: active ? "rgba(214,177,90,0.06)" : "rgba(7,8,10,0.6)",
                boxShadow: active
                  ? "inset 0 1px 0 rgba(255,255,255,0.03), 0 0 8px rgba(214,177,90,0.06)"
                  : "inset 0 1px 0 rgba(255,255,255,0.02)",
                cursor: "pointer",
                transition: "background 0.14s ease, border-color 0.14s ease, box-shadow 0.14s ease",
                position: "relative",
                /*
                 * overflow: hidden so the 2px gold bar at left: 0 is clipped
                 * cleanly by the 9px border-radius rather than poking outside.
                 */
                overflow: "hidden",
              }}
            >
              {/* 2px gold active bar — mirrors NavRowButton's active indicator exactly */}
              <span
                aria-hidden="true"
                style={{
                  position: "absolute",
                  left: 0,
                  top: 8,
                  bottom: 8,
                  width: 2,
                  borderRadius: 2,
                  background: "var(--gold)",
                  boxShadow: "0 0 8px var(--gold)",
                  opacity: active ? 1 : 0,
                  transform: active ? "scaleY(1)" : "scaleY(0.4)",
                  transformOrigin: "center",
                  transition: "opacity 0.14s ease, transform 0.14s ease",
                }}
              />

              {/* Visually hidden native radio — carries real semantics + keyboard nav */}
              <input
                id={radioId}
                type="radio"
                name="sidebar-variant"
                value={option.value}
                checked={active}
                onChange={() => setSidebarVariant(option.value)}
                style={{
                  position: "absolute",
                  opacity: 0,
                  width: 0,
                  height: 0,
                  pointerEvents: "none",
                }}
              />

              {/* Custom dot indicator — consistent with the forged aesthetic */}
              <span
                aria-hidden="true"
                style={{
                  flexShrink: 0,
                  marginTop: 3,
                  width: 12,
                  height: 12,
                  borderRadius: "50%",
                  border: active ? "2px solid var(--gold)" : "2px solid rgba(154,167,181,0.35)",
                  background: active ? "var(--gold)" : "transparent",
                  boxShadow: active ? "0 0 6px rgba(214,177,90,0.4)" : "none",
                  transition:
                    "border-color 0.14s ease, background 0.14s ease, box-shadow 0.14s ease",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                {active && (
                  <span
                    aria-hidden="true"
                    style={{
                      width: 4,
                      height: 4,
                      borderRadius: "50%",
                      background: "var(--obsidian)",
                    }}
                  />
                )}
              </span>

              <span style={{ flex: 1 }}>
                <span
                  className="font-mono"
                  style={{
                    display: "block",
                    fontSize: 11.5,
                    letterSpacing: "0.05em",
                    textTransform: "uppercase",
                    color: active ? "var(--gold)" : "rgba(229,231,235,0.7)",
                    transition: "color 0.14s ease",
                  }}
                >
                  {option.label}
                </span>
                <span
                  className="font-body"
                  style={{
                    display: "block",
                    marginTop: 3,
                    fontSize: 11,
                    color: "rgba(229,231,235,0.4)",
                    lineHeight: 1.4,
                  }}
                >
                  {option.description}
                </span>
              </span>
            </label>
          );
        })}
      </div>
      <p className="font-body text-xs" style={{ color: "rgba(229,231,235,0.4)" }}>
        Change takes effect immediately and persists across sessions.
      </p>
    </div>
  );
}
