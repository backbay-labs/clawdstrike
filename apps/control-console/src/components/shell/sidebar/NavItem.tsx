import { useState } from "react";
import type { NavSigil, NavTone } from "./useNavApps";

const IDLE_ICON = "rgba(154,167,181,0.7)";
const IDLE_ICON_RAIL = "rgba(154,167,181,0.78)";
const IDLE_ROW_LABEL = "rgba(231,237,246,0.78)";

function accentFor(tone: NavTone): string {
  if (tone === "teal") return "var(--teal)";
  if (tone === "muted") return "var(--muted)";
  return "var(--gold)";
}

interface TooltipProps {
  label: string;
  kbd?: string;
}

/** Right-anchored hover label for the icon rail. */
export function Tooltip({ label, kbd }: TooltipProps) {
  return (
    <span
      role="tooltip"
      style={{
        position: "absolute",
        left: "calc(100% + 10px)",
        top: "50%",
        transform: "translateY(-50%)",
        background: "rgba(11,13,16,0.97)",
        border: "1px solid var(--gold-edge)",
        borderRadius: 8,
        padding: "5px 9px",
        whiteSpace: "nowrap",
        pointerEvents: "none",
        fontFamily: "var(--glia-font-mono)",
        fontSize: 10.5,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: "var(--text)",
        boxShadow: "0 6px 24px rgba(0,0,0,0.6), inset 0 1px 0 rgba(214,177,90,0.15)",
        zIndex: 50,
      }}
    >
      {label}
      {kbd && <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 9.5 }}>{kbd}</span>}
    </span>
  );
}

const FOCUS_RING_CLASS = "cs-nav-focus";

interface NavIconButtonProps {
  label: string;
  Sigil: NavSigil;
  tone: NavTone;
  active: boolean;
  running: boolean;
  onClick: () => void;
}

/** Icon-only nav entry for the 64px rail. Renders the sigil at 20px. */
export function NavIconButton({
  label,
  Sigil,
  tone,
  active,
  running,
  onClick,
}: NavIconButtonProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const accent = accentFor(tone);
  const highlighted = hover || focused;

  const iconColor = active ? "var(--gold)" : highlighted ? accent : IDLE_ICON_RAIL;

  const background = active
    ? "linear-gradient(180deg, rgba(214,177,90,0.18), rgba(214,177,90,0.06))"
    : highlighted
      ? "color-mix(in srgb, var(--gold) 7%, transparent)"
      : "transparent";

  const boxShadow = active
    ? "inset 0 1px 0 rgba(214,177,90,0.32), inset 0 0 0 1px rgba(214,177,90,0.18), 0 0 16px var(--gold-bloom)"
    : "inset 0 0 0 1px rgba(27,34,48,0)";

  return (
    <div
      style={{ position: "relative" }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <button
        type="button"
        onClick={onClick}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        aria-current={active ? "page" : undefined}
        aria-label={label}
        title={label}
        className={FOCUS_RING_CLASS}
        style={{
          width: 44,
          height: 44,
          borderRadius: 10,
          border: "none",
          background,
          color: iconColor,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          boxShadow,
          transition: "background 0.14s ease, color 0.14s ease, box-shadow 0.14s ease",
        }}
      >
        <Sigil size={20} />
      </button>
      {running && (
        <span
          aria-hidden="true"
          data-testid="nav-running-indicator"
          style={{
            position: "absolute",
            left: -2,
            top: "50%",
            transform: "translateY(-50%)",
            width: 3,
            height: 16,
            borderRadius: 2,
            background: active ? "var(--gold)" : "var(--teal)",
            boxShadow: active ? "0 0 8px var(--gold)" : "0 0 6px var(--teal)",
            pointerEvents: "none",
          }}
        />
      )}
      {(hover || focused) && <Tooltip label={label} />}
    </div>
  );
}

interface NavRowButtonProps {
  label: string;
  Sigil: NavSigil;
  tone: NavTone;
  active: boolean;
  running: boolean;
  onClick: () => void;
  compact?: boolean;
}

/** Full-width labeled nav row for the expanded and two-pane variants. Sigil at 17px. */
export function NavRowButton({
  label,
  Sigil,
  tone,
  active,
  running,
  onClick,
  compact = false,
}: NavRowButtonProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const accent = accentFor(tone);
  const highlighted = hover || focused;

  const iconColor = active ? "var(--gold)" : highlighted ? accent : IDLE_ICON;
  const labelColor = active ? "var(--gold)" : highlighted ? "var(--text)" : IDLE_ROW_LABEL;

  const background = active
    ? "linear-gradient(90deg, rgba(214,177,90,0.16), rgba(214,177,90,0.03))"
    : highlighted
      ? "color-mix(in srgb, var(--gold) 6%, transparent)"
      : "transparent";

  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      aria-current={active ? "page" : undefined}
      className={FOCUS_RING_CLASS}
      style={{
        position: "relative",
        display: "flex",
        alignItems: "center",
        gap: 12,
        width: "100%",
        padding: compact ? "7px 10px" : "9px 12px",
        borderRadius: 9,
        border: "none",
        textAlign: "left",
        cursor: "pointer",
        background,
        color: labelColor,
        boxShadow: active ? "inset 0 0 0 1px rgba(214,177,90,0.22)" : "none",
        transition: "background 0.14s ease, color 0.14s ease, box-shadow 0.14s ease",
      }}
    >
      {active && (
        <span
          aria-hidden="true"
          data-testid="nav-active-indicator"
          style={{
            position: "absolute",
            left: -1,
            top: 6,
            bottom: 6,
            width: 2,
            background: "var(--gold)",
            borderRadius: 2,
            boxShadow: "0 0 8px var(--gold)",
          }}
        />
      )}
      <span
        style={{
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          color: iconColor,
          transition: "color 0.14s ease",
        }}
      >
        <Sigil size={17} />
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11.5,
          letterSpacing: "0.05em",
          textTransform: "uppercase",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          flex: 1,
        }}
      >
        {label}
      </span>
      {running && (
        <span
          aria-hidden="true"
          data-testid="nav-running-dot"
          style={{
            width: 5,
            height: 5,
            borderRadius: "50%",
            background: active ? "var(--gold)" : "var(--teal)",
            boxShadow: active ? "0 0 6px var(--gold)" : "0 0 6px var(--teal)",
            flexShrink: 0,
          }}
        />
      )}
    </button>
  );
}
