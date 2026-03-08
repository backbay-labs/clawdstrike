/**
 * OrbLensRotor — marking-menu lens switcher.
 *
 * Gestures:
 *   Click              → toggle drawer collapse / expand
 *   Hold 280ms + drag  → marking menu: drag to lens, release to select
 *   Right-click        → toggle lens chooser list (click-to-select mode)
 *   Mouse wheel        → cycle lenses
 *
 * The lens chooser is a vertical list anchored to the right of the spine.
 * During hold-drag, the nearest item to the pointer auto-highlights, and
 * releasing selects it. This enables the hold → flick → release muscle memory.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useLens, useWorkbench, useWorkbenchDispatch } from "@/shell/workbench/WorkbenchStateProvider";
import { useSidebarWakeController } from "@/shell/workbench/anticipation";
import type { LensId } from "@/shell/workbench/workbenchState";

const HOLD_MS = 280;

interface LensEntry {
  id: LensId;
  label: string;
  key: string;
}

const LENSES: readonly LensEntry[] = [
  { id: "scopes", label: "Scopes", key: "S" },
  { id: "history", label: "History", key: "H" },
  { id: "files", label: "Files", key: "F" },
  { id: "sandboxes", label: "Sandboxes", key: "B" },
  { id: "entities", label: "Entities", key: "E" },
  { id: "swarms", label: "Swarms", key: "W" },
  { id: "notes", label: "Notes", key: "N" },
] as const;

export function OrbLensRotor() {
  const { lens } = useLens();
  const { state } = useWorkbench();
  const dispatch = useWorkbenchDispatch();
  const sidebarWake = useSidebarWakeController();

  const orbRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const pressTimerRef = useRef<number | null>(null);
  const isMarkingRef = useRef(false); // true = opened via hold (release-to-select)
  const didOpenRef = useRef(false);

  const [menuOpen, setMenuOpen] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState({ top: 0, left: 0 });
  const [hoveredLens, setHoveredLens] = useState<LensId | null>(null);

  /* ── Position the menu to the right of the orb ──────────────── */
  const computeAnchor = useCallback(() => {
    if (!orbRef.current) return { top: 0, left: 0 };
    const r = orbRef.current.getBoundingClientRect();
    // anchor top-left of the menu list at the right edge of the spine
    const menuHeight = LENSES.length * 28 + 8; // 28px per item + padding
    return {
      left: r.right + 8,
      top: Math.max(4, r.top + r.height / 2 - menuHeight / 2),
    };
  }, []);

  /* ── Open helpers ───────────────────────────────────────────── */
  const openAsMarking = useCallback(() => {
    isMarkingRef.current = true;
    didOpenRef.current = true;
    setMenuAnchor(computeAnchor());
    setHoveredLens(null);
    setMenuOpen(true);
  }, [computeAnchor]);

  const openAsClick = useCallback(() => {
    isMarkingRef.current = false;
    didOpenRef.current = true;
    setMenuAnchor(computeAnchor());
    setHoveredLens(null);
    setMenuOpen(true);
  }, [computeAnchor]);

  /* ── Select + close ─────────────────────────────────────────── */
  const selectLens = useCallback((id: LensId) => {
    dispatch({ type: "SET_LENS", payload: id });
    if (state.sidebarCollapsed) {
      dispatch({ type: "TOGGLE_SIDEBAR" });
    }
    setMenuOpen(false);
    setHoveredLens(null);
  }, [dispatch, state.sidebarCollapsed]);

  /* ── Hold timer ─────────────────────────────────────────────── */
  const clearTimer = useCallback(() => {
    if (pressTimerRef.current !== null) {
      window.clearTimeout(pressTimerRef.current);
      pressTimerRef.current = null;
    }
  }, []);

  const handlePointerDown = useCallback(() => {
    clearTimer();
    didOpenRef.current = false;
    pressTimerRef.current = window.setTimeout(() => {
      openAsMarking();
      pressTimerRef.current = null;
    }, HOLD_MS);
  }, [clearTimer, openAsMarking]);

  /* ── Pointer move: highlight nearest lens while marking ────── */
  useEffect(() => {
    if (!menuOpen || !isMarkingRef.current) return;
    const menuEl = menuRef.current;
    if (!menuEl) return;

    const onMove = (e: PointerEvent) => {
      // Find which menu item the pointer is closest to
      const items = menuEl.querySelectorAll<HTMLButtonElement>("[data-lens-id]");
      let closest: LensId | null = null;
      let closestDist = Infinity;
      for (const item of items) {
        const r = item.getBoundingClientRect();
        const cy = r.top + r.height / 2;
        const cx = r.left + r.width / 2;
        const dist = Math.hypot(e.clientX - cx, e.clientY - cy);
        if (dist < closestDist) {
          closestDist = dist;
          closest = item.dataset.lensId as LensId;
        }
      }
      // Only highlight if pointer has moved into the menu area (not still on orb)
      if (closestDist < 60) {
        setHoveredLens(closest);
      }
    };

    window.addEventListener("pointermove", onMove);
    return () => window.removeEventListener("pointermove", onMove);
  }, [menuOpen]);

  /* ── Pointer up: select highlighted if marking mode ─────────── */
  useEffect(() => {
    if (!menuOpen || !isMarkingRef.current) return;

    const onUp = () => {
      if (hoveredLens) {
        selectLens(hoveredLens);
      } else {
        setMenuOpen(false);
      }
      isMarkingRef.current = false;
    };

    window.addEventListener("pointerup", onUp);
    return () => window.removeEventListener("pointerup", onUp);
  }, [menuOpen, hoveredLens, selectLens]);

  /* ── Click-outside to close (for right-click mode) ──────────── */
  useEffect(() => {
    if (!menuOpen || isMarkingRef.current) return;
    const onDown = (e: PointerEvent) => {
      const t = e.target as HTMLElement | null;
      if (t?.closest(".orb-lens-menu, .nexus-orb")) return;
      setMenuOpen(false);
    };
    window.addEventListener("pointerdown", onDown);
    return () => window.removeEventListener("pointerdown", onDown);
  }, [menuOpen]);

  /* ── Escape to close ────────────────────────────────────────── */
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setMenuOpen(false); return; }
      // Keyboard lens shortcuts when menu is open
      const match = LENSES.find((l) => l.key.toLowerCase() === e.key.toLowerCase());
      if (match) selectLens(match.id);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen, selectLens]);

  /* ── Click = toggle sidebar (if hold didn't fire) ───────────── */
  const handleClick = useCallback(() => {
    clearTimer();
    if (didOpenRef.current) return;
    dispatch({ type: "TOGGLE_SIDEBAR" });
  }, [clearTimer, dispatch]);

  const handlePointerUp = useCallback(() => {
    clearTimer();
  }, [clearTimer]);

  /* ── Mouse wheel = cycle lenses ─────────────────────────────── */
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const idx = LENSES.findIndex((l) => l.id === lens);
    const next = (idx + (e.deltaY > 0 ? 1 : -1) + LENSES.length) % LENSES.length;
    dispatch({ type: "SET_LENS", payload: LENSES[next].id });
  }, [lens, dispatch]);

  const activeLens = LENSES.find((l) => l.id === lens);
  const anticipatoryWake = state.sidebarCollapsed && sidebarWake.shouldWarmDock;
  const anticipatoryIntensity = sidebarWake.wakeState === "ghost-peek"
    ? 1
    : sidebarWake.wakeState === "prewake" || sidebarWake.wakeState === "retracting"
      ? 0.72
      : 0.54;

  return (
    <>
      <div className="relative" onWheel={handleWheel}>
        <button
          ref={orbRef}
          type="button"
          className="nexus-orb"
          onClick={handleClick}
          onContextMenu={(e) => {
            e.preventDefault();
            if (menuOpen) setMenuOpen(false);
            else openAsClick();
          }}
          onPointerDown={handlePointerDown}
          onPointerUp={handlePointerUp}
          onPointerLeave={handlePointerUp}
          onPointerCancel={handlePointerUp}
          title={`Lens: ${activeLens?.label ?? lens}`}
          aria-label={`Active lens: ${activeLens?.label ?? lens}. Click to toggle sidebar.`}
          data-sidebar-wake={sidebarWake.wakeState}
          style={{
            filter: anticipatoryWake
              ? `brightness(${1.04 + anticipatoryIntensity * 0.08})`
              : undefined,
            transform: anticipatoryWake
              ? "translateY(-1px)"
              : undefined,
          }}
        >
          <div
            className="nexus-orb-glow"
            style={anticipatoryWake
              ? {
                  animation: "none",
                  opacity: 0.78 + anticipatoryIntensity * 0.16,
                  filter: "blur(6px)",
                  background: "radial-gradient(circle, rgba(213, 173, 87, 0.32) 0%, rgba(213, 173, 87, 0.1) 46%, transparent 74%)",
                }
              : undefined}
          />
          <div
            className="nexus-orb-mode-ring"
            style={anticipatoryWake ? { opacity: 0.82 + anticipatoryIntensity * 0.18 } : undefined}
          />
          <div
            className="nexus-orb-visual"
            style={anticipatoryWake
              ? {
                  borderColor: "rgba(213, 173, 87, 0.7)",
                  boxShadow:
                    "0 0 26px rgba(213, 173, 87, 0.24), 0 0 8px rgba(213, 173, 87, 0.18), inset 0 1px 0 rgba(255, 255, 255, 0.08)",
                }
              : undefined}
          >
            <OrbCore />
          </div>
        </button>
      </div>

      {/* Lens chooser — vertical list, fixed position */}
      {menuOpen && (
        <div
          ref={menuRef}
          className="orb-lens-menu"
          role="menu"
          aria-label="Workbench lenses"
          style={{ top: menuAnchor.top, left: menuAnchor.left }}
        >
          {LENSES.map((entry) => {
            const isActive = entry.id === lens;
            const isHovered = entry.id === hoveredLens;
            return (
              <button
                key={entry.id}
                type="button"
                role="menuitemradio"
                aria-checked={isActive}
                data-lens-id={entry.id}
                data-active={isActive ? "true" : undefined}
                className="orb-lens-menu__item"
                data-hovered={isHovered ? "true" : undefined}
                onClick={() => selectLens(entry.id)}
                onPointerEnter={() => {
                  if (!isMarkingRef.current) setHoveredLens(entry.id);
                }}
                onPointerLeave={() => {
                  if (!isMarkingRef.current) setHoveredLens(null);
                }}
              >
                <span className="orb-lens-menu__label">{entry.label}</span>
                <span className="orb-lens-menu__key">{entry.key}</span>
              </button>
            );
          })}
        </div>
      )}
    </>
  );
}

function OrbCore() {
  return (
    <svg
      viewBox="0 0 24 24"
      width="18"
      height="18"
      fill="none"
      stroke="var(--origin-gold)"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="6" opacity="0.2" />
      <circle cx="12" cy="12" r="2.5" fill="var(--origin-gold)" opacity="0.3" />
      <circle cx="12" cy="12" r="1" fill="var(--origin-gold)" />
    </svg>
  );
}

export default OrbLensRotor;
