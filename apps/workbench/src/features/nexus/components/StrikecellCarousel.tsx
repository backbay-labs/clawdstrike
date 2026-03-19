import { clsx } from "clsx";
import { useMemo, useState } from "react";
import { getNexusStationCode, getNexusStationLabel, resolveNexusObservatoryStationId } from "../observatory";
import type { Strikecell, StrikecellDomainId, StrikecellStatus } from "../types";

interface StrikecellCarouselProps {
  strikecells: Strikecell[];
  strikecellOrder: StrikecellDomainId[];
  activeStrikecellId: StrikecellDomainId | null;
  keyboardHighlightedId: StrikecellDomainId | null;
  carouselFocused: boolean;
  pinned: { left?: StrikecellDomainId; right?: StrikecellDomainId };
  onFocusChange: (focused: boolean) => void;
  onNavigate: (direction: "prev" | "next") => void;
  onActivate: (id: StrikecellDomainId) => void;
  onHighlight: (id: StrikecellDomainId | null) => void;
  onToggleExpanded: (id: StrikecellDomainId) => void;
  onPin: (id: StrikecellDomainId, position: "left" | "right" | null) => void;
  onReorder: (id: StrikecellDomainId, direction: "up" | "down") => void;
}

interface MenuState {
  x: number;
  y: number;
  id: StrikecellDomainId;
}

function statusClass(status: StrikecellStatus): string {
  switch (status) {
    case "healthy":
      return "border-sdr-accent-green/45 text-sdr-accent-green";
    case "warning":
      return "border-sdr-accent-amber/45 text-sdr-accent-amber";
    case "critical":
      return "border-sdr-accent-red/45 text-sdr-accent-red";
    default:
      return "border-sdr-text-muted/45 text-sdr-text-muted";
  }
}

function resolveStrikecell(strikecells: Strikecell[], id: StrikecellDomainId): Strikecell | null {
  return strikecells.find((strikecell) => strikecell.id === id) ?? null;
}

function orderedAroundActive(
  strikecells: Strikecell[],
  strikecellOrder: StrikecellDomainId[],
  activeStrikecellId: StrikecellDomainId | null,
): Strikecell[] {
  const fullOrder = strikecellOrder
    .map((id) => resolveStrikecell(strikecells, id))
    .filter((strikecell): strikecell is Strikecell => Boolean(strikecell));

  if (fullOrder.length <= 2 || !activeStrikecellId) return fullOrder;

  const activeIndex = fullOrder.findIndex((strikecell) => strikecell.id === activeStrikecellId);
  if (activeIndex < 0) return fullOrder;

  const centerIndex = Math.floor(fullOrder.length / 2);
  const rotated: Strikecell[] = [];
  for (let index = 0; index < fullOrder.length; index += 1) {
    const sourceIndex = (activeIndex - centerIndex + index + fullOrder.length) % fullOrder.length;
    rotated.push(fullOrder[sourceIndex]);
  }
  return rotated;
}

export function StrikecellCarousel({
  strikecells,
  strikecellOrder,
  activeStrikecellId,
  keyboardHighlightedId,
  carouselFocused,
  pinned,
  onFocusChange,
  onNavigate,
  onActivate,
  onHighlight,
  onToggleExpanded,
  onPin,
  onReorder,
}: StrikecellCarouselProps) {
  const [menu, setMenu] = useState<MenuState | null>(null);
  const ordered = useMemo(
    () => orderedAroundActive(strikecells, strikecellOrder, activeStrikecellId),
    [activeStrikecellId, strikecellOrder, strikecells],
  );
  const railHeight = Math.max(ordered.length * 68, 280);

  return (
    <>
      <aside className="absolute left-2 top-1/2 z-30 -translate-y-1/2 pointer-events-auto">
        <div
          tabIndex={0}
          role="listbox"
          aria-label="Strikecell carousel"
          onFocus={() => onFocusChange(true)}
          onBlur={() => onFocusChange(false)}
          onKeyDown={(event) => {
            if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
              event.preventDefault();
              onNavigate("prev");
            }
            if (event.key === "ArrowDown" || event.key === "ArrowRight") {
              event.preventDefault();
              onNavigate("next");
            }
            if (event.key === "Enter" && keyboardHighlightedId) {
              event.preventDefault();
              onActivate(keyboardHighlightedId);
            }
          }}
          className={clsx(
            "origin-chrome-panel origin-focus-ring relative w-[214px] rounded-2xl px-3 py-3",
            carouselFocused
              ? "border-[color:color-mix(in_srgb,var(--origin-gold)_72%,transparent)]"
              : "",
          )}
        >
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="origin-glyph-orb origin-glyph-orb--small" aria-hidden="true" />
              <div className="origin-label text-[10px] tracking-[0.15em]">Station Arc</div>
            </div>
            <span className="text-[9px] font-mono text-sdr-text-muted">Tab/Arrows</span>
          </div>

          <div className="relative overflow-visible" style={{ height: railHeight }}>
            {ordered.map((strikecell, index) => {
              const isActive = strikecell.id === activeStrikecellId;
              const isHighlighted = strikecell.id === keyboardHighlightedId;
              const normalized = ordered.length <= 1 ? 0 : (index / (ordered.length - 1)) * 2 - 1;
              const curveOffset = Math.cos(normalized * (Math.PI / 2)) * 36;
              const top = index * 68;
              const isPinned = pinned.left === strikecell.id || pinned.right === strikecell.id;
              const stationId = resolveNexusObservatoryStationId(strikecell.id);

              return (
                <div
                  key={strikecell.id}
                  style={{ top, left: `${14 + curveOffset}px` }}
                  className={clsx(
                    "absolute w-[165px] rounded-lg border transition-all duration-150",
                    isActive
                      ? "border-[color:color-mix(in_srgb,var(--origin-gold)_76%,transparent)] bg-sdr-accent-amber/10 shadow-[0_0_18px_rgba(213,173,87,0.18)]"
                      : isHighlighted
                        ? "border-[color:color-mix(in_srgb,var(--origin-gold-dim)_64%,transparent)] bg-[color:color-mix(in_srgb,var(--origin-gold-dim)_12%,transparent)]"
                        : "border-[color:color-mix(in_srgb,var(--origin-panel-border)_55%,transparent)] bg-sdr-bg-secondary/70",
                  )}
                  onMouseEnter={() => onHighlight(strikecell.id)}
                  onMouseLeave={() => onHighlight(null)}
                >
                  <button
                    type="button"
                    onClick={() => onActivate(strikecell.id)}
                    onDoubleClick={() => onToggleExpanded(strikecell.id)}
                    onContextMenu={(event) => {
                      event.preventDefault();
                      setMenu({ id: strikecell.id, x: event.clientX, y: event.clientY });
                    }}
                    className="origin-focus-ring w-full rounded-lg px-2.5 py-2 text-left"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] font-mono leading-none text-sdr-text-primary">
                        {strikecell.name}
                      </span>
                      <span
                        className={clsx(
                          "rounded border px-1.5 py-0.5 text-[9px] font-mono uppercase",
                          statusClass(strikecell.status),
                        )}
                      >
                        {strikecell.status}
                      </span>
                    </div>
                    <div className="mt-1 text-[10px] font-mono text-sdr-text-muted">
                      {getNexusStationCode(stationId)} {"\u00B7"} {getNexusStationLabel(stationId)}
                    </div>
                    <div className="mt-0.5 text-[10px] font-mono text-sdr-text-muted">
                      {strikecell.activityCount} activity {"\u00B7"} {strikecell.nodeCount} nodes
                    </div>
                    {isPinned ? (
                      <div className="mt-1 text-[9px] font-mono uppercase text-sdr-accent-amber">
                        pinned {pinned.left === strikecell.id ? "left" : "right"}
                      </div>
                    ) : null}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </aside>

      {menu ? (
        <div className="fixed inset-0 z-50" onClick={() => setMenu(null)}>
          <div
            className="origin-chrome-panel absolute min-w-[170px] rounded-md p-1"
            style={{ left: menu.x, top: menu.y }}
            onClick={(event) => event.stopPropagation()}
          >
            <MenuButton
              label={pinned.left === menu.id ? "Unpin Left" : "Pin Left"}
              onClick={() => {
                onPin(menu.id, pinned.left === menu.id ? null : "left");
                setMenu(null);
              }}
            />
            <MenuButton
              label={pinned.right === menu.id ? "Unpin Right" : "Pin Right"}
              onClick={() => {
                onPin(menu.id, pinned.right === menu.id ? null : "right");
                setMenu(null);
              }}
            />
            <div className="my-1 h-px bg-sdr-border" />
            <MenuButton
              label="Move Up"
              onClick={() => {
                onReorder(menu.id, "up");
                setMenu(null);
              }}
            />
            <MenuButton
              label="Move Down"
              onClick={() => {
                onReorder(menu.id, "down");
                setMenu(null);
              }}
            />
          </div>
        </div>
      ) : null}
    </>
  );
}

function MenuButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="origin-focus-ring block w-full rounded px-2 py-1.5 text-left text-[11px] font-mono text-sdr-text-secondary transition-colors hover:bg-sdr-bg-tertiary/70 hover:text-sdr-text-primary"
    >
      {label}
    </button>
  );
}
