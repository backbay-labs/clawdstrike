import { clsx } from "clsx";
import type { Strikecell, StrikecellDomainId } from "../types";

interface NexusBreadcrumbsProps {
  strikecells: Strikecell[];
  activeStrikecellId: StrikecellDomainId | null;
  expandedStrikecellIds: StrikecellDomainId[];
  onSelectStrikecell: (id: StrikecellDomainId) => void;
  onCollapseToRoot: () => void;
}

function resolveLabel(strikecells: Strikecell[], id: StrikecellDomainId | null): string {
  if (!id) return "Cyber Nexus";
  return strikecells.find((strikecell) => strikecell.id === id)?.name ?? id;
}

export function NexusBreadcrumbs({
  strikecells,
  activeStrikecellId,
  expandedStrikecellIds,
  onSelectStrikecell,
  onCollapseToRoot,
}: NexusBreadcrumbsProps) {
  return (
    <div className="origin-chrome-panel relative z-20 mx-3 mt-2 flex items-center justify-between gap-4 rounded-lg px-3 py-2">
      <div className="flex min-w-0 items-center gap-2 overflow-x-auto">
        <button
          type="button"
          onClick={onCollapseToRoot}
          className="origin-focus-ring origin-headline rounded px-1.5 py-0.5 text-[11px] transition-colors hover:text-[color:var(--origin-gold)]"
        >
          Cyber Nexus
        </button>

        {activeStrikecellId ? (
          <>
            <span className="text-sdr-text-muted">›</span>
            <button
              type="button"
              onClick={() => onSelectStrikecell(activeStrikecellId)}
              className="origin-focus-ring rounded px-1.5 py-0.5 text-xs font-semibold text-sdr-text-primary transition-colors hover:text-[color:var(--origin-gold)]"
            >
              {resolveLabel(strikecells, activeStrikecellId)}
            </button>
          </>
        ) : null}

        {expandedStrikecellIds.map((id, index) => (
          <span key={`expanded:${id}`} className="inline-flex items-center gap-2">
            <span className="text-sdr-text-muted">›</span>
            <button
              type="button"
              onClick={() => onSelectStrikecell(id)}
              className={clsx(
                "origin-focus-ring rounded border px-1.5 py-0.5 text-[10px] font-mono uppercase transition-colors",
                index === expandedStrikecellIds.length - 1
                  ? "border-[color:color-mix(in_srgb,var(--origin-gold)_66%,transparent)] text-[color:var(--origin-gold)]"
                  : "border-[color:color-mix(in_srgb,var(--origin-steel-bright)_48%,transparent)] text-sdr-text-secondary hover:text-sdr-text-primary",
              )}
            >
              {resolveLabel(strikecells, id)}
            </button>
          </span>
        ))}
      </div>

      <div className="origin-label hidden text-[10px] sm:block">
        {activeStrikecellId ? "drill depth " + (expandedStrikecellIds.length + 1) : "root graph"}
      </div>
    </div>
  );
}
