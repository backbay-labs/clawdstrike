/**
 * SuggestedSection — Ranked items with reason labels.
 * Returns null when there are no suggestions.
 */
import type { SuggestedItem } from "./useSidebarIntelligence";
import { SectionHeader, ReasonRow } from "./lenses/SharedRows";
import { ARTIFACT_KIND_ICONS } from "./lenses/LensIcons";

export function SuggestedSection({ items }: { items: SuggestedItem[] }) {
  if (items.length === 0) return null;

  return (
    <div className="flex flex-col py-1">
      <SectionHeader>Suggested</SectionHeader>
      {items.map((item) => {
        const IconComp = ARTIFACT_KIND_ICONS[item.kind];
        return (
          <ReasonRow
            key={item.id}
            icon={<IconComp />}
            label={item.title}
            reason={item.reason}
            meta={item.sourceUri?.split("/").pop()}
            dragPayload={item.dragPayload}
          />
        );
      })}
    </div>
  );
}
