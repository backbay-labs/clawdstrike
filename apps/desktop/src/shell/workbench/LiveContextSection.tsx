/**
 * LiveContextSection — Shows active tab, recent tabs, and recent artifacts.
 * Returns null when there's nothing to show.
 */
import type { LiveContextData } from "./useSidebarIntelligence";
import { formatTimeAgo } from "./useSidebarIntelligence";
import { SectionHeader, DataRow } from "./lenses/SharedRows";
import { TAB_KIND_ICONS, ARTIFACT_KIND_ICONS, DocIcon } from "./lenses/LensIcons";

export function LiveContextSection({
  data,
  onSelectTab,
}: {
  data: LiveContextData;
  onSelectTab: (tabId: string) => void;
}) {
  if (data.isEmpty) return null;

  return (
    <div className="flex flex-col py-1">
      <SectionHeader>Live context</SectionHeader>

      {/* Active tab — highlighted with left border */}
      {data.activeTab && (() => {
        const IconComp = TAB_KIND_ICONS[data.activeTab.kind] ?? DocIcon;
        return (
          <div style={{ borderLeft: "2px solid rgba(213,173,87,0.4)", paddingLeft: 8 }}>
            <DataRow
              icon={<IconComp />}
              label={data.activeTab.title}
              meta={data.activeTab.isDirty ? "modified" : undefined}
            />
          </div>
        );
      })()}

      {/* Recent tabs — slightly dimmed */}
      {data.recentTabs.map((tab) => {
        const IconComp = TAB_KIND_ICONS[tab.kind] ?? DocIcon;
        return (
          <div key={tab.id} style={{ opacity: 0.6 }}>
            <DataRow
              icon={<IconComp />}
              label={tab.title}
              meta={tab.isPreview ? "preview" : undefined}
              onClick={() => onSelectTab(tab.id)}
            />
          </div>
        );
      })}

      {/* Recent artifacts */}
      {data.recentArtifacts.map((artifact) => {
        const IconComp = ARTIFACT_KIND_ICONS[artifact.kind];
        const ageMs = Date.now() - artifact.createdAt;
        return (
          <DataRow
            key={artifact.id}
            icon={<IconComp />}
            label={artifact.title}
            meta={formatTimeAgo(ageMs)}
          />
        );
      })}
    </div>
  );
}
