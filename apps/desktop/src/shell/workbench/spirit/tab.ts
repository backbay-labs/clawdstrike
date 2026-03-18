import type { Hunt } from "../huntTypes";
import type { TabState } from "../workbenchState";
import type { SpiritChamberRequestSource } from "./components/SpiritSurfaceBridge";

export const SPIRIT_CHAMBER_TAB_KIND = "spirit-chamber" as const;

const SPIRIT_CHAMBER_SOURCE_PREFIX = "spirit-chamber:";

export interface SpiritChamberTabMetadata {
  huntId: string;
  source: SpiritChamberRequestSource;
}

function isSpiritChamberMetadata(value: unknown): value is SpiritChamberTabMetadata {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SpiritChamberTabMetadata>;
  return typeof candidate.huntId === "string" && typeof candidate.source === "string";
}

export function buildSpiritChamberSourceUri(huntId: string): string {
  return `${SPIRIT_CHAMBER_SOURCE_PREFIX}${huntId}`;
}

export function buildSpiritChamberTab(
  hunt: Hunt,
  source: SpiritChamberRequestSource,
): Omit<TabState, "id"> {
  return {
    kind: SPIRIT_CHAMBER_TAB_KIND,
    title: `${hunt.title} Spirit`,
    subtitle: "Spirit",
    icon: "S",
    isPreview: false,
    isPinned: false,
    isDirty: false,
    sourceUri: buildSpiritChamberSourceUri(hunt.id),
    metadata: {
      huntId: hunt.id,
      source,
    },
  };
}

export function readSpiritChamberMetadata(tab: Pick<TabState, "metadata">): SpiritChamberTabMetadata | null {
  return isSpiritChamberMetadata(tab.metadata) ? tab.metadata : null;
}

export function readSpiritChamberHuntId(tab: Pick<TabState, "metadata" | "sourceUri">): string | null {
  const metadata = readSpiritChamberMetadata(tab);
  if (metadata) {
    return metadata.huntId;
  }

  if (!tab.sourceUri?.startsWith(SPIRIT_CHAMBER_SOURCE_PREFIX)) {
    return null;
  }

  const huntId = tab.sourceUri.slice(SPIRIT_CHAMBER_SOURCE_PREFIX.length);
  return huntId.length > 0 ? huntId : null;
}
