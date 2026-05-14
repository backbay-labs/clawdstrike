import type { ComponentType } from "react";
import type { SigilProps } from "@/components/desktop/sidebar-icons";
import {
  SigilSentinel,
  SigilFindings,
  SigilEditor,
  SigilLibrary,
  SigilFleet,
  SigilCompliance,
  SigilHunt,
  SigilObservatory,
} from "@/components/desktop/sidebar-icons";
import { IconSearch, IconUsers } from "@tabler/icons-react";

/**
 * Panel IDs for the activity bar. Each maps to a sidebar panel view.
 *
 * "settings" is intentionally excluded -- it navigates to /settings rather
 * than opening a sidebar panel.
 */
export type ActivityBarItemId =
  | "heartbeat"
  | "hunt"
  | "sentinels"
  | "findings"
  | "explorer"
  | "search"
  | "library"
  | "fleet"
  | "compliance"
  | "people"
  | "observatory";

export interface ActivityBarItemConfig {
  id: ActivityBarItemId;
  label: string;
  tooltip: string;
  icon: ComponentType<SigilProps>;
}

/**
 * Config array for the 6 standard activity bar items. The heartbeat item is
 * special-cased in the ActivityBar component (renders the SystemHeartbeat
 * diamond inline rather than a standard sigil).
 */
export const ACTIVITY_BAR_ITEMS: readonly ActivityBarItemConfig[] = [
  { id: "hunt", label: "Hunt", tooltip: "Hunt (artifacts & observatory)", icon: SigilHunt },
  { id: "sentinels", label: "Sentinels", tooltip: "Sentinels", icon: SigilSentinel },
  { id: "findings", label: "Findings & Intel", tooltip: "Findings & Intel", icon: SigilFindings },
  { id: "explorer", label: "Explorer", tooltip: "Explorer (Cmd+Shift+E)", icon: SigilEditor },
  { id: "search", label: "Search", tooltip: "Search (Cmd+Shift+F)", icon: IconSearch },
  { id: "library", label: "Library", tooltip: "Library", icon: SigilLibrary },
  { id: "fleet", label: "Fleet & Topology", tooltip: "Fleet & Topology", icon: SigilFleet },
  { id: "compliance", label: "Compliance", tooltip: "Compliance", icon: SigilCompliance },
  { id: "people", label: "People", tooltip: "People", icon: IconUsers },
  { id: "observatory", label: "Observatory", tooltip: "Observatory Minimap", icon: SigilObservatory },
];
