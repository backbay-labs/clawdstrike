// NexusTab -- store bridge that reads workbench Zustand stores and renders
// the full CyberNexusView ported from huntronomer.

import { useNexusStore } from "../stores/nexus-store";
import { CyberNexusView } from "./CyberNexusView";

export function NexusTab() {
  const strikecells = useNexusStore.use.strikecells();

  return (
    <div className="relative flex-1 overflow-hidden" data-testid="nexus-tab">
      <CyberNexusView strikecells={strikecells} />
    </div>
  );
}
