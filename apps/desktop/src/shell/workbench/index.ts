export { WorkbenchShell } from "./WorkbenchShell";
export { WorkbenchStateProvider, useWorkbench, useShell, useLens, useBottomPanel, useContextInspector, useWorkbenchDispatch, useActiveTab, useTabGroup, useTabs, useSelection, useHuntStore, useActiveHunt, useHuntDock, useHuntArtifacts, useBucketSummaryCollapsed } from "./WorkbenchStateProvider";
export { DragDropProvider, useDragSource, useDropTarget } from "./DragDropContext";
export type { DragPayload } from "./DragDropContext";
export { BucketSummary } from "./BucketSummary";
export { ActivitySpine } from "./ActivitySpine";
export { OrbLensRotor } from "./OrbLensRotor";
export { HuntDock } from "./HuntDock";
export { LensSidebar } from "./LensSidebar";
export { StatusBar } from "./StatusBar";
export * from "./workbenchState";
export * from "./huntTypes";
export type { HuntAction } from "./huntReducer";
export { TAB_REGISTRY, getTabRegistryEntry } from "./tabRegistry";
export type { TabContentProps, TabRegistryEntry } from "./tabRegistry";
export { TabBar } from "./TabBar";
export { TabContentRenderer } from "./TabContentRenderer";
export { SplitPaneContainer } from "./SplitPaneContainer";
export { BottomPanel } from "./BottomPanel";
export { ContextInspector } from "./ContextInspector";
export { ContextTab } from "./inspector/ContextTab";
export { GraphTab } from "./inspector/GraphTab";
export { ProofTab } from "./inspector/ProofTab";
export { CompanionTab } from "./inspector/CompanionTab";
export { BOTTOM_PANEL_REGISTRY, getBottomPanelEntry } from "./bottomPanelRegistry";
export type { BottomPanelRegistryEntry } from "./bottomPanelRegistry";

export function isWorkbenchV2Enabled(): boolean {
  try {
    // v2 workbench is the default; set "huntronomer:workbench:v2" to "0" to revert to v1
    return globalThis.localStorage?.getItem("huntronomer:workbench:v2") !== "0";
  } catch {
    return true;
  }
}
