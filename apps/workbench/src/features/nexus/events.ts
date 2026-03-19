import type {
  NexusLayoutMode,
  NexusOperationMode,
  NexusViewMode,
  StrikecellDomainId,
} from "./types";

export type CyberNexusCommand =
  | { type: "focus-strikecell"; strikecellId: StrikecellDomainId }
  | { type: "reset-camera" }
  | { type: "open-drawer"; strikecellId: StrikecellDomainId }
  | { type: "open-search" }
  | { type: "set-layout"; layoutMode: NexusLayoutMode }
  | { type: "set-operation-mode"; mode: NexusOperationMode }
  | { type: "set-view-mode"; viewMode: NexusViewMode }
  | { type: "toggle-field" }
  | { type: "focus-next" }
  | { type: "focus-prev" };

export const CYBER_NEXUS_COMMAND_EVENT = "cyber-nexus:command";

export function dispatchCyberNexusCommand(command: CyberNexusCommand) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent<CyberNexusCommand>(CYBER_NEXUS_COMMAND_EVENT, { detail: command }),
  );
}
