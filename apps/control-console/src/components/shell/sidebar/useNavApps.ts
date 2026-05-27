import { useDesktopOS } from "@backbay/glia-desktop";
import { type FC, useMemo } from "react";
import {
  type DesktopIconGroupId,
  desktopIconGroups,
  PROCESS_ICONS,
  PROCESS_TONE,
} from "../../../state/processRegistry";

export type NavTone = "gold" | "teal" | "muted";

/** Size-aware sigil component; consumers render it at their own density. */
export type NavSigil = FC<{ size?: number }>;

export interface NavApp {
  processId: string;
  label: string;
  description: string;
  Sigil: NavSigil;
  tone: NavTone;
  running: boolean;
  active: boolean;
}

export interface NavGroup {
  id: DesktopIconGroupId;
  label: string;
  apps: NavApp[];
}

/**
 * Projects the static desktop icon groups onto live process state, yielding the
 * grouped nav model the sidebar renders. `running` reflects open instances and
 * `active` reflects the focused window.
 */
export function useNavApps(): NavGroup[] {
  const { processes, windows } = useDesktopOS();
  const { instances } = processes;
  const { focusedId } = windows;

  return useMemo(() => {
    const runningIds = new Set(instances.map((instance) => instance.processId));
    const activeId = instances.find((instance) => instance.windowId === focusedId)?.processId;

    return desktopIconGroups.map((group) => ({
      id: group.id,
      label: group.label,
      apps: group.icons.map((icon) => ({
        processId: icon.processId,
        label: icon.label,
        description: processes.getDefinition(icon.processId)?.description ?? "",
        Sigil: PROCESS_ICONS[icon.processId],
        tone: PROCESS_TONE[icon.processId] ?? "gold",
        running: runningIds.has(icon.processId),
        active: icon.processId === activeId,
      })),
    }));
  }, [processes, instances, focusedId]);
}

/** The single focused app, for breadcrumbs and header context. */
export function useActiveNavApp(): NavApp | null {
  const groups = useNavApps();
  return useMemo(() => {
    for (const group of groups) {
      const match = group.apps.find((app) => app.active);
      if (match) return match;
    }
    return null;
  }, [groups]);
}
