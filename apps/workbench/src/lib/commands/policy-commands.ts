import { commandRegistry } from "@/lib/command-registry";
import type { Command } from "@/lib/command-registry";
import type { WorkbenchPolicy } from "@/lib/workbench/types";
import type { TabMeta } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { isDesktop } from "@/lib/tauri-bridge";
import { isPolicyFileType } from "@/lib/workbench/file-type-registry";
import { policyToYaml } from "@/features/policy/yaml-utils";
import { triggerNativeValidation } from "@/features/policy/use-native-validation";
import { usePaneStore } from "@/features/panes/pane-store";

export interface PolicyCommandDeps {
  getActiveTab: () => TabMeta | undefined;
  getActivePolicy: () => WorkbenchPolicy;
  getYaml: () => string;
  getDirty: () => boolean;
}

export function registerPolicyCommands(deps: PolicyCommandDeps): void {
  const { getActiveTab, getActivePolicy, getYaml, getDirty } = deps;

  const commands: Command[] = [
    {
      id: "policy.validate",
      title: "Validate Current File",
      category: "Policy",
      keybinding: "Meta+Shift+V",
      context: "editor",
      execute: () => {
        const tab = getActiveTab();
        if (!tab) return;

        const source = isPolicyFileType(tab.fileType)
          ? policyToYaml(getActivePolicy())
          : getYaml();

        const shouldSyncYaml =
          isPolicyFileType(tab.fileType) && (getDirty() || source !== getYaml());

        if (shouldSyncYaml) {
          const editStore = usePolicyEditStore.getState();
          editStore.setYaml(tab.id, source, tab.fileType, tab.filePath, tab.name);
        }

        if (isDesktop()) {
          void triggerNativeValidation(tab.fileType, source, (action) => {
            usePolicyEditStore.getState().setNativeValidation(tab.id, action.payload);
          });
        }

        // Validation runs in-place -- no navigation needed (user is already viewing the file)
      },
    },
    {
      id: "policy.createSentinel",
      title: "Create Sentinel",
      category: "Sentinel",
      execute: () => usePaneStore.getState().openApp("/sentinels/create", "Create Sentinel"),
    },
    {
      id: "policy.connectFleet",
      title: "Connect to Fleet",
      category: "Fleet",
      execute: () => usePaneStore.getState().openApp("/settings", "Settings"),
    },
  ];

  commandRegistry.registerAll(commands);
}
