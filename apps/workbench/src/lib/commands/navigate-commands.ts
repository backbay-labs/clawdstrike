import { commandRegistry } from "@/lib/command-registry";
import type { Command } from "@/lib/command-registry";
import { usePaneStore } from "@/features/panes/pane-store";
import { openQuickOpen } from "@/features/navigation/quick-open-dialog";

export function registerNavigateCommands(): void {
  const commands: Command[] = [
    // ---- Quick Open ----
    {
      id: "nav.quickOpen",
      title: "Quick Open",
      category: "Navigate",
      keybinding: "Meta+P",
      execute: () => openQuickOpen(),
    },

    // ---- Existing nav.* commands (openApp pattern) ----
    {
      id: "nav.home",
      title: "Home",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/home", "Home"),
    },
    {
      id: "nav.lab",
      title: "Lab",
      category: "Navigate",
      keybinding: "Meta+2",
      execute: () => usePaneStore.getState().openApp("/lab", "Lab"),
    },
    {
      id: "nav.sentinels",
      title: "Sentinels",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/sentinels", "Sentinels"),
    },
    {
      id: "nav.findings",
      title: "Findings & Intel",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/findings", "Findings"),
    },
    {
      id: "nav.fleet",
      title: "Fleet Dashboard",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/fleet", "Fleet"),
    },
    {
      id: "nav.approvals",
      title: "Approvals",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/approvals", "Approvals"),
    },
    {
      id: "nav.audit",
      title: "Audit Log",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/audit", "Audit"),
    },
    {
      id: "nav.compliance",
      title: "Compliance",
      category: "Navigate",
      keybinding: "Meta+3",
      execute: () =>
        usePaneStore.getState().openApp("/compliance", "Compliance"),
    },
    {
      id: "nav.receipts",
      title: "Receipts",
      category: "Navigate",
      keybinding: "Meta+4",
      execute: () => usePaneStore.getState().openApp("/receipts", "Receipts"),
    },
    {
      id: "nav.topology",
      title: "Topology",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/topology", "Topology"),
    },
    {
      id: "nav.swarms",
      title: "Swarms",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/swarms", "Swarms"),
    },
    {
      id: "nav.library",
      title: "Policy Library",
      category: "Navigate",
      keybinding: "Meta+5",
      execute: () => usePaneStore.getState().openApp("/library", "Library"),
    },
    {
      id: "nav.settings",
      title: "Settings",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/settings", "Settings"),
    },
    {
      id: "nav.missions",
      title: "Mission Control",
      category: "Navigate",
      execute: () =>
        usePaneStore.getState().openApp("/missions", "Mission Control"),
    },
    {
      id: "nav.simulator",
      title: "Threat Simulator",
      category: "Navigate",
      keybinding: "Meta+6",
      execute: () =>
        usePaneStore.getState().openApp("/simulator", "Simulator"),
    },

    // ---- Detection editor views (07-01) ----
    {
      id: "nav.guards",
      title: "Guards Browser",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/guards", "Guards"),
    },
    {
      id: "nav.compare",
      title: "Compare / Diff",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/compare", "Compare"),
    },
    {
      id: "nav.liveAgent",
      title: "Live Agent Monitor",
      category: "Navigate",
      execute: () =>
        usePaneStore.getState().openApp("/live-agent", "Live Agent"),
    },
    {
      id: "nav.sdkIntegration",
      title: "SDK Integration",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/sdk-integration", "SDK Integration"),
    },
    {
      id: "nav.coverage",
      title: "ATT&CK Coverage Heatmap",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/coverage", "Coverage"),
    },

    // ---- Visual Builders (07-03) ----
    {
      id: "nav.visualSigma",
      title: "Open Sigma Visual Builder",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/visual-builder/sigma", "Sigma Builder"),
    },
    {
      id: "nav.visualYara",
      title: "Open YARA Visual Builder",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/visual-builder/yara", "YARA Builder"),
    },
    {
      id: "nav.visualOcsf",
      title: "Open OCSF Visual Builder",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/visual-builder/ocsf", "OCSF Builder"),
    },

    // ---- TrustPrint Suite (07-03) ----
    {
      id: "nav.trustprintPatterns",
      title: "TrustPrint: Pattern Explorer",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/trustprint/patterns", "TrustPrint Patterns"),
    },
    {
      id: "nav.trustprintProviders",
      title: "TrustPrint: Provider Wizard",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/trustprint/providers", "TrustPrint Providers"),
    },
    {
      id: "nav.trustprintThresholds",
      title: "TrustPrint: Threshold Tuner",
      category: "Navigate",
      execute: () =>
        usePaneStore
          .getState()
          .openApp("/trustprint/thresholds", "TrustPrint Thresholds"),
    },

    // ---- Unique app.* commands (no nav.* duplicate) ----
    {
      id: "app.swarmBoard",
      title: "Open Swarm Board",
      category: "Navigate",
      execute: () =>
        usePaneStore.getState().openApp("/swarm-board", "Swarm Board"),
    },
    {
      id: "nav.newSwarm",
      title: "New Swarm Board",
      category: "File",
      execute: async () => {
        const { isDesktop, createSwarmBundle } = await import("@/lib/tauri-bridge");
        if (!isDesktop()) return;

        // Use the first mounted workspace root as the parent directory
        const { useProjectStore } = await import("@/features/project/stores/project-store");
        const roots = useProjectStore.getState().projectRoots;
        if (roots.length === 0) return;
        const parentDir = roots[0];

        // Generate a default name with timestamp
        const timestamp = new Date().toISOString().slice(0, 10);
        const name = `investigation-${timestamp}`;

        const bundlePath = await createSwarmBundle(parentDir, name);
        if (!bundlePath) return;

        // Refresh the Explorer tree so the new .swarm entry appears
        await useProjectStore.getState().actions.loadRoot(parentDir);

        // Open the new board
        const label = name.replace(/\.swarm$/, "");
        usePaneStore.getState().openApp(
          `/swarm-board/${encodeURIComponent(bundlePath)}`,
          label,
        );
      },
    },
    // ---- Editor-to-Swarm bridge (12-01) ----
    {
      id: "swarm.launchFromEditor",
      title: "Launch Swarm from Active Policy",
      category: "Swarm",
      execute: async () => {
        const { isDesktop, createSwarmBundleFromPolicy } = await import("@/lib/tauri-bridge");
        if (!isDesktop()) return;

        // Get active tab metadata
        const { usePolicyTabsStore } = await import("@/features/policy/stores/policy-tabs-store");
        const tabsState = usePolicyTabsStore.getState();
        const activeTab = tabsState.tabs.find((t) => t.id === tabsState.activeTabId);
        if (!activeTab?.filePath) return;

        // Only launch for policy files
        const { isPolicyFileType } = await import("@/lib/workbench/file-type-registry");
        if (!isPolicyFileType(activeTab.fileType)) return;

        // Get project root
        const { useProjectStore } = await import("@/features/project/stores/project-store");
        const roots = useProjectStore.getState().projectRoots;
        if (roots.length === 0) return;
        const parentDir = roots[0];

        // Get active sentinels
        const { useSentinelStore } = await import("@/features/sentinels/stores/sentinel-store");
        const sentinels = useSentinelStore.getState().sentinels
          .filter((s) => s.status === "active")
          .map((s) => ({ id: s.id, name: s.name, mode: s.mode }));

        const policyFileName = activeTab.name || activeTab.filePath.split("/").pop() || "policy";
        const bundlePath = await createSwarmBundleFromPolicy({
          parentDir,
          policyFileName,
          policyFilePath: activeTab.filePath,
          sentinels,
        });
        if (!bundlePath) return;

        // Refresh explorer tree
        await useProjectStore.getState().actions.loadRoot(parentDir);

        // Open in pane tab (SWARM-02)
        const label = policyFileName.replace(/\.(ya?ml|json)$/i, "") + " Swarm";
        usePaneStore.getState().openApp(
          `/swarm-board/${encodeURIComponent(bundlePath)}`,
          label,
        );
      },
    },
    {
      id: "app.hunt",
      title: "Open Threat Hunt",
      category: "Navigate",
      execute: () => usePaneStore.getState().openApp("/hunt", "Hunt"),
    },
  ];

  commandRegistry.registerAll(commands);
}
