import { lazy } from "react";
import { createPlugin } from "../plugin-sdk-shim";

export default createPlugin({
  manifest: {
    id: "clawdstrike.plugin-playground",
    name: "plugin-playground",
    displayName: "Plugin Playground",
    description: "In-app plugin development playground with live preview",
    version: "0.1.0",
    publisher: "clawdstrike",
    categories: ["ui"],
    trust: "internal",
    activationEvents: ["onStartup"],
    contributions: {
      activityBarItems: [
        {
          id: "plugin-dev",
          section: "tools",
          label: "Plugin Dev",
          icon: "Puzzle",
          href: "/plugin-dev",
          order: 90,
        },
      ],
      editorTabs: [
        {
          id: "playground-editor",
          label: "Plugin Playground",
          icon: "Code",
          entrypoint: "",
        },
      ],
      rightSidebarPanels: [
        {
          id: "contribution-inspector",
          label: "Contributions",
          icon: "TreePine",
          entrypoint: "",
        },
      ],
      bottomPanelTabs: [
        {
          id: "plugin-console",
          label: "Plugin Console",
          icon: "Terminal",
          entrypoint: "",
        },
      ],
    },
  },

  activate(ctx) {
    const editorTabDispose = ctx.views.registerEditorTab({
      id: "playground-editor",
      label: "Plugin Playground",
      icon: "Code",
      component: lazy(
        () => import("@/components/plugins/playground/PlaygroundEditorPane"),
      ),
    });
    ctx.subscriptions.push(editorTabDispose);

    const sidebarDispose = ctx.views.registerRightSidebarPanel({
      id: "contribution-inspector",
      label: "Contributions",
      icon: "TreePine",
      component: lazy(
        () => import("@/components/plugins/playground/ContributionInspector"),
      ),
    });
    ctx.subscriptions.push(sidebarDispose);

    const consolePanelDispose = ctx.views.registerBottomPanelTab({
      id: "plugin-console",
      label: "Plugin Console",
      icon: "Terminal",
      component: lazy(
        () => import("@/components/plugins/playground/PluginConsolePanel"),
      ),
    });
    ctx.subscriptions.push(consolePanelDispose);
  },
});
