import type { ScaffoldOptions } from "../types";

export function fullSourceTemplate(options: ScaffoldOptions): string {
  const technicalName = options.name.replace(/-/g, "_");
  const shortLabel = options.name.slice(0, 3).toUpperCase();

  return `import { createPlugin } from "@clawdstrike/plugin-sdk";
import type {
  PluginContext,
  GuardContribution,
  CommandContribution,
  FileTypeContribution,
  ThreatIntelSourceContribution,
  EditorTabContribution,
  ActivityBarItemContribution,
} from "@clawdstrike/plugin-sdk";


const guardDef: GuardContribution = {
  id: "${options.name}-guard",
  name: "${options.displayName} Guard",
  technicalName: "${technicalName}",
  description: "Custom guard provided by ${options.displayName}",
  category: "custom",
  defaultVerdict: "deny",
  icon: "shield",
  configFields: [
    {
      key: "enabled",
      label: "Enabled",
      type: "toggle",
      defaultValue: true,
    },
  ],
};


const configureCommand: CommandContribution = {
  id: "${options.publisher}.${options.name}.configure",
  title: "Configure ${options.displayName}",
};


const fileTypeDef: FileTypeContribution = {
  id: "${options.name}",
  label: "${options.displayName}",
  shortLabel: "${shortLabel}",
  extensions: [".${options.name}"],
  iconColor: "#4FC3F7",
  defaultContent: "// ${options.displayName} detection rule\\n",
  testable: true,
};

const intelSource: ThreatIntelSourceContribution = {
  id: "${options.name}-intel",
  name: "${options.displayName}",
  description: "Threat intelligence source provided by ${options.displayName}",
  entrypoint: "./source",
};

const editorTab: EditorTabContribution = {
  id: "${options.name}-panel",
  label: "${options.displayName}",
  icon: "layout-panel-top",
  entrypoint: "./panel",
};

const bottomPanelTab = {
  id: "${options.name}-bottom",
  label: "${options.displayName} Output",
  entrypoint: "./panel",
};

const rightSidebarPanel = {
  id: "${options.name}-inspector",
  label: "${options.displayName} Inspector",
  icon: "search",
  entrypoint: "./panel",
};

const statusBarItem = {
  id: "${options.name}-status",
  side: "right" as const,
  priority: 50,
  entrypoint: "./status-widget",
};

const activityBarItem: ActivityBarItemContribution = {
  id: "${options.name}-sidebar",
  section: "plugins",
  label: "${options.displayName}",
  icon: "puzzle",
  href: "/${options.name}",
};

export default createPlugin({
  manifest: {
    id: "${options.publisher}.${options.name}",
    name: "${options.name}",
    displayName: "${options.displayName}",
    description: "A full-featured plugin for ClawdStrike",
    version: "0.1.0",
    publisher: "${options.publisher}",
    categories: ["guards", "detection", "intel", "ui"],
    trust: "internal",
    activationEvents: ["onStartup"],
    main: "./dist/index.js",
    contributions: {
      guards: [guardDef],
      commands: [configureCommand],
      fileTypes: [fileTypeDef],
      threatIntelSources: [intelSource],
      editorTabs: [editorTab],
      bottomPanelTabs: [bottomPanelTab],
      rightSidebarPanels: [rightSidebarPanel],
      statusBarItems: [statusBarItem],
      activityBarItems: [activityBarItem],
    },
  },

  activate(ctx: PluginContext) {
    // Register guard
    const guardDisposable = ctx.guards.register(guardDef);
    ctx.subscriptions.push(guardDisposable);

    // Register file type
    const ftDisposable = ctx.fileTypes.register(fileTypeDef);
    ctx.subscriptions.push(ftDisposable);

    // Register command
    const cmdDisposable = ctx.commands.register(configureCommand, () => {
      console.log("Configure ${options.displayName}");
    });
    ctx.subscriptions.push(cmdDisposable);
  },

  deactivate() {
    // Cleanup handled by subscriptions
  },
});
`;
}
