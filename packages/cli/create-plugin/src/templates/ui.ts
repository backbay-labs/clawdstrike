import type { ScaffoldOptions } from "../types";

export function uiSourceTemplate(options: ScaffoldOptions): string {
  return `import { createPlugin } from "@clawdstrike/plugin-sdk";
import type {
  PluginContext,
  EditorTabContribution,
  ActivityBarItemContribution,
  CommandContribution,
} from "@clawdstrike/plugin-sdk";

const editorTab: EditorTabContribution = {
  id: "${options.name}-panel",
  label: "${options.displayName}",
  icon: "layout-panel-top",
  entrypoint: "./panel",
};

const activityBarItem: ActivityBarItemContribution = {
  id: "${options.name}-sidebar",
  section: "plugins",
  label: "${options.displayName}",
  icon: "puzzle",
  href: "/${options.name}",
};

const openCommand: CommandContribution = {
  id: "${options.publisher}.${options.name}.open",
  title: "Open ${options.displayName}",
};

export default createPlugin({
  manifest: {
    id: "${options.publisher}.${options.name}",
    name: "${options.name}",
    displayName: "${options.displayName}",
    description: "A UI extension plugin for ClawdStrike",
    version: "0.1.0",
    publisher: "${options.publisher}",
    categories: ["ui"],
    trust: "internal",
    activationEvents: ["onStartup"],
    main: "./dist/index.js",
    contributions: {
      editorTabs: [editorTab],
      activityBarItems: [activityBarItem],
      commands: [openCommand],
    },
  },

  activate(ctx: PluginContext) {
    const cmdDisposable = ctx.commands.register(openCommand, () => {
      console.log("Open ${options.displayName}");
    });
    ctx.subscriptions.push(cmdDisposable);
  },

  deactivate() {
    // Cleanup handled by subscriptions
  },
});
`;
}
