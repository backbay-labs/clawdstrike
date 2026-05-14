import type { ScaffoldOptions } from "../types";

export function guardSourceTemplate(options: ScaffoldOptions): string {
  const technicalName = options.name.replace(/-/g, "_");

  return `import { createPlugin } from "@clawdstrike/plugin-sdk";
import type { PluginContext, GuardContribution, CommandContribution } from "@clawdstrike/plugin-sdk";

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

export default createPlugin({
  manifest: {
    id: "${options.publisher}.${options.name}",
    name: "${options.name}",
    displayName: "${options.displayName}",
    description: "A guard plugin for ClawdStrike",
    version: "0.1.0",
    publisher: "${options.publisher}",
    categories: ["guards"],
    trust: "community",
    activationEvents: ["onStartup"],
    main: "./dist/index.js",
    contributions: {
      guards: [guardDef],
      commands: [configureCommand],
    },
  },

  activate(ctx: PluginContext) {
    const guardDisposable = ctx.guards.register(guardDef);
    ctx.subscriptions.push(guardDisposable);

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
