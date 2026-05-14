import type { ScaffoldOptions } from "../types";

export function intelSourceTemplate(options: ScaffoldOptions): string {
  return `import { createPlugin } from "@clawdstrike/plugin-sdk";
import type {
  PluginContext,
  ThreatIntelSourceContribution,
  CommandContribution,
} from "@clawdstrike/plugin-sdk";

const intelSource: ThreatIntelSourceContribution = {
  id: "${options.name}-intel",
  name: "${options.displayName}",
  description: "Threat intelligence source provided by ${options.displayName}",
  entrypoint: "./source",
};

const lookupCommand: CommandContribution = {
  id: "${options.publisher}.${options.name}.lookup",
  title: "Lookup via ${options.displayName}",
};

export default createPlugin({
  manifest: {
    id: "${options.publisher}.${options.name}",
    name: "${options.name}",
    displayName: "${options.displayName}",
    description: "A threat intel source plugin for ClawdStrike",
    version: "0.1.0",
    publisher: "${options.publisher}",
    categories: ["intel"],
    trust: "internal",
    activationEvents: ["onStartup"],
    main: "./dist/index.js",
    contributions: {
      threatIntelSources: [intelSource],
      commands: [lookupCommand],
    },
    requiredSecrets: [
      {
        key: "api_key",
        label: "${options.displayName} API Key",
        description: "API key for ${options.displayName} lookups",
      },
    ],
  },

  activate(ctx: PluginContext) {
    const cmdDisposable = ctx.commands.register(lookupCommand, () => {
      console.log("Lookup via ${options.displayName}");
    });
    ctx.subscriptions.push(cmdDisposable);
  },

  deactivate() {
    // Cleanup handled by subscriptions
  },
});
`;
}
