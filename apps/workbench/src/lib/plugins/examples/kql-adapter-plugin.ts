/**
 * Microsoft Sentinel KQL Adapter Plugin
 *
 * Demonstrates a detection format adapter plugin using the createPlugin()
 * factory from @clawdstrike/plugin-sdk. Declares first-class KQL detection
 * format support with a visual tabular expression editor and bidirectional
 * Sigma translation capabilities.
 *
 * The adapter, visual panel, and translation provider are self-registered
 * at module load via registerAdapter(), registerVisualPanel(), and
 * registerTranslationProvider(). This manifest serves as declarative
 * documentation of those contributions for the plugin loader.
 */

import { createPlugin } from "../plugin-sdk-shim";
import type { PluginContext } from "../plugin-sdk-shim";

export default createPlugin({
  manifest: {
    id: "clawdstrike.kql-adapter",
    name: "kql-adapter",
    displayName: "Microsoft Sentinel KQL Adapter",
    description:
      "First-class KQL detection format support with visual tabular expression editor and bidirectional Sigma translation.",
    version: "1.0.0",
    publisher: "clawdstrike",
    categories: ["detection"],
    trust: "internal",
    activationEvents: ["onFileType:kql_rule"],
    main: "./kql-adapter-plugin.ts",
    contributions: {
      detectionAdapters: [
        {
          fileType: "kql_rule",
          entrypoint: "./kql-adapter.ts",
          fileTypeDescriptor: {
            label: "Microsoft Sentinel KQL Rule",
            shortLabel: "KQL",
            extensions: [".kql"],
            iconColor: "#0078d4",
            defaultContent: [
              "// KQL Detection Rule",
              "SecurityEvent",
              '| where EventID == 4688',
              '| where CommandLine contains "powershell"',
              "| project TimeGenerated, Computer, CommandLine",
            ].join("\n"),
            testable: true,
          },
          hasVisualPanel: true,
          translations: [
            {
              from: "sigma_rule",
              to: "kql_rule",
              lossless: true,
            },
            {
              from: "kql_rule",
              to: "sigma_rule",
              lossless: false,
              lossDescription:
                "KQL aggregation (summarize), joins, time functions, and project clauses cannot be expressed in Sigma",
            },
          ],
        },
      ],
    },
  },
  activate(_ctx: PluginContext) {
    // The adapter, visual panel, and translation provider are self-registered
    // at module load via registerAdapter(), registerVisualPanel(), and
    // registerTranslationProvider(). The manifest above is declarative
    // documentation of those contributions for the plugin loader.
  },
});
