# Plugin Manifest

The `PluginManifest` is the central contract that describes what a plugin provides. It declares identity, trust level, contribution points, activation triggers, and distribution metadata. All downstream systems (registry, loader, SDK) depend on this type.

## Fields

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Reverse-domain plugin identifier (e.g. `"clawdstrike.egress-guard"`). Must be unique across the registry. |
| `name` | `string` | Package name in kebab-case (e.g. `"egress-guard"`). |
| `displayName` | `string` | Human-readable name for UI rendering (e.g. `"Egress Guard"`). |
| `description` | `string` | Short description of what the plugin does. |
| `version` | `string` | Semantic version string (e.g. `"1.0.0"`, `"2.1.0-beta.1"`). |
| `publisher` | `string` | Publisher name or organization. |
| `categories` | `PluginCategory[]` | Plugin categories for filtering and discovery. Well-known values: `"guards"`, `"detection"`, `"intel"`, `"compliance"`, `"ui"`, `"integration"`. |
| `trust` | `PluginTrustTier` | Trust tier -- determines loading strategy and sandbox level. |
| `activationEvents` | `ActivationEvent[]` | Events that trigger plugin activation. |

### Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `main` | `string` | Entry point path for plugin code (relative to plugin root). |
| `contributions` | `PluginContributions` | All contribution point declarations. See [Contribution Points](contribution-points.md). |
| `installation` | `InstallationMetadata` | Distribution and installation metadata. See [Publishing](publishing.md). |
| `requiredSecrets` | `PluginSecretDeclaration[]` | Secrets the plugin requires (e.g. API keys). |

## Trust tiers

The `trust` field determines how the plugin is loaded:

| Tier | Loading strategy | API access |
|------|-----------------|------------|
| `"internal"` | In-process, no sandbox | Full workbench APIs |
| `"community"` | Sandboxed iframe | Mediated via postMessage bridge |
| `"mcp"` | MCP protocol bridge | MCP tool interface |

Community plugins run in an iframe sandbox with a permissions system. Only APIs explicitly granted by the user are available. Internal plugins are built-in and have full access.

## Activation events

The `activationEvents` array controls when your plugin is activated. Lazy activation keeps startup fast.

| Pattern | Description | Example |
|---------|-------------|---------|
| `"onStartup"` | Activate immediately on workbench load | `["onStartup"]` |
| `"onFileType:{type}"` | Activate when a file of the given type is opened | `["onFileType:spl"]` |
| `"onCommand:{id}"` | Activate when a specific command is invoked | `["onCommand:myPlugin.runScan"]` |
| `"onGuardEvaluate:{id}"` | Activate when a specific guard is evaluated | `["onGuardEvaluate:my-guard"]` |

Multiple activation events can be declared. The plugin is activated on the first matching event.

## Required secrets

If your plugin needs API keys or credentials, declare them in the `requiredSecrets` array. The workbench renders a generic secret entry form for each declared secret in the plugin settings UI.

```typescript,ignore
requiredSecrets: [
  {
    key: "api_key",
    label: "VirusTotal API Key",
    description: "Get your API key from https://virustotal.com/gui/my-apikey",
  },
],
```

At runtime, your plugin retrieves secrets via `ctx.secrets.get("api_key")`.

## Installation metadata

The `installation` field carries distribution metadata for plugins published to the registry. See [Publishing](publishing.md) for details.

| Field | Type | Description |
|-------|------|-------------|
| `downloadUrl` | `string` | URL to download the plugin package |
| `size` | `number` | Package size in bytes |
| `checksum` | `string` | SHA-256 hex digest of the package contents |
| `signature` | `string` | Ed25519 signature of the canonical manifest JSON |
| `minWorkbenchVersion` | `string?` | Minimum compatible workbench version (semver) |
| `maxWorkbenchVersion` | `string?` | Maximum compatible workbench version (semver) |

## Complete example

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";
import type { PluginManifest } from "@clawdstrike/plugin-sdk";

const manifest: PluginManifest = {
  id: "acme.network-scanner",
  name: "network-scanner",
  displayName: "Network Scanner",
  description: "Scans network egress patterns for suspicious destinations",
  version: "1.2.0",
  publisher: "Acme Security",
  categories: ["guards", "intel"],
  trust: "community",
  activationEvents: ["onStartup"],
  main: "dist/index.js",
  contributions: {
    guards: [
      {
        id: "acme.network-scanner.egress-check",
        name: "Network Scanner",
        technicalName: "network_scanner",
        description: "Checks outbound connections against threat intel",
        category: "network",
        defaultVerdict: "deny",
        icon: "network",
        configFields: [
          {
            key: "threshold",
            label: "Risk Threshold",
            type: "number_slider",
            description: "Minimum risk score to trigger (0-100)",
            defaultValue: 50,
            min: 0,
            max: 100,
            step: 5,
          },
        ],
      },
    ],
    commands: [
      {
        id: "acme.network-scanner.scan-now",
        title: "Scan Network Now",
        category: "Network Scanner",
        shortcut: "Cmd+Shift+N",
      },
    ],
  },
  requiredSecrets: [
    {
      key: "vt_api_key",
      label: "VirusTotal API Key",
      description: "Required for domain reputation lookups",
    },
  ],
};

export default createPlugin({
  manifest,
  activate(ctx) {
    ctx.subscriptions.push(
      ctx.guards.register(manifest.contributions!.guards![0]),
      ctx.commands.register(manifest.contributions!.commands![0], () => {
        console.log("Running network scan...");
      })
    );
  },
});
```
