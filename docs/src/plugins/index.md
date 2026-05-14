# Plugin Development

ClawdStrike's plugin system lets you extend the workbench with custom guards, commands, file types, UI panels, threat intelligence sources, and compliance framework mappings. Plugins are TypeScript packages that declare their capabilities in a typed manifest and register contributions at activation time through the `@clawdstrike/plugin-sdk`.

Plugins are classified into three **trust tiers** that determine how they are loaded and what they can access:

- **internal** -- Built-in plugins shipped with the workbench. Loaded in-process with full access to workbench APIs.
- **community** -- Third-party plugins installed from the marketplace. Loaded in a sandboxed iframe with a postMessage bridge. All API calls are mediated by the sandbox permissions system.
- **mcp** -- MCP tool plugins loaded via the Model Context Protocol bridge. Useful for integrating external agent tools as workbench contributions.

Plugins are activated lazily based on **activation events** declared in the manifest. For example, a guard plugin can declare `"onGuardEvaluate:my-guard"` so it only loads when that guard is first evaluated, or `"onStartup"` to load immediately when the workbench opens. This keeps startup fast -- only the plugins relevant to the current session are loaded.

To get started building your first plugin, see the [Getting Started](getting-started.md) guide.
