# Commands

Command contributions add entries to the workbench command palette and optionally bind keyboard shortcuts.

## CommandContribution interface

```typescript,ignore
interface CommandContribution {
  /** Unique command identifier (e.g. "myPlugin.runScan"). */
  id: string;
  /** Display title in the command palette. */
  title: string;
  /** Optional category for grouping in the palette. */
  category?: string;
  /** Optional default keyboard shortcut (e.g. "Cmd+Shift+S"). */
  shortcut?: string;
  /** Optional contextual visibility expression (for future use). */
  when?: string;
}
```

## Registering a command

Declare the command in the manifest's `contributions.commands` array, then register it with a handler in `activate()`:

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";
import type { CommandContribution } from "@clawdstrike/plugin-sdk";

const scanCommand: CommandContribution = {
  id: "acme.scanner.run-scan",
  title: "Run Security Scan",
  category: "Scanner",
  shortcut: "Cmd+Shift+S",
};

export default createPlugin({
  manifest: {
    id: "acme.scanner",
    name: "scanner",
    displayName: "Scanner",
    description: "On-demand security scanning",
    version: "1.0.0",
    publisher: "Acme",
    categories: ["guards"],
    trust: "community",
    activationEvents: ["onCommand:acme.scanner.run-scan"],
    contributions: {
      commands: [scanCommand],
    },
  },

  activate(ctx) {
    ctx.subscriptions.push(
      ctx.commands.register(scanCommand, () => {
        console.log("Security scan started...");
        // Perform scan logic here
      })
    );
  },
});
```

## Command palette integration

Commands appear in the command palette grouped by their `category` field. Users can invoke them by:

1. Opening the command palette (Cmd+K or Ctrl+K)
2. Typing the command title or category
3. Selecting the command

If a `shortcut` is specified, the command can also be invoked directly via the keyboard shortcut.

## Keybinding contributions

For more control over keyboard shortcuts, you can declare `keybindings` separately in the manifest:

```typescript,ignore
interface KeybindingContribution {
  /** Command ID to bind. */
  command: string;
  /** Key combination (e.g. "Cmd+Shift+S", "Ctrl+K"). */
  key: string;
  /** Optional contextual activation expression. */
  when?: string;
}
```

Keybindings declared in the manifest are registered automatically -- no additional `activate()` code is needed.

```typescript,ignore
contributions: {
  commands: [
    { id: "acme.format", title: "Format Document", category: "Acme" },
  ],
  keybindings: [
    { command: "acme.format", key: "Cmd+Shift+F", when: "editorFocus" },
  ],
}
```
