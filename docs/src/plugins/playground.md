# Plugin Playground

> **Note:** The playground requires Phase 5 implementation. Details on this page may change as the feature is built out.

The Plugin Playground is a built-in workbench feature that lets you write, run, and debug plugins without leaving the workbench. It is accessible from the "Plugin Dev" activity bar item.

## Overview

The playground provides three panels:

- **Code editor** (left): A CodeMirror editor with TypeScript support, pre-loaded with a `createPlugin()` template
- **Contribution inspector** (right sidebar): A tree view showing all contributions registered by the playground plugin
- **Plugin console** (bottom panel): Captured console output from the plugin's execution context

## Workflow

1. Open the "Plugin Dev" item from the activity bar
2. Write your plugin code in the CodeMirror editor
3. Click the **Run** button in the toolbar
4. The editor content is transpiled from TypeScript to JavaScript and loaded as a dynamic module
5. The plugin's contributions appear in the workbench and the contribution inspector updates

Each run deactivates the previous playground plugin before activating the new version, ensuring a clean state.

## Error handling

When a playground plugin throws during activation, an error boundary catches the error and displays:

- The error message and stack trace
- Source-mapped line numbers pointing back to the CodeMirror editor
- A clear action to dismiss the error and try again

The workbench remains fully functional even when the playground plugin errors -- the error is contained within the playground area.

## Console output

The plugin console panel captures `console.log`, `console.warn`, and `console.error` calls from the playground plugin using a scoped proxy. Output does not leak into the global browser console. The console panel supports:

- Severity icons (info, warning, error)
- Filtering by severity level
- A clear button to reset output
