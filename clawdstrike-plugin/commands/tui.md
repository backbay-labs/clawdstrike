---
description: "Launch the ClawdStrike TUI dashboard"
---

# ClawdStrike TUI

Launch the interactive ClawdStrike terminal dashboard.

## Steps

1. Detect the plugin root directory using this resolution order:
   - If `CLAWDSTRIKE_PLUGIN_DIR` environment variable is set, use that
   - Otherwise, search ancestor directories from the current working directory for a `.claude-plugin/plugin.json` file
   - Walk up from the cwd: check `$CWD/.claude-plugin/plugin.json`, then `$CWD/../.claude-plugin/plugin.json`, etc.
   - If found, the plugin root is the directory containing `.claude-plugin/`
   - If not found after reaching filesystem root, report an error and suggest setting `CLAWDSTRIKE_PLUGIN_DIR`

2. Run the TUI using the Bash tool from the detected plugin root:
   ```
   bun run --cwd "$PLUGIN_ROOT/../apps/terminal" cli
   ```

3. The TUI provides an interactive dashboard with:
   - Real-time event stream
   - Policy status overview
   - Guard activity metrics
   - Session audit log

If the command fails:
- Check that `CLAWDSTRIKE_PLUGIN_DIR` is set or that the plugin root could be found
- Check that dependencies are installed (`bun install` in the apps/terminal directory)
- Check that the required environment variables are set
