#!/usr/bin/env bash
# Post-edit hook: auto-validate YAML policy files after edits.
# Runs only when the edited file looks like a ClawdStrike policy.
#
# Environment variables set by Claude Code:
#   TOOL_INPUT — JSON with the tool invocation details
#   TOOL_OUTPUT — JSON with the tool result

set -eo pipefail

# Extract the file path from the tool input
FILE_PATH=$(echo "${TOOL_INPUT:-}" | grep -o '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || true)

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Only process YAML files
case "$FILE_PATH" in
  *.yaml|*.yml) ;;
  *) exit 0 ;;
esac

# Check if it looks like a ClawdStrike policy (has 'guards:' or 'version:' fields)
if [ -f "$FILE_PATH" ]; then
  if grep -q -E '^(guards:|version:|extends:)' "$FILE_PATH" 2>/dev/null; then
    echo "ClawdStrike policy detected — use workbench_validate_policy to check for issues."
  fi
fi

exit 0
