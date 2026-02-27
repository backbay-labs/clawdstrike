#!/usr/bin/env bash
set -euo pipefail

PROFILE="infra/deploy/helm/clawdstrike/profiles/all-on-dev-platform.yaml"
SHA=""

usage() {
  cat <<'EOF'
Usage: scripts/update-all-on-profile-tags.sh --sha <git-sha> [--profile <path>]

Updates all-on profile image tags to the provided SHA:
  - spine.image.tag -> spine-checkpointer-<sha>
  - hushd.image.tag -> <sha>
  - bridges.tetragon.image.tag -> <sha>
  - bridges.hubble.image.tag -> <sha>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha)
      SHA="${2:-}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$SHA" ]]; then
  echo "--sha is required" >&2
  usage >&2
  exit 1
fi

if ! [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "--sha must be a full 40-char git SHA" >&2
  exit 1
fi

if [[ ! -f "$PROFILE" ]]; then
  echo "Profile not found: $PROFILE" >&2
  exit 1
fi

python3 - "$PROFILE" "$SHA" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

profile = Path(sys.argv[1])
sha = sys.argv[2]

lines = profile.read_text(encoding="utf-8").splitlines()

section: str | None = None
bridge: str | None = None
updated = {
    "spine": False,
    "hushd": False,
    "tetragon": False,
    "hubble": False,
}

for idx, line in enumerate(lines):
    stripped = line.strip()
    indent = len(line) - len(line.lstrip(" "))

    if indent == 0 and stripped.endswith(":"):
        section = stripped[:-1]
        bridge = None
        continue

    if section == "bridges" and indent == 2 and stripped.endswith(":"):
        bridge = stripped[:-1]
        continue

    if not stripped.startswith("tag:"):
        continue

    if section == "spine" and indent == 4:
        lines[idx] = re.sub(r'tag:\s*".*"', f'tag: "spine-checkpointer-{sha}"', line)
        updated["spine"] = True
    elif section == "hushd" and indent == 4:
        lines[idx] = re.sub(r'tag:\s*".*"', f'tag: "{sha}"', line)
        updated["hushd"] = True
    elif section == "bridges" and bridge == "tetragon" and indent == 6:
        lines[idx] = re.sub(r'tag:\s*".*"', f'tag: "{sha}"', line)
        updated["tetragon"] = True
    elif section == "bridges" and bridge == "hubble" and indent == 6:
        lines[idx] = re.sub(r'tag:\s*".*"', f'tag: "{sha}"', line)
        updated["hubble"] = True

missing = [k for k, v in updated.items() if not v]
if missing:
    raise SystemExit(f"Failed to update expected tags: {', '.join(missing)}")

profile.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Updated {profile} to image SHA {sha}")
PY

