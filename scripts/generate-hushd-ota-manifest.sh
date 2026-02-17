#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/generate-hushd-ota-manifest.sh \
    --version <X.Y.Z> \
    --tag <vX.Y.Z> \
    --channel <stable|beta> \
    --assets-dir <dir> \
    --output <manifest.json> \
    [--public-key <hex32>] \
    [--min-agent-version <X.Y.Z>]

Required assets in --assets-dir:
  hushd-linux-x86_64
  hushd-darwin-x86_64
  hushd-darwin-aarch64
  hushd-windows-x86_64.exe
USAGE
}

version=""
tag=""
channel=""
assets_dir=""
output_path=""
public_key=""
min_agent_version=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --tag)
      tag="${2:-}"
      shift 2
      ;;
    --channel)
      channel="${2:-}"
      shift 2
      ;;
    --assets-dir)
      assets_dir="${2:-}"
      shift 2
      ;;
    --output)
      output_path="${2:-}"
      shift 2
      ;;
    --public-key)
      public_key="${2:-}"
      shift 2
      ;;
    --min-agent-version)
      min_agent_version="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$version" || -z "$tag" || -z "$channel" || -z "$assets_dir" || -z "$output_path" ]]; then
  echo "Missing required arguments" >&2
  usage
  exit 1
fi

if [[ "$channel" != "stable" && "$channel" != "beta" ]]; then
  echo "Channel must be 'stable' or 'beta'" >&2
  exit 1
fi

for file in \
  hushd-linux-x86_64 \
  hushd-darwin-x86_64 \
  hushd-darwin-aarch64 \
  hushd-windows-x86_64.exe
do
  if [[ ! -f "${assets_dir}/${file}" ]]; then
    echo "Missing required artifact: ${assets_dir}/${file}" >&2
    exit 1
  fi
done

export OTA_RELEASE_VERSION="$version"
export OTA_RELEASE_TAG="$tag"
export OTA_CHANNEL="$channel"
export OTA_ASSETS_DIR="$assets_dir"
export OTA_OUTPUT_PATH="$output_path"
export OTA_PUBLIC_KEY="$public_key"
export OTA_MIN_AGENT_VERSION="$min_agent_version"

python3 - <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import sys

version = os.environ["OTA_RELEASE_VERSION"].strip()
tag = os.environ["OTA_RELEASE_TAG"].strip()
channel = os.environ["OTA_CHANNEL"].strip()
assets_dir = pathlib.Path(os.environ["OTA_ASSETS_DIR"])
output_path = pathlib.Path(os.environ["OTA_OUTPUT_PATH"])
public_key = os.environ.get("OTA_PUBLIC_KEY", "").strip()
min_agent_version = os.environ.get("OTA_MIN_AGENT_VERSION", "").strip()

artifacts_spec = [
    ("darwin-aarch64", "hushd-darwin-aarch64"),
    ("darwin-x86_64", "hushd-darwin-x86_64"),
    ("linux-x86_64", "hushd-linux-x86_64"),
    ("windows-x86_64", "hushd-windows-x86_64.exe"),
]

artifacts = []
for platform, filename in artifacts_spec:
    path = assets_dir / filename
    if not path.is_file():
        print(f"missing artifact: {path}", file=sys.stderr)
        sys.exit(1)
    data = path.read_bytes()
    artifacts.append(
        {
            "platform": platform,
            "url": f"https://github.com/backbay-labs/clawdstrike/releases/download/{tag}/{filename}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    )

manifest = {
    "schema_version": "clawdstrike-hushd-ota-v1",
    "release_version": version,
    "published_at": datetime.datetime.now(datetime.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "channel": channel,
    "notes_url": f"https://github.com/backbay-labs/clawdstrike/releases/tag/{tag}",
    "artifacts": artifacts,
    "signature": "",
}

if min_agent_version:
    manifest["min_agent_version"] = min_agent_version
if public_key:
    manifest["public_key"] = public_key

output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

echo "Wrote OTA manifest: ${output_path}"
