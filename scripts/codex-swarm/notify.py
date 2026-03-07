#!/usr/bin/env python3
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def orchestration_root(root: Path) -> Path:
    return root.parent / "clawdstrike-orchestration"


def load_lane_map(root: Path) -> dict[str, str]:
    lane_map: dict[str, str] = {}
    lane_file = root / ".codex" / "swarm" / "lanes.tsv"
    if not lane_file.exists():
        return lane_map

    lines = lane_file.read_text(encoding="utf-8").splitlines()
    for line in lines[1:]:
        if not line.strip():
            continue
        lane, worktree, *_rest = line.split("\t")
        lane_map[worktree] = lane
    return lane_map


def write_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def main() -> int:
    if len(sys.argv) < 2:
        return 0

    try:
        notification = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        return 0

    root = repo_root()
    orch = orchestration_root(root)
    orch.mkdir(parents=True, exist_ok=True)

    payload = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        **notification,
    }

    write_jsonl(orch / "notifications.jsonl", payload)

    cwd = Path(notification.get("cwd", ""))
    lane_map = load_lane_map(root)
    lane = lane_map.get(cwd.name)
    if lane:
        write_jsonl(orch / lane / "notify.jsonl", payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
