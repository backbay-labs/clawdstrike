#!/usr/bin/env python3
"""Fail CI when changed Rust code falls below a line-coverage floor."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class FileCoverage:
    covered: int = 0
    total: int = 0
    line_hits: dict[int, int] = field(default_factory=dict)

    def ratio(self) -> float:
        return 1.0 if self.total == 0 else self.covered / self.total

    def subset_for_lines(self, changed_lines: set[int]) -> "FileCoverage":
        subset = FileCoverage()
        for line in changed_lines:
            hits = self.line_hits.get(line)
            if hits is None:
                continue
            subset.total += 1
            if hits > 0:
                subset.covered += 1
        return subset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check aggregate line coverage across changed Rust files from LCOV."
    )
    parser.add_argument("--lcov", required=True, help="Path to LCOV file (e.g. lcov.info)")
    parser.add_argument(
        "--changed-files-file",
        required=True,
        help="Text file containing one changed file path per line",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=70.0,
        help="Minimum required aggregate line coverage percentage",
    )
    parser.add_argument(
        "--git-diff-range",
        help=(
            "Optional git diff range (for example: origin/main...HEAD). "
            "When provided, coverage is evaluated only for changed lines."
        ),
    )
    return parser.parse_args()


def normalize(path: str) -> str:
    return path.replace("\\", "/")


def load_changed_files(path: str) -> list[str]:
    changed: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            item = raw.strip()
            if not item or not item.endswith(".rs"):
                continue
            if item.startswith("infra/vendor/"):
                continue
            changed.append(normalize(item))
    return changed


def parse_lcov(path: str) -> dict[str, FileCoverage]:
    records: dict[str, FileCoverage] = {}
    current_path: str | None = None
    current_cov = FileCoverage()

    def flush() -> None:
        nonlocal current_path, current_cov
        if current_path is None:
            return
        records[normalize(current_path)] = current_cov
        current_path = None
        current_cov = FileCoverage()

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("SF:"):
                flush()
                current_path = line[3:]
            elif line.startswith("DA:") and current_path is not None:
                _, data = line.split(":", 1)
                line_no_raw, hits_raw = data.split(",", 1)
                line_no = int(line_no_raw)
                hits = int(hits_raw)
                current_cov.total += 1
                if hits > 0:
                    current_cov.covered += 1
                current_cov.line_hits[line_no] = hits
            elif line == "end_of_record":
                flush()

    flush()
    return records


def find_record(
    lcov_records: dict[str, FileCoverage], changed_relpath: str
) -> FileCoverage | None:
    changed_relpath = normalize(changed_relpath)

    if changed_relpath in lcov_records:
        return lcov_records[changed_relpath]

    for sf_path, coverage in lcov_records.items():
        if sf_path.endswith(changed_relpath):
            return coverage
    return None


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def load_changed_lines(diff_range: str, changed_files: list[str]) -> dict[str, set[int]]:
    if not changed_files:
        return {}

    cmd = ["git", "diff", "--unified=0", "--no-color", diff_range, "--", *changed_files]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        print(f"Failed to compute changed-line diff: {err.output}", file=sys.stderr)
        raise

    changed_lines: dict[str, set[int]] = {}
    current_path: str | None = None

    for raw in output.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:]
            if path == "/dev/null":
                current_path = None
                continue
            if path.startswith("b/"):
                path = path[2:]
            current_path = normalize(path)
            changed_lines.setdefault(current_path, set())
            continue

        if current_path is None:
            continue

        match = HUNK_RE.match(raw)
        if not match:
            continue

        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count <= 0:
            continue
        for line_no in range(start, start + count):
            changed_lines[current_path].add(line_no)

    return changed_lines


def main() -> int:
    args = parse_args()
    changed_files = load_changed_files(args.changed_files_file)
    if not changed_files:
        print("No changed Rust files detected; skipping changed-file coverage gate.")
        return 0

    lcov_records = parse_lcov(args.lcov)
    changed_lines_by_file: dict[str, set[int]] = {}
    if args.git_diff_range:
        changed_lines_by_file = load_changed_lines(args.git_diff_range, changed_files)

    aggregate = FileCoverage()
    missing: list[str] = []
    per_file_lines: list[str] = []

    for relpath in changed_files:
        record = find_record(lcov_records, relpath)
        if record is None:
            missing.append(relpath)
            continue

        effective = record
        if args.git_diff_range:
            changed_lines = changed_lines_by_file.get(relpath, set())
            if not changed_lines:
                # File changed only by deletions/renames or couldn't be mapped;
                # it contributes nothing to changed-line coverage.
                continue
            effective = record.subset_for_lines(changed_lines)
            if effective.total == 0:
                # No executable lines from this file were changed.
                continue

        aggregate.covered += effective.covered
        aggregate.total += effective.total
        per_file_lines.append(
            f"{relpath}: {effective.covered}/{effective.total} "
            f"({effective.ratio() * 100:.2f}%)"
        )

    print("Changed-file Rust coverage:")
    for line in per_file_lines:
        print(f"  - {line}")

    if missing:
        print("Missing LCOV records for changed files:")
        for relpath in missing:
            print(f"  - {relpath}")
        return 1

    coverage_pct = aggregate.ratio() * 100.0
    print(
        f"Aggregate changed-file Rust coverage: {aggregate.covered}/{aggregate.total} "
        f"({coverage_pct:.2f}%)"
    )

    if coverage_pct + 1e-9 < args.threshold:
        print(
            f"Coverage gate failed: {coverage_pct:.2f}% is below threshold "
            f"{args.threshold:.2f}%"
        )
        return 1

    print(
        f"Coverage gate passed: {coverage_pct:.2f}% >= threshold {args.threshold:.2f}%"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
