#!/usr/bin/env python3
"""Fail CI when changed Swift code falls below a line-coverage floor."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FileCoverage:
    covered: int = 0
    total: int = 0
    line_hits: dict[int, int] = field(default_factory=dict)

    def ratio(self) -> float:
        return 1.0 if self.total == 0 else self.covered / self.total

    def subset_for_lines(self, changed_lines: set[int]) -> "FileCoverage":
        subset = FileCoverage()
        for line in sorted(changed_lines):
            hits = self.line_hits.get(line)
            if hits is None:
                continue
            subset.total += 1
            if hits > 0:
                subset.covered += 1
        return subset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check aggregate line coverage across changed Swift files from llvm-cov JSON."
    )
    parser.add_argument(
        "--coverage-json",
        action="append",
        required=True,
        help="Path to an llvm-cov export JSON file. May be provided more than once.",
    )
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


def repo_relative(path: str) -> str:
    normalized = normalize(path)
    cwd = normalize(str(Path.cwd().resolve()))
    if normalized.startswith(cwd + "/"):
        return normalized[len(cwd) + 1 :]
    return normalized


def load_changed_files(path: str) -> list[str]:
    changed: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            item = normalize(raw.strip())
            if not item.endswith(".swift"):
                continue
            if "/.build/" in item or item.endswith("/Package.swift"):
                continue
            if "/Tests/" in item:
                continue
            changed.append(item)
    return changed


def line_hits_from_segments(segments: list[list[Any]]) -> dict[int, int]:
    line_hits: dict[int, int] = {}
    normalized_segments: list[tuple[int, int, int, bool, bool]] = []

    for segment in segments:
        if len(segment) < 6:
            continue
        line = int(segment[0])
        column = int(segment[1])
        count = int(segment[2])
        has_count = bool(segment[3])
        is_gap_region = bool(segment[5])
        normalized_segments.append((line, column, count, has_count, is_gap_region))

    normalized_segments.sort(key=lambda item: (item[0], item[1]))

    for index, (line, _column, count, has_count, is_gap_region) in enumerate(normalized_segments):
        if not has_count or is_gap_region:
            continue
        next_line = line
        if index + 1 < len(normalized_segments):
            next_line = max(line, normalized_segments[index + 1][0] - 1)
        for covered_line in range(line, next_line + 1):
            line_hits[covered_line] = max(line_hits.get(covered_line, 0), count)

    return line_hits


def parse_coverage_json(path: str) -> dict[str, FileCoverage]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    records: dict[str, FileCoverage] = {}
    for report in payload.get("data", []):
        for file_record in report.get("files", []):
            filename = file_record.get("filename")
            if not isinstance(filename, str):
                continue
            relpath = repo_relative(filename)
            if "/.build/" in relpath:
                continue

            line_hits = line_hits_from_segments(file_record.get("segments", []))
            coverage = FileCoverage(line_hits=line_hits)
            coverage.total = len(line_hits)
            coverage.covered = sum(1 for hits in line_hits.values() if hits > 0)

            existing = records.get(relpath)
            if existing is None:
                records[relpath] = coverage
                continue

            for line, hits in coverage.line_hits.items():
                existing.line_hits[line] = max(existing.line_hits.get(line, 0), hits)
            existing.total = len(existing.line_hits)
            existing.covered = sum(1 for hits in existing.line_hits.values() if hits > 0)

    return records


def find_record(records: dict[str, FileCoverage], changed_relpath: str) -> FileCoverage | None:
    changed_relpath = normalize(changed_relpath)
    if changed_relpath in records:
        return records[changed_relpath]
    for sf_path, coverage in records.items():
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
        print("No changed Swift source files detected; skipping changed-file coverage gate.")
        return 0

    coverage_records: dict[str, FileCoverage] = {}
    for path in args.coverage_json:
        for relpath, coverage in parse_coverage_json(path).items():
            existing = coverage_records.get(relpath)
            if existing is None:
                coverage_records[relpath] = coverage
                continue
            for line, hits in coverage.line_hits.items():
                existing.line_hits[line] = max(existing.line_hits.get(line, 0), hits)
            existing.total = len(existing.line_hits)
            existing.covered = sum(1 for hits in existing.line_hits.values() if hits > 0)

    changed_lines_by_file: dict[str, set[int]] = {}
    if args.git_diff_range:
        changed_lines_by_file = load_changed_lines(args.git_diff_range, changed_files)

    aggregate = FileCoverage()
    missing: list[str] = []
    missing_changed_lines: list[str] = []
    per_file_lines: list[str] = []

    for relpath in changed_files:
        record = find_record(coverage_records, relpath)
        if record is None:
            missing.append(relpath)
            continue

        effective = record
        if args.git_diff_range:
            changed_lines = changed_lines_by_file.get(relpath, set())
            if not changed_lines:
                continue
            effective = record.subset_for_lines(changed_lines)
            if effective.total == 0:
                missing_changed_lines.append(relpath)
                continue

        aggregate.covered += effective.covered
        aggregate.total += effective.total
        per_file_lines.append(
            f"{relpath}: {effective.covered}/{effective.total} "
            f"({effective.ratio() * 100:.2f}%)"
        )

    print("Changed-file Swift coverage:")
    for line in per_file_lines:
        print(f"  - {line}")

    if missing:
        print("Missing llvm-cov records for changed files:")
        for relpath in missing:
            print(f"  - {relpath}")
        return 1

    if missing_changed_lines:
        print("Changed Swift lines had no llvm-cov line records:")
        for relpath in missing_changed_lines:
            print(f"  - {relpath}")
        return 1

    coverage_pct = aggregate.ratio() * 100.0
    print(
        f"Aggregate changed-file Swift coverage: {aggregate.covered}/{aggregate.total} "
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
