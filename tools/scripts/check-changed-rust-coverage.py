#!/usr/bin/env python3
"""Fail CI when changed Rust files fall below a line-coverage floor."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass


@dataclass
class FileCoverage:
    covered: int = 0
    total: int = 0

    def ratio(self) -> float:
        return 1.0 if self.total == 0 else self.covered / self.total


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
                _, hits_raw = data.split(",", 1)
                hits = int(hits_raw)
                current_cov.total += 1
                if hits > 0:
                    current_cov.covered += 1
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


def main() -> int:
    args = parse_args()
    changed_files = load_changed_files(args.changed_files_file)
    if not changed_files:
        print("No changed Rust files detected; skipping changed-file coverage gate.")
        return 0

    lcov_records = parse_lcov(args.lcov)
    aggregate = FileCoverage()
    missing: list[str] = []
    per_file_lines: list[str] = []

    for relpath in changed_files:
        record = find_record(lcov_records, relpath)
        if record is None:
            missing.append(relpath)
            continue

        aggregate.covered += record.covered
        aggregate.total += record.total
        per_file_lines.append(
            f"{relpath}: {record.covered}/{record.total} "
            f"({record.ratio() * 100:.2f}%)"
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
