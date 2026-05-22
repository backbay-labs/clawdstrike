#!/usr/bin/env python3
"""Unit checks for check-changed-swift-coverage.py."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("check-changed-swift-coverage.py")


def load_checker():
    spec = importlib.util.spec_from_file_location("swiftcov", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["swiftcov"] = module
    spec.loader.exec_module(module)
    return module


def test_line_hits_expand_regions_between_segment_starts() -> None:
    checker = load_checker()
    segments = [
        [10, 1, 1, True, True, False],
        [12, 1, 0, True, True, False],
    ]

    line_hits = checker.line_hits_from_segments(segments)
    subset = checker.FileCoverage(line_hits=line_hits).subset_for_lines({11})

    assert line_hits[10] == 1
    assert line_hits[11] == 1
    assert line_hits[12] == 0
    assert subset.covered == 1
    assert subset.total == 1


def test_load_changed_files_ignores_deleted_sources() -> None:
    checker = load_checker()
    original_cwd = Path.cwd()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "Sources").mkdir()
        (root / "Sources" / "Kept.swift").write_text("", encoding="utf-8")
        changed_files = root / "changed.txt"
        changed_files.write_text(
            "Sources/Kept.swift\nSources/Deleted.swift\nSources/Package.swift\n",
            encoding="utf-8",
        )
        os.chdir(root)
        try:
            assert checker.load_changed_files(str(changed_files)) == ["Sources/Kept.swift"]
        finally:
            os.chdir(original_cwd)


if __name__ == "__main__":
    test_line_hits_expand_regions_between_segment_starts()
    test_load_changed_files_ignores_deleted_sources()
