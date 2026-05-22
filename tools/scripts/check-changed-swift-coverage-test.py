#!/usr/bin/env python3
"""Unit checks for check-changed-swift-coverage.py."""

from __future__ import annotations

import importlib.util
import sys
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


if __name__ == "__main__":
    test_line_hits_expand_regions_between_segment_starts()
