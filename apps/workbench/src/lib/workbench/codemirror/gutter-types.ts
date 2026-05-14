/**
 * Shared types and utilities for CodeMirror gutter extensions.
 *
 * Provides guard line-range parsing from YAML policy documents and
 * MITRE ATT&CK coverage gap computation for the coverage gutter.
 */

import type { Text } from "@codemirror/state";
import { ALL_GUARD_IDS } from "@/lib/workbench/guard-registry";
import {
  GUARD_TECHNIQUE_MAP,
  extractPolicyTechniques,
} from "@/lib/workbench/mitre-attack-data";

// ---- Types ----

/** Identifies which lines in a YAML document correspond to a guard config section. */
export interface GuardLineRange {
  guardId: string;
  fromLine: number;
  toLine: number;
}

/** A guard at a given line with uncovered MITRE techniques. */
export interface CoverageGap {
  guardId: string;
  line: number;
  uncoveredTechniques: string[];
}

// ---- Parsing ----

/**
 * Parse a YAML document to find guard config sections under a `guards:` key.
 *
 * Scans for guard IDs (from ALL_GUARD_IDS) appearing as YAML keys at
 * indentation level 2 or 4 under a `guards:` parent key. Each range starts
 * at the guard key line and extends until the next sibling key at the same
 * indentation or end of the guards block.
 */
export function parseGuardRanges(doc: Text): GuardLineRange[] {
  const ranges: GuardLineRange[] = [];
  const guardIdSet = new Set<string>(ALL_GUARD_IDS);

  let inGuardsBlock = false;
  let guardsIndent = -1;
  let currentGuard: { guardId: string; fromLine: number; indent: number } | null = null;

  for (let i = 1; i <= doc.lines; i++) {
    const lineText = doc.line(i).text;

    // Skip empty lines and comment-only lines
    if (lineText.trim() === "" || lineText.trim().startsWith("#")) {
      continue;
    }

    // Calculate leading whitespace
    const stripped = lineText.trimStart();
    const indent = lineText.length - stripped.length;

    // Detect `guards:` key (top-level or nested)
    if (stripped.startsWith("guards:")) {
      inGuardsBlock = true;
      guardsIndent = indent;
      continue;
    }

    if (!inGuardsBlock) continue;

    // If we encounter a line at the same or lesser indent as `guards:`,
    // the guards block has ended.
    if (indent <= guardsIndent && !stripped.startsWith("#")) {
      // Close any open guard range
      if (currentGuard) {
        ranges.push({
          guardId: currentGuard.guardId,
          fromLine: currentGuard.fromLine,
          toLine: i - 1,
        });
        currentGuard = null;
      }
      inGuardsBlock = false;
      continue;
    }

    // Check if this line is a guard key at indent guardsIndent+2 or guardsIndent+4
    const childIndent1 = guardsIndent + 2;
    const childIndent2 = guardsIndent + 4;
    const isChildLevel = indent === childIndent1 || indent === childIndent2;

    if (isChildLevel && stripped.includes(":")) {
      const keyPart = stripped.split(":")[0].trim();
      if (guardIdSet.has(keyPart)) {
        // Close the previous guard range
        if (currentGuard) {
          ranges.push({
            guardId: currentGuard.guardId,
            fromLine: currentGuard.fromLine,
            toLine: i - 1,
          });
        }
        currentGuard = { guardId: keyPart, fromLine: i, indent };
        continue;
      }

      // Non-guard key at the same level as a current guard: close the current guard
      if (currentGuard && indent === currentGuard.indent) {
        ranges.push({
          guardId: currentGuard.guardId,
          fromLine: currentGuard.fromLine,
          toLine: i - 1,
        });
        currentGuard = null;
      }
    }
  }

  // Close any trailing guard range at document end
  if (currentGuard) {
    ranges.push({
      guardId: currentGuard.guardId,
      fromLine: currentGuard.fromLine,
      toLine: doc.lines,
    });
  }

  return ranges;
}

// ---- Coverage gap computation ----

/**
 * For each guard range, check if the guard is enabled and compute
 * which of its mapped MITRE techniques are uncovered by the policy.
 *
 * A guard's techniques are "covered" when `extractPolicyTechniques`
 * returns them for the full YAML content. Guards whose techniques
 * are all covered produce no gap. Guards with uncovered techniques
 * produce a CoverageGap entry on their first line.
 */
export function computeCoverageGaps(
  guardRanges: GuardLineRange[],
  yamlContent: string,
): CoverageGap[] {
  const gaps: CoverageGap[] = [];
  const coveredTechniques = new Set(extractPolicyTechniques(yamlContent));

  for (const range of guardRanges) {
    const guardTechniques = GUARD_TECHNIQUE_MAP[range.guardId];
    if (!guardTechniques || guardTechniques.length === 0) continue;

    // Check if the guard is enabled within its range by looking
    // at the YAML content lines within the range.
    const lines = yamlContent.split("\n");
    const rangeLines = lines.slice(range.fromLine - 1, range.toLine);
    const rangeText = rangeLines.join("\n");
    const enabledRe = /enabled:\s*true/;
    if (!enabledRe.test(rangeText)) continue;

    const uncovered = guardTechniques.filter((t) => !coveredTechniques.has(t));
    if (uncovered.length > 0) {
      gaps.push({
        guardId: range.guardId,
        line: range.fromLine,
        uncoveredTechniques: uncovered,
      });
    }
  }

  return gaps;
}
