import fs from 'node:fs';
import path from 'node:path';
import { EXTRACTION_MANIFEST, REPO_ROOT, OUT_DIR } from './manifest';
import type { ManifestEntry } from './manifest';

export interface TaggedRegion {
  tag: string;
  file: string;
  startLine: number;
  endLine: number;
  code: string;
  language: string;
}

export interface SourceManifest {
  extractedAt: string;
  regions: Record<string, TaggedRegion>;
}

/**
 * Marker patterns for different comment styles.
 * Supports // (Rust, TS, JS) and # (Python, YAML) comment prefixes.
 */
const START_PATTERN = /^\s*(?:\/\/|#)\s*@academy:start\s+(\S+)\s*$/;
const END_PATTERN = /^\s*(?:\/\/|#)\s*@academy:end\s+(\S+)\s*$/;

/** Map file extensions to Shiki language identifiers */
function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.rs':
      return 'rust';
    case '.ts':
    case '.tsx':
      return 'typescript';
    case '.js':
    case '.jsx':
      return 'javascript';
    case '.py':
      return 'python';
    case '.yaml':
    case '.yml':
      return 'yaml';
    default:
      return 'text';
  }
}

/**
 * Extract all tagged regions from a source file.
 *
 * Reads the file line by line, looking for @academy:start / @academy:end
 * marker pairs. Returns an array of TaggedRegion objects.
 *
 * Throws if an @academy:start tag is found without a matching @academy:end.
 */
export function extractFromFile(filePath: string): TaggedRegion[] {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const language = detectLanguage(filePath);
  const regions: TaggedRegion[] = [];

  // Track open tags: tag name -> { startLine (1-indexed), contentStartIndex (0-indexed) }
  const openTags = new Map<string, { startLine: number; contentStartIndex: number }>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1; // 1-indexed

    const startMatch = START_PATTERN.exec(line);
    if (startMatch) {
      const tag = startMatch[1];
      openTags.set(tag, {
        startLine: lineNumber + 1, // content starts on next line
        contentStartIndex: i + 1,
      });
      continue;
    }

    const endMatch = END_PATTERN.exec(line);
    if (endMatch) {
      const tag = endMatch[1];
      const open = openTags.get(tag);
      if (open) {
        const codeLines = lines.slice(open.contentStartIndex, i);
        regions.push({
          tag,
          file: filePath,
          startLine: open.startLine,
          endLine: lineNumber - 1, // content ends on previous line
          code: codeLines.join('\n'),
          language,
        });
        openTags.delete(tag);
      }
    }
  }

  if (openTags.size > 0) {
    const unclosed = Array.from(openTags.keys()).join(', ');
    throw new Error(
      `Unclosed @academy:start tag(s) in ${filePath}: ${unclosed}`,
    );
  }

  return regions;
}

/**
 * Run extraction for a manifest of files and expected tags.
 *
 * For each manifest entry, extracts tagged regions from the source file
 * and writes one JSON file per tag to the output directory.
 *
 * Throws if any expected tag from the manifest is not found.
 */
export function runExtraction(
  manifest: ManifestEntry[],
  outDir: string,
): void {
  fs.mkdirSync(outDir, { recursive: true });

  const extractedAt = new Date().toISOString();
  const allRegions = new Map<string, TaggedRegion>();

  for (const entry of manifest) {
    const regions = extractFromFile(entry.file);

    for (const region of regions) {
      allRegions.set(region.tag, region);
    }

    // Validate that all expected tags were found
    const foundTags = new Set(regions.map((r) => r.tag));
    const missingTags = entry.expectedTags.filter(
      (tag) => !foundTags.has(tag),
    );

    if (missingTags.length > 0) {
      throw new Error(
        `Missing expected tags in ${entry.file}: ${missingTags.join(', ')}`,
      );
    }
  }

  // Write one JSON file per extracted tag
  for (const [tag, region] of allRegions) {
    const outputPath = path.join(outDir, `${tag}.json`);
    const data = {
      ...region,
      extractedAt,
    };
    fs.writeFileSync(outputPath, JSON.stringify(data, null, 2), 'utf8');
  }
}

// Main entry: run when executed directly
const isMain =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith('source-extraction/extract.ts');

if (isMain) {
  try {
    // Resolve manifest paths relative to repo root
    const resolvedManifest = EXTRACTION_MANIFEST.map((entry) => ({
      ...entry,
      file: path.resolve(REPO_ROOT, entry.file),
    }));

    runExtraction(resolvedManifest, OUT_DIR);

    const tagCount = resolvedManifest.reduce(
      (sum, e) => sum + e.expectedTags.length,
      0,
    );
    console.log(
      `Source extraction complete: ${tagCount} tags from ${resolvedManifest.length} files`,
    );
    process.exit(0);
  } catch (error) {
    console.error(
      'Source extraction failed:',
      error instanceof Error ? error.message : error,
    );
    process.exit(1);
  }
}
