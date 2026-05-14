/**
 * Build-time script: extract ClawdStrike YAML rulesets to static JSON.
 *
 * Reads all 10 built-in rulesets from `rulesets/*.yaml` at the repo root,
 * parses them with the `yaml` library, and writes individual JSON files plus
 * an `index.json` summary to `src/data/rulesets/`.
 *
 * Run via: `node --import tsx scripts/extract-rulesets.ts`
 */
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';

// Resolve from apps/academy to repo root (up 2 levels)
const RULESETS_DIR = path.resolve(process.cwd(), '../../rulesets');
const OUTPUT_DIR = path.resolve(process.cwd(), 'src/data/rulesets');

export const RULESET_NAMES = [
  'default',
  'strict',
  'permissive',
  'ai-agent',
  'ai-agent-posture',
  'cicd',
  'remote-desktop',
  'remote-desktop-strict',
  'remote-desktop-permissive',
  'spider-sense',
] as const;

interface RulesetIndexEntry {
  name: string;
  extends?: string;
  description: string;
}

function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const index: Record<string, RulesetIndexEntry> = {};

  for (const rulesetName of RULESET_NAMES) {
    const yamlPath = path.join(RULESETS_DIR, `${rulesetName}.yaml`);

    if (!fs.existsSync(yamlPath)) {
      console.error(`WARNING: Ruleset file not found: ${yamlPath}`);
      continue;
    }

    const yamlContent = fs.readFileSync(yamlPath, 'utf-8');
    const parsed = YAML.parse(yamlContent);

    // Write individual JSON file
    const jsonPath = path.join(OUTPUT_DIR, `${rulesetName}.json`);
    fs.writeFileSync(jsonPath, JSON.stringify(parsed, null, 2) + '\n');

    // Add to index
    index[rulesetName] = {
      name: parsed.name ?? rulesetName,
      ...(parsed.extends ? { extends: parsed.extends } : {}),
      description: parsed.description ?? '',
    };
  }

  // Write index.json
  const indexPath = path.join(OUTPUT_DIR, 'index.json');
  fs.writeFileSync(indexPath, JSON.stringify(index, null, 2) + '\n');

  console.log(`Extracted ${Object.keys(index).length} rulesets to ${OUTPUT_DIR}`);
}

main();
