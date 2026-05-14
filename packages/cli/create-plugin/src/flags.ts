import path from "node:path";
import type { ScaffoldOptions, PluginType, ContributionPoint } from "./types";
import { PLUGIN_TYPES, CONTRIBUTION_POINTS, PLUGIN_TYPE_DEFAULTS } from "./types";

const KEBAB_CASE_RE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const FLAGS_WITH_VALUES = new Set([
  "--name",
  "--type",
  "--publisher",
  "--contributions",
  "--pm",
]);

function toDisplayName(name: string): string {
  return name
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function getFlag(argv: string[], flag: string): string | undefined {
  const idx = argv.indexOf(flag);
  if (idx === -1 || idx + 1 >= argv.length) return undefined;
  return argv[idx + 1];
}

function getPositionalName(argv: string[]): string | undefined {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("-")) {
      if (FLAGS_WITH_VALUES.has(arg)) {
        i += 1;
      }
      continue;
    }

    return arg;
  }

  return undefined;
}

/** Returns null if required flags are missing. */
export function parseFlags(argv: string[]): ScaffoldOptions | null {
  const nameFlag = getFlag(argv, "--name");
  const positionalName = getPositionalName(argv);
  const name = nameFlag ?? positionalName;

  if (!name) {
    console.error("Error: Plugin name is required. Provide it as a positional argument or with --name.");
    return null;
  }

  if (!KEBAB_CASE_RE.test(name)) {
    console.error(`Error: Plugin name "${name}" must be kebab-case (e.g., "my-guard").`);
    return null;
  }

  const typeFlag = getFlag(argv, "--type");
  if (!typeFlag) {
    console.error("Error: --type flag is required (guard, detection, ui, intel, compliance, full).");
    return null;
  }

  if (!PLUGIN_TYPES.includes(typeFlag as PluginType)) {
    console.error(`Error: Invalid plugin type "${typeFlag}". Must be one of: ${PLUGIN_TYPES.join(", ")}`);
    return null;
  }

  const pluginType = typeFlag as PluginType;

  const contributionsFlag = getFlag(argv, "--contributions");
  let contributions: ContributionPoint[];
  if (contributionsFlag) {
    const parts = contributionsFlag.split(",").map((s) => s.trim());
    const invalid = parts.filter((p) => !CONTRIBUTION_POINTS.includes(p as ContributionPoint));
    if (invalid.length > 0) {
      console.error(`Error: Invalid contribution points: ${invalid.join(", ")}`);
      return null;
    }
    contributions = parts as ContributionPoint[];
  } else {
    contributions = PLUGIN_TYPE_DEFAULTS[pluginType];
  }

  const publisher = getFlag(argv, "--publisher") ?? "my-org";

  const pmFlag = getFlag(argv, "--pm") ?? "npm";
  if (!["npm", "bun", "pnpm"].includes(pmFlag)) {
    console.error(`Error: Invalid package manager "${pmFlag}". Must be one of: npm, bun, pnpm`);
    return null;
  }

  const displayName = toDisplayName(name);
  const outputDir = path.resolve(process.cwd(), name);

  return {
    name,
    displayName,
    publisher,
    type: pluginType,
    contributions,
    packageManager: pmFlag as "npm" | "bun" | "pnpm",
    outputDir,
  };
}
