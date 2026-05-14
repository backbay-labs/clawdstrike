/**
 * Default workspace bootstrapping for first-launch experience.
 *
 * On first launch (no prior workspace), scaffolds ~/.clawdstrike/workspace/
 * with example policies, Sigma rules, YARA rules, and scenarios so the
 * Explorer is never empty.
 *
 * All Tauri API calls are lazily imported so this module can be safely
 * imported in non-Tauri contexts (tests, SSR) without throwing.
 */

import { isDesktop } from "@/lib/tauri-bridge";
import { BUILTIN_RULESETS } from "@/features/policy/builtin-rulesets";

const TAURI_FS_SPECIFIER = "@tauri-apps/plugin-fs";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Workspace directory name relative to user home. */
export const WORKSPACE_DIR_NAME = ".clawdstrike/workspace";

/** Subdirectories created inside the default workspace. */
export const WORKSPACE_SUBDIRS = [
  "policies",
  "sigma/examples",
  "yara/examples",
  "scenarios",
];

/** IDs of the built-in rulesets written as editable YAML files. */
const BOOTSTRAP_RULESET_IDS = [
  "permissive",
  "default",
  "strict",
  "ai-agent",
  "cicd",
];

// ---------------------------------------------------------------------------
// Example content
// ---------------------------------------------------------------------------

const EXAMPLE_SIGMA_RULE = `title: Suspicious Process Creation
status: experimental
description: Detects suspicious process creation patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
    CommandLine|contains:
      - 'whoami'
      - 'net user'
  condition: selection
level: medium
`;

const EXAMPLE_YARA_RULE = `rule SuspiciousStrings {
    meta:
        description = "Detects suspicious string patterns"
        author = "ClawdStrike Workbench"
        date = "2026-01-01"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "mimikatz" nocase
    condition:
        any of them
}
`;

const EXAMPLE_SCENARIO = `name: Basic File Access Test
description: Tests file access guards against common sensitive paths
steps:
  - action: file_read
    target: /etc/passwd
    expect: blocked
  - action: file_read
    target: /workspace/src/main.rs
    expect: allowed
  - action: file_write
    target: /home/user/.ssh/id_rsa
    expect: blocked
`;

const README_CONTENT = `# ClawdStrike Workspace

Welcome to your ClawdStrike detection engineering workspace.

## Structure

- **policies/** -- Editable security policy rulesets (YAML). These are copies of the
  built-in rulesets that you can customise freely.
- **sigma/examples/** -- Example Sigma detection rules.
- **yara/examples/** -- Example YARA detection rules.
- **scenarios/** -- Test scenarios for guard evaluation.

## Getting Started

1. Open any policy file in the editor to review or customise guards.
2. Use the command palette (Cmd+Shift+P) to run guard tests against scenarios.
3. Add your own rules by creating new files in the appropriate directory.

## Adding More Folders

Use the "Add Folder" button at the bottom of the Explorer panel to mount
additional directories as workspace roots.
`;

async function importTauriFs() {
  return import(/* @vite-ignore */ TAURI_FS_SPECIFIER);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the absolute path to the default workspace directory.
 * Uses the user's home directory from the Tauri path API.
 */
export async function getDefaultWorkspacePath(): Promise<string> {
  const { homeDir } = await import("@tauri-apps/api/path");
  const home = await homeDir();
  // Ensure no trailing slash on home before joining.
  const cleanHome = home.endsWith("/") ? home.slice(0, -1) : home;
  return `${cleanHome}/${WORKSPACE_DIR_NAME}`;
}

/**
 * Bootstrap the default workspace if it does not already exist.
 *
 * - Creates ~/.clawdstrike/workspace/ with subdirectories
 * - Writes editable copies of built-in rulesets into policies/
 * - Writes example Sigma, YARA, and scenario files
 * - Writes a README.md with getting-started guidance
 *
 * Returns the workspace path on success, or null if not running in
 * desktop mode or if the workspace already existed.
 *
 * Errors are caught and logged -- the app continues to work without
 * a bootstrapped workspace (fail-open for UX).
 */
export async function bootstrapDefaultWorkspace(): Promise<string | null> {
  if (!isDesktop()) return null;

  try {
    const workspacePath = await getDefaultWorkspacePath();

    const { exists, mkdir, writeTextFile } = await importTauriFs();

    // Check if workspace has already been fully scaffolded by looking for
    // the sentinel file (README.md).  The directory itself may exist (e.g.
    // created by a prior `createDetectionFile` or `mkdir`) without having
    // any of the example content, so checking the directory alone is not
    // sufficient.
    const sentinelPath = `${workspacePath}/README.md`;
    const alreadyBootstrapped = await exists(sentinelPath);
    if (alreadyBootstrapped) {
      return workspacePath;
    }

    // Create root directory.
    await mkdir(workspacePath, { recursive: true });

    // Create subdirectories.
    for (const subdir of WORKSPACE_SUBDIRS) {
      await mkdir(`${workspacePath}/${subdir}`, { recursive: true });
    }

    // Write built-in rulesets as editable YAML files.
    const rulesets = BUILTIN_RULESETS.filter((r) =>
      BOOTSTRAP_RULESET_IDS.includes(r.id),
    );
    for (const ruleset of rulesets) {
      await writeTextFile(
        `${workspacePath}/policies/${ruleset.id}.yaml`,
        ruleset.yaml,
      );
    }

    // Write example Sigma rule.
    await writeTextFile(
      `${workspacePath}/sigma/examples/suspicious-process.yml`,
      EXAMPLE_SIGMA_RULE,
    );

    // Write example YARA rule.
    await writeTextFile(
      `${workspacePath}/yara/examples/suspicious-strings.yar`,
      EXAMPLE_YARA_RULE,
    );

    // Write example scenario.
    await writeTextFile(
      `${workspacePath}/scenarios/basic-file-access.yaml`,
      EXAMPLE_SCENARIO,
    );

    // Write workspace README.
    await writeTextFile(`${workspacePath}/README.md`, README_CONTENT);

    return workspacePath;
  } catch (err) {
    console.error("[workspace-bootstrap] Failed to bootstrap workspace:", err);
    return null;
  }
}
