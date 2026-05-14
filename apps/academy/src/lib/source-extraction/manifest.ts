import path from 'node:path';

export interface ManifestEntry {
  /** Source file path relative to the repo root */
  file: string;
  /** Tags expected to be found in this file */
  expectedTags: string[];
}

/**
 * Repo root, computed from this file's location:
 * apps/academy/src/lib/source-extraction/ -> up 5 levels to repo root
 */
export const REPO_ROOT = path.resolve(
  import.meta.dirname,
  '../../../../..',
);

/** Output directory for extracted JSON source files */
export const OUT_DIR = path.resolve(
  import.meta.dirname,
  '../../data/extracted-sources',
);

/**
 * Manifest of source files to scan for @academy tagged regions.
 * Content authors add entries here; the prebuild script validates
 * that all expected tags exist in the referenced files.
 *
 * Start with placeholder entries -- tags will be added to source
 * files as lessons are authored in Phase 3.
 */
export const EXTRACTION_MANIFEST: ManifestEntry[] = [
  // Guards - Green tier
  { file: 'crates/libs/clawdstrike/src/guards/forbidden_path.rs', expectedTags: ['forbidden-path-check', 'forbidden-path-defaults'] },
  { file: 'crates/libs/clawdstrike/src/guards/path_allowlist.rs', expectedTags: ['path-allowlist-check', 'path-allowlist-match'] },
  { file: 'crates/libs/clawdstrike/src/guards/egress_allowlist.rs', expectedTags: ['egress-allowlist-check', 'egress-domain-eval'] },
  // Guards - Yellow tier
  { file: 'crates/libs/clawdstrike/src/guards/secret_leak.rs', expectedTags: ['secret-leak-scan', 'secret-leak-patterns'] },
  { file: 'crates/libs/clawdstrike/src/guards/shell_command.rs', expectedTags: ['shell-command-check', 'shell-command-extract'] },
  { file: 'crates/libs/clawdstrike/src/guards/patch_integrity.rs', expectedTags: ['patch-integrity-analyze', 'patch-integrity-check'] },
  { file: 'crates/libs/clawdstrike/src/guards/mcp_tool.rs', expectedTags: ['mcp-tool-decision', 'mcp-tool-check'] },
  // Guards - Orange tier
  { file: 'crates/libs/clawdstrike/src/guards/prompt_injection.rs', expectedTags: ['prompt-injection-check'] },
  { file: 'crates/libs/clawdstrike/src/guards/jailbreak.rs', expectedTags: ['jailbreak-check'] },
  { file: 'crates/libs/clawdstrike/src/guards/computer_use.rs', expectedTags: ['computer-use-check'] },
  // Guards - Red tier
  { file: 'crates/libs/clawdstrike/src/spider_sense.rs', expectedTags: ['spider-sense-search', 'spider-sense-cosine'] },
  { file: 'crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs', expectedTags: ['remote-desktop-check', 'remote-desktop-candidate'] },
  { file: 'crates/libs/clawdstrike/src/guards/input_injection_capability.rs', expectedTags: ['input-injection-check'] },
  // Security regressions
  { file: 'crates/libs/clawdstrike/tests/security_regressions.rs', expectedTags: ['security-regression-url-spoof'] },
  // Network IRM
  { file: 'crates/libs/clawdstrike/src/irm/net.rs', expectedTags: ['net-irm-extract-host'] },
];
