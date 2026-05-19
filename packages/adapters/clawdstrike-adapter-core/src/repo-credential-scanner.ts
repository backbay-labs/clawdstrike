import type { Dirent } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type {
  LocalEdrConfig,
  LocalEdrRepoScannerCredentialFinding,
} from "./local-edr-publisher.js";
import { publishRepoScannerCredentialFindingToLocalEdr } from "./local-edr-publisher.js";

export interface RepoCredentialScannerInput {
  rootDir: string;
  scannerId?: string;
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  maxEntries?: number;
  maxDepth?: number;
  config?: LocalEdrConfig;
}

export interface RepoCredentialScannerResult {
  scannedPathCount: number;
  publishedFindingCount: number;
  skippedDirectoryCount: number;
  truncated: boolean;
}

type CredentialPathClassification = Pick<
  LocalEdrRepoScannerCredentialFinding,
  "kind" | "credentialKind" | "name" | "ruleId"
>;

const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_MAX_DEPTH = 12;
const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  ".turbo",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

export async function scanRepositoryCredentialPathsForLocalEdr(
  input: RepoCredentialScannerInput,
): Promise<RepoCredentialScannerResult> {
  const rootDir = input.rootDir;
  const maxEntries = boundedPositiveInteger(input.maxEntries, DEFAULT_MAX_ENTRIES);
  const maxDepth = boundedPositiveInteger(input.maxDepth, DEFAULT_MAX_DEPTH);
  const result: RepoCredentialScannerResult = {
    scannedPathCount: 0,
    publishedFindingCount: 0,
    skippedDirectoryCount: 0,
    truncated: false,
  };

  async function walk(directory: string, depth: number): Promise<void> {
    if (result.scannedPathCount >= maxEntries) {
      result.truncated = true;
      return;
    }
    if (depth > maxDepth) return;

    let entries: Dirent<string>[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (result.scannedPathCount >= maxEntries) {
        result.truncated = true;
        return;
      }

      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(entry.name)) {
          result.skippedDirectoryCount += 1;
          continue;
        }
        await walk(path, depth + 1);
        continue;
      }

      if (!entry.isFile()) continue;
      const relativePath = normalizedRelativePath(rootDir, path);
      const classification = classifyRepositoryCredentialPath(relativePath);
      if (!classification) continue;
      result.scannedPathCount += 1;

      const publishable = await regularFileExists(path);
      if (!publishable) continue;

      await publishRepoScannerCredentialFindingToLocalEdr(
        {
          ...classification,
          path,
          scannerId: input.scannerId ?? "adapter-core-repo-scanner",
          repositoryPath: rootDir,
          hostId: input.hostId,
          userId: input.userId,
          sessionId: input.sessionId,
          agentId: input.agentId,
          workloadId: input.workloadId,
          approvalId: input.approvalId,
          metadata: {
            repositoryRelativePath: relativePath,
          },
        },
        input.config,
      );
      result.publishedFindingCount += 1;
    }
  }

  await walk(rootDir, 0);
  return result;
}

function classifyRepositoryCredentialPath(
  relativePath: string,
): CredentialPathClassification | null {
  const lower = relativePath.toLowerCase();
  const fileName = lower.split("/").pop() ?? lower;

  if (lower.includes("cookies") || lower.includes("browser-cookie")) {
    return {
      kind: "browser_cookie",
      credentialKind: "browser_cookie",
      name: "browser_cookie_store",
      ruleId: "repo.secret.browser_cookie_path",
    };
  }
  if (lower.includes("ci_token") || (lower.includes(".github/") && lower.includes("token"))) {
    return {
      kind: "ci_token",
      credentialKind: "api_token",
      name: credentialNameFromRelativePath(relativePath, "ci_token"),
      ruleId: "repo.secret.ci_token_path",
    };
  }
  if (lower.includes("local_api") || lower.includes("local-api")) {
    return {
      kind: "local_api_key",
      credentialKind: "api_token",
      name: credentialNameFromRelativePath(relativePath, "local_api_key"),
      ruleId: "repo.secret.local_api_key_path",
    };
  }
  if (
    fileName === ".env" ||
    fileName.startsWith(".env.") ||
    fileName === ".npmrc" ||
    fileName === ".pypirc" ||
    fileName === "credentials" ||
    fileName.includes("secret") ||
    fileName.includes("token") ||
    fileName.includes("api_key") ||
    fileName.includes("apikey")
  ) {
    return {
      kind: "repo_secret",
      credentialKind: credentialKindFromRelativePath(lower),
      name: credentialNameFromRelativePath(relativePath, "repo_secret"),
      ruleId: "repo.secret.credential_path",
    };
  }

  return null;
}

function credentialKindFromRelativePath(
  relativePath: string,
): LocalEdrRepoScannerCredentialFinding["credentialKind"] {
  if (relativePath.includes(".npmrc") || relativePath.includes(".pypirc")) {
    return "package_registry_token";
  }
  if (
    relativePath.includes(".aws") ||
    relativePath.includes("gcloud") ||
    relativePath.includes("azure")
  ) {
    return "cloud_credential";
  }
  if (relativePath.includes("id_rsa") || relativePath.includes("id_ed25519")) return "ssh_key";
  if (relativePath.includes("signing") || relativePath.includes("codesign")) return "signing_key";
  return "api_token";
}

function credentialNameFromRelativePath(relativePath: string, fallback: string): string {
  return (
    relativePath
      .split("/")
      .filter(Boolean)
      .pop()
      ?.replace(/[^A-Za-z0-9_.-]+/g, "_") || fallback
  );
}

function normalizedRelativePath(rootDir: string, path: string): string {
  return relative(rootDir, path).split(sep).join("/");
}

async function regularFileExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function boundedPositiveInteger(value: number | undefined, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const integer = Math.trunc(value);
  return integer > 0 ? integer : fallback;
}
