import { joinWorkspacePath, restoreFileRoutePath } from "@/lib/workbench/path-utils";

/**
 * toPresencePath -- normalize a file path to the same format the server uses.
 *
 * The hushd normalize_path function (crates/services/hushd/src/api/presence.rs):
 *   1. Replaces backslashes with forward slashes
 *   2. Strips leading drive letter (e.g. "C:/")
 *   3. Strips leading "/"
 *
 * We must produce identical output so that:
 *   - view_file sends match what the server broadcasts in analyst_viewing
 *   - viewersByFile lookups in tab dots and speakeasy use the same key format
 */
export function toPresencePath(path: string): string {
  let p = path.replace(/\\/g, "/");
  // Strip drive letter (C:/)
  if (p.length >= 3 && /^[a-zA-Z]$/.test(p[0]) && p[1] === ":" && p[2] === "/") {
    p = p.slice(3);
  }
  // Strip leading /
  if (p.startsWith("/")) {
    p = p.slice(1);
  }
  return p;
}

export function fromPresencePath(path: string, projectRoots: string[]): string {
  const normalizedPath = toPresencePath(path);
  const orderedRoots = projectRoots
    .map((rootPath) => ({
      rootPath,
      normalizedRoot: toPresencePath(rootPath),
    }))
    .sort((a, b) => b.normalizedRoot.length - a.normalizedRoot.length);

  const matchingRoot = orderedRoots.find(({ normalizedRoot }) =>
    normalizedPath === normalizedRoot ||
    normalizedPath.startsWith(`${normalizedRoot}/`),
  );

  if (matchingRoot) {
    const relativePath = normalizedPath
      .slice(matchingRoot.normalizedRoot.length)
      .replace(/^\/+/, "");
    return joinWorkspacePath(matchingRoot.rootPath, relativePath);
  }

  return restoreFileRoutePath(normalizedPath);
}
