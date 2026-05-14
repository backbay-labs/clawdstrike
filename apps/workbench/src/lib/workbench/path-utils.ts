export function normalizeWorkspacePath(path: string): string {
  return path.replace(/\\/g, "/");
}

export function isWindowsAbsolutePath(path: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(path);
}

export function isAbsoluteWorkspacePath(path: string): boolean {
  return (
    path.startsWith("/") ||
    path.startsWith("\\\\") ||
    path.startsWith("//") ||
    isWindowsAbsolutePath(path)
  );
}

function normalizeWorkspaceRootPath(rootPath: string): string {
  const normalized = normalizeWorkspacePath(rootPath);
  if (normalized === "/" || /^[A-Za-z]:\/$/.test(normalized)) {
    return normalized;
  }
  return normalized.replace(/\/+$/, "");
}

function hasWorkspaceRootPrefix(path: string, rootPath: string): boolean {
  if (path === rootPath) {
    return true;
  }
  if (rootPath.endsWith("/")) {
    return path.startsWith(rootPath);
  }
  return path.startsWith(`${rootPath}/`);
}

export function joinWorkspacePath(rootPath: string, childPath: string): string {
  const normalizedRoot = normalizeWorkspaceRootPath(rootPath);
  const normalizedChild = normalizeWorkspacePath(childPath).replace(/^\/+/, "");

  if (!normalizedRoot) {
    return normalizedChild;
  }
  if (!normalizedChild) {
    return normalizedRoot;
  }
  return normalizedRoot.endsWith("/")
    ? `${normalizedRoot}${normalizedChild}`
    : `${normalizedRoot}/${normalizedChild}`;
}

export function relativeWorkspacePath(rootPath: string, path: string): string {
  const normalizedPath = normalizeWorkspacePath(path);
  if (!isAbsoluteWorkspacePath(normalizedPath)) {
    return normalizedPath.replace(/^\/+/, "");
  }

  const normalizedRoot = normalizeWorkspaceRootPath(rootPath);
  if (!hasWorkspaceRootPrefix(normalizedPath, normalizedRoot)) {
    return normalizedPath.replace(/^\/+/, "");
  }

  return normalizedPath.slice(normalizedRoot.length).replace(/^\/+/, "");
}

export function resolveWorkspaceRootPath(
  rootPaths: string[],
  path: string,
): string | null {
  const normalizedPath = normalizeWorkspacePath(path);
  if (!isAbsoluteWorkspacePath(normalizedPath)) {
    return null;
  }

  const orderedRoots = rootPaths
    .map((rootPath) => ({
      rootPath,
      normalizedRoot: normalizeWorkspaceRootPath(rootPath),
    }))
    .sort((a, b) => b.normalizedRoot.length - a.normalizedRoot.length);

  return (
    orderedRoots.find(({ normalizedRoot }) =>
      hasWorkspaceRootPrefix(normalizedPath, normalizedRoot),
    )?.rootPath ?? null
  );
}

export function restoreFileRoutePath(rawParam: string): string {
  const decoded = decodeURIComponent(rawParam);

  if (
    decoded.length === 0 ||
    decoded.startsWith("__new__/") ||
    decoded.startsWith("/") ||
    decoded.startsWith("\\\\") ||
    isWindowsAbsolutePath(decoded)
  ) {
    return decoded;
  }

  return `/${decoded}`;
}
