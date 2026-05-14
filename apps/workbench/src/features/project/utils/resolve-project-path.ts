export const WINDOWS_ABSOLUTE_PATH = /^[A-Za-z]:[\\/]/;
export const UNC_ABSOLUTE_PATH = /^[\\/]{2}[^\\/]+[\\/][^\\/]+/;

function normalizeProjectPath(path: string): string {
  const slashNormalized = path.replace(/\\/g, "/");
  const hasUncPrefix = UNC_ABSOLUTE_PATH.test(path) || slashNormalized.startsWith("//");
  const collapsed = hasUncPrefix
    ? `//${slashNormalized.replace(/^\/+/, "").replace(/\/+/g, "/")}`
    : slashNormalized.replace(/\/+/g, "/");

  if (collapsed === "/" || collapsed === "//" || /^[A-Za-z]:\/$/.test(collapsed)) {
    return collapsed;
  }

  return collapsed.replace(/\/+$/, "");
}

export function getProjectPathBasename(filePath: string): string {
  const normalized = filePath.replace(/[\\/]+$/, "");
  const lastSeparator = Math.max(normalized.lastIndexOf("/"), normalized.lastIndexOf("\\"));
  return lastSeparator >= 0 ? normalized.slice(lastSeparator + 1) : normalized;
}

export function isValidProjectBasename(name: string): boolean {
  const trimmed = name.trim();
  if (!trimmed || trimmed === "." || trimmed === "..") {
    return false;
  }

  return !/[\\/]/.test(trimmed);
}

export function isAbsoluteProjectPath(path: string | null | undefined): boolean {
  return typeof path === "string"
    && (path.startsWith("/") || WINDOWS_ABSOLUTE_PATH.test(path) || UNC_ABSOLUTE_PATH.test(path));
}

export function resolveProjectPath(
  rootPath: string | null | undefined,
  filePath: string,
): string {
  if (!rootPath || isAbsoluteProjectPath(filePath)) {
    return normalizeProjectPath(filePath);
  }

  const normalizedRoot = normalizeProjectPath(rootPath);
  const normalizedFile = normalizeProjectPath(filePath).replace(/^\/+/, "");
  return `${normalizedRoot}/${normalizedFile}`;
}

export function stripProjectRoot(
  rootPath: string | null | undefined,
  filePath: string,
): string {
  const normalizedFile = normalizeProjectPath(filePath);
  if (!rootPath) {
    return normalizedFile.replace(/^\/+/, "");
  }

  const normalizedRoot = normalizeProjectPath(rootPath);
  if (normalizedFile === normalizedRoot) {
    return "";
  }

  if (normalizedFile.startsWith(`${normalizedRoot}/`)) {
    return normalizedFile.slice(normalizedRoot.length + 1);
  }

  return normalizedFile.replace(/^\/+/, "");
}

export function getProjectPathDirname(filePath: string): string | null {
  const normalized = filePath.replace(/[\\/]+$/, "");
  const lastSeparator = Math.max(normalized.lastIndexOf("/"), normalized.lastIndexOf("\\"));
  return lastSeparator >= 0 ? normalized.slice(0, lastSeparator) : null;
}

export function replaceProjectPathBasename(filePath: string, newName: string): string {
  const parentPath = getProjectPathDirname(filePath);
  if (!parentPath) {
    return newName;
  }

  const separator = parentPath.includes("\\") && !parentPath.includes("/") ? "\\" : "/";
  return `${parentPath}${separator}${newName}`;
}

interface ParsedAbsoluteDirectory {
  kind: "posix" | "windows" | "unc";
  prefix: string;
  separator: "/" | "\\";
  directories: string[];
}

function parseAbsoluteDirectory(filePath: string): ParsedAbsoluteDirectory | null {
  if (!isAbsoluteProjectPath(filePath)) {
    return null;
  }

  const normalized = normalizeProjectPath(filePath);
  if (WINDOWS_ABSOLUTE_PATH.test(filePath)) {
    const [drive, ...segments] = normalized.split("/");
    return {
      kind: "windows",
      prefix: drive,
      separator: "\\",
      directories: segments.filter(Boolean).slice(0, -1),
    };
  }

  if (normalized.startsWith("//")) {
    const [server, share, ...segments] = normalized.replace(/^\/+/, "").split("/");
    if (!server || !share) {
      return null;
    }

    return {
      kind: "unc",
      prefix: `//${server}/${share}`,
      separator: "/",
      directories: segments.filter(Boolean).slice(0, -1),
    };
  }

  return {
    kind: "posix",
    prefix: "/",
    separator: "/",
    directories: normalized.split("/").filter(Boolean).slice(0, -1),
  };
}

function stringifyAbsoluteDirectory(
  parsed: ParsedAbsoluteDirectory,
  directories = parsed.directories,
): string {
  if (parsed.kind === "windows") {
    return directories.length > 0
      ? `${parsed.prefix}${parsed.separator}${directories.join(parsed.separator)}`
      : `${parsed.prefix}${parsed.separator}`;
  }

  if (parsed.kind === "unc") {
    return directories.length > 0 ? `${parsed.prefix}/${directories.join("/")}` : parsed.prefix;
  }

  return directories.length > 0 ? `/${directories.join("/")}` : "/";
}

function deriveSearchRootFromProjectFiles(
  absoluteFilePaths: string[],
  projectRelativeFilePaths: string[],
): string | null {
  if (projectRelativeFilePaths.length === 0) {
    return null;
  }

  const candidateRoots = absoluteFilePaths
    .map((absoluteFilePath) => {
      const parsedAbsolutePath = parseAbsoluteDirectory(absoluteFilePath);
      if (!parsedAbsolutePath) {
        return null;
      }

      const normalizedAbsolutePath = normalizeProjectPath(absoluteFilePath);
      const absoluteSegments = normalizedAbsolutePath.split("/").filter(Boolean);
      const absoluteBasename = absoluteSegments[absoluteSegments.length - 1];
      if (!absoluteBasename) {
        return null;
      }

      const matches = projectRelativeFilePaths
        .map((relativeFilePath) => {
          const normalizedRelativePath = normalizeProjectPath(relativeFilePath).replace(/^\/+/, "");
          const relativeSegments = normalizedRelativePath.split("/").filter(Boolean);
          const relativeBasename = relativeSegments[relativeSegments.length - 1];
          const relativeDirectories = relativeSegments.slice(0, -1);

          if (
            relativeSegments.length === 0
            || relativeBasename !== absoluteBasename
            || relativeDirectories.length > parsedAbsolutePath.directories.length
          ) {
            return null;
          }

          const absoluteTail = parsedAbsolutePath.directories.slice(
            parsedAbsolutePath.directories.length - relativeDirectories.length,
          );
          if (absoluteTail.join("/") !== relativeDirectories.join("/")) {
            return null;
          }

          return stringifyAbsoluteDirectory(
            parsedAbsolutePath,
            parsedAbsolutePath.directories.slice(
              0,
              parsedAbsolutePath.directories.length - relativeDirectories.length,
            ),
          );
        })
        .filter((candidate): candidate is string => candidate !== null);

      return matches.length === 1 ? matches[0] : null;
    })
    .filter((candidate): candidate is string => candidate !== null);

  if (candidateRoots.length === 0) {
    return null;
  }

  const [firstRoot, ...restRoots] = candidateRoots;
  return restRoots.every((candidate) => candidate === firstRoot) ? firstRoot : null;
}

export function deriveSearchRootPath(
  rootPath: string | null | undefined,
  absoluteFilePaths: string[],
  projectRelativeFilePaths: string[] = [],
): string | null {
  if (isAbsoluteProjectPath(rootPath)) {
    return rootPath ?? null;
  }

  const projectDerivedRoot = deriveSearchRootFromProjectFiles(
    absoluteFilePaths,
    projectRelativeFilePaths,
  );
  if (projectDerivedRoot) {
    return projectDerivedRoot;
  }

  const parsedPaths = absoluteFilePaths
    .map((filePath) => parseAbsoluteDirectory(filePath))
    .filter((parsed): parsed is ParsedAbsoluteDirectory => parsed !== null);

  if (parsedPaths.length === 0) {
    return null;
  }

  const [first, ...rest] = parsedPaths;
  let commonDirectories = [...first.directories];

  for (const parsed of rest) {
    if (parsed.kind !== first.kind || parsed.prefix !== first.prefix) {
      return stringifyAbsoluteDirectory(first);
    }

    let sharedIndex = 0;
    while (
      sharedIndex < commonDirectories.length
      && sharedIndex < parsed.directories.length
      && commonDirectories[sharedIndex] === parsed.directories[sharedIndex]
    ) {
      sharedIndex += 1;
    }
    commonDirectories = commonDirectories.slice(0, sharedIndex);
    if (commonDirectories.length === 0) {
      return stringifyAbsoluteDirectory(first);
    }
  }

  return stringifyAbsoluteDirectory(first, commonDirectories);
}
