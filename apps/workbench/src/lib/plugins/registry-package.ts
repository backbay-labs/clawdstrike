import { gunzipSync } from "fflate";

export interface RegistryPackageMetadata {
  entrypoint: string | null;
  packageJson: Record<string, unknown> | null;
  size: number;
}

function decodeAscii(bytes: Uint8Array): string {
  return new TextDecoder("utf-8").decode(bytes).replace(/\0.*$/, "").trim();
}

function parseOctal(value: string): number {
  const normalized = value.replace(/\0.*$/, "").trim();
  return normalized ? Number.parseInt(normalized, 8) : 0;
}

function normalizePackagePath(path: string): string {
  return path.replace(/^package\//, "").replace(/^\.\//, "");
}

function decodeText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8").decode(bytes);
}

function parseTarEntries(bytes: Uint8Array): Map<string, Uint8Array> {
  const entries = new Map<string, Uint8Array>();
  let offset = 0;

  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    const name = decodeAscii(header.subarray(0, 100));

    if (!name) {
      break;
    }

    const size = parseOctal(decodeAscii(header.subarray(124, 136)));
    const bodyStart = offset + 512;
    const bodyEnd = bodyStart + size;

    if (bodyEnd > bytes.length) {
      throw new Error("Registry package archive is truncated");
    }

    entries.set(name, bytes.slice(bodyStart, bodyEnd));

    offset = bodyStart + Math.ceil(size / 512) * 512;
  }

  return entries;
}

function resolvePackageEntrypoint(
  packageJson: Record<string, unknown> | null,
): string | null {
  if (!packageJson) {
    return null;
  }

  const exportsField = packageJson.exports;
  if (typeof exportsField === "string") {
    return normalizePackagePath(exportsField);
  }

  if (exportsField && typeof exportsField === "object") {
    const rootExport = (exportsField as Record<string, unknown>)["."];
    if (typeof rootExport === "string") {
      return normalizePackagePath(rootExport);
    }
    if (rootExport && typeof rootExport === "object") {
      const exportRecord = rootExport as Record<string, unknown>;
      if (typeof exportRecord.import === "string") {
        return normalizePackagePath(exportRecord.import);
      }
      if (typeof exportRecord.default === "string") {
        return normalizePackagePath(exportRecord.default);
      }
    }
  }

  if (typeof packageJson.module === "string") {
    return normalizePackagePath(packageJson.module);
  }

  if (typeof packageJson.main === "string") {
    return normalizePackagePath(packageJson.main);
  }

  return null;
}

export function extractRegistryPackageMetadata(
  archiveBuffer: ArrayBuffer,
): RegistryPackageMetadata {
  const archiveBytes = new Uint8Array(archiveBuffer);
  const tarBytes =
    archiveBytes[0] === 0x1f && archiveBytes[1] === 0x8b
      ? gunzipSync(archiveBytes)
      : archiveBytes;
  const entries = parseTarEntries(tarBytes);
  const packageJsonEntry = entries.get("package/package.json") ?? entries.get("package.json");

  if (!packageJsonEntry) {
    return {
      entrypoint: null,
      packageJson: null,
      size: archiveBuffer.byteLength,
    };
  }

  const packageJson = JSON.parse(
    decodeText(packageJsonEntry),
  ) as Record<string, unknown>;

  return {
    entrypoint: resolvePackageEntrypoint(packageJson),
    packageJson,
    size: archiveBuffer.byteLength,
  };
}

export function extractRegistryPackageFile(
  archiveBuffer: ArrayBuffer,
  filePath: string,
): string | null {
  const archiveBytes = new Uint8Array(archiveBuffer);
  const tarBytes =
    archiveBytes[0] === 0x1f && archiveBytes[1] === 0x8b
      ? gunzipSync(archiveBytes)
      : archiveBytes;
  const entries = parseTarEntries(tarBytes);
  const normalizedTarget = normalizePackagePath(filePath);

  for (const [name, content] of entries) {
    if (normalizePackagePath(name) === normalizedTarget) {
      return decodeText(content);
    }
  }

  return null;
}

export function selectLatestInstallableVersion(
  versions: Array<{ version: string; yanked: boolean }>,
  fallbackVersion: string | null | undefined,
): string {
  for (let index = versions.length - 1; index >= 0; index -= 1) {
    const candidate = versions[index];
    if (!candidate.yanked) {
      return candidate.version;
    }
  }

  return fallbackVersion ?? "0.0.0";
}
