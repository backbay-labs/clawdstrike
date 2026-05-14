import { extractRegistryPackageFile } from "./registry-package";
import { rewritePluginSdkImports } from "./sdk-import-rewrite";
import type { PluginManifest } from "./types";

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function transformCommunityPluginSource(source: string): string {
  let code = rewritePluginSdkImports(source);

  code = code.replace(
    /export\s*\{\s*([A-Za-z_$][\w$]*)\s+as\s+default\s*\};?/g,
    "window.__CLAWDSTRIKE_PLUGIN__ = $1;",
  );
  code = code.replace(
    /export\s+default\s+/g,
    "window.__CLAWDSTRIKE_PLUGIN__ = ",
  );
  code = code.replace(/export\s*\{[^}]+\};?\s*$/gm, "");

  return code;
}

export async function resolveRegistryPluginCode(
  manifest: PluginManifest,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const downloadUrl = manifest.installation?.downloadUrl;
  if (!downloadUrl) {
    throw new Error(
      `Cannot load community plugin "${manifest.id}": installation.downloadUrl is missing`,
    );
  }
  const expectedChecksum = manifest.installation?.checksum;
  if (!expectedChecksum) {
    throw new Error(
      `Cannot load community plugin "${manifest.id}": installation.checksum is missing`,
    );
  }
  if (!manifest.main) {
    throw new Error(
      `Cannot load community plugin "${manifest.id}": main entry point is missing`,
    );
  }

  const response = await fetcher(downloadUrl);
  if (!response.ok) {
    throw new Error(
      `Failed to download plugin package for "${manifest.id}": HTTP ${response.status}`,
    );
  }

  const archiveBuffer = await response.arrayBuffer();
  const actualChecksum = await sha256Hex(archiveBuffer);
  if (actualChecksum !== expectedChecksum.toLowerCase()) {
    throw new Error(
      `Failed to verify plugin package checksum for "${manifest.id}"`,
    );
  }
  const entrypointSource = extractRegistryPackageFile(
    archiveBuffer,
    manifest.main,
  );

  if (entrypointSource === null) {
    throw new Error(
      `Failed to load plugin entrypoint "${manifest.main}" from package "${manifest.id}"`,
    );
  }

  return transformCommunityPluginSource(entrypointSource);
}
