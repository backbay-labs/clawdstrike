import { normalize, sep } from 'path';

/**
 * Bidirectional mapping from file paths to plugin IDs using
 * directory-prefix matching. Longest prefix wins for nested plugins.
 */
export class FilePluginMap {
  private dirToPluginId = new Map<string, string>();
  private pluginIdToEntry = new Map<string, string>();
  private pluginIdToDir = new Map<string, string>();

  register(pluginId: string, dir: string, entry?: string): void {
    const normalizedDir = this.normalizeDir(dir);
    this.dirToPluginId.set(normalizedDir, pluginId);
    this.pluginIdToDir.set(pluginId, normalizedDir);

    const entryFile = entry ?? 'src/index.ts';
    const entryPath = this.joinPath(normalizedDir, entryFile);
    this.pluginIdToEntry.set(pluginId, entryPath);
  }

  resolve(filePath: string): string | undefined {
    const normalized = this.normalizePath(filePath);

    let bestMatch: string | undefined;
    let bestLength = 0;

    for (const [dir, pluginId] of this.dirToPluginId) {
      // Check if the file path starts with the directory path
      if (this.isWithinDir(normalized, dir) && dir.length > bestLength) {
        bestMatch = pluginId;
        bestLength = dir.length;
      }
    }

    return bestMatch;
  }

  getEntry(pluginId: string): string | undefined {
    return this.pluginIdToEntry.get(pluginId);
  }

  getPluginDir(pluginId: string): string | undefined {
    return this.pluginIdToDir.get(pluginId);
  }

  private isWithinDir(filePath: string, dir: string): boolean {
    return filePath === this.stripTrailingSeparator(dir) || filePath.startsWith(dir);
  }

  private joinPath(dir: string, filePath: string): string {
    return this.normalizePath(
      `${this.stripTrailingSeparator(dir)}${sep}${filePath}`,
    );
  }

  private normalizePath(filePath: string): string {
    return normalize(filePath.replace(/[\\/]+/g, sep));
  }

  private normalizeDir(dir: string): string {
    const normalized = this.stripTrailingSeparator(this.normalizePath(dir));
    return normalized.endsWith(sep) ? normalized : `${normalized}${sep}`;
  }

  private stripTrailingSeparator(filePath: string): string {
    if (filePath === sep || /^[A-Za-z]:[\\/]$/.test(filePath)) {
      return filePath;
    }
    return filePath.endsWith(sep) ? filePath.slice(0, -1) : filePath;
  }
}
