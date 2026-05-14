/**
 * Registry Client
 *
 * Typed TypeScript client for the clawdstrike-registry HTTP API.
 * Provides search, package info, popular packages, download stats,
 * and attestation verification methods.
 *
 * Response types use snake_case field names to match the Rust API
 * serde serialization exactly (no camelCase conversion).
 *
 * Used by the Plugins tab UI (Plan 06-02) and install flow (Plan 06-03).
 */

// ---- Response Type Interfaces ----
// These match the Rust API response shapes from clawdstrike-registry

/** A single search result from GET /api/v1/search. Matches db.rs SearchResult. */
export interface RegistrySearchResult {
  name: string;
  description: string | null;
  latest_version: string | null;
}

/** Search response from GET /api/v1/search. Matches api/search.rs SearchResponse. */
export interface RegistrySearchResponse {
  packages: RegistrySearchResult[];
  total: number;
  /** Present only when the request failed (network error, non-ok status). */
  error?: string;
}

/** Version summary within a package info response. Matches api/info.rs VersionSummary. */
export interface RegistryVersionSummary {
  version: string;
  pkg_type: string;
  checksum: string;
  yanked: boolean;
  published_at: string;
  downloads: number;
}

/** Package info response from GET /api/v1/packages/{name}. Matches api/info.rs PackageInfoResponse. */
export interface RegistryPackageInfo {
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  total_downloads: number;
  versions: RegistryVersionSummary[];
}

/** Per-version download statistics. Matches db.rs VersionStats. */
export interface RegistryVersionStats {
  version: string;
  downloads: number;
  published_at: string;
}

/** Package download statistics from GET /api/v1/packages/{name}/stats. Matches db.rs PackageStats. */
export interface RegistryPackageStats {
  name: string;
  total_downloads: number;
  versions: RegistryVersionStats[];
  first_published: string | null;
  latest_version: string | null;
}

/** Popular package entry from GET /api/v1/popular. Matches db.rs PopularPackage. */
export interface RegistryPopularPackage {
  name: string;
  description: string | null;
  total_downloads: number;
  latest_version: string | null;
}

/** Version info response from GET /api/v1/packages/{name}/{version}. Matches api/info.rs VersionInfoResponse. */
export interface RegistryVersionInfo {
  name: string;
  version: string;
  pkg_type: string;
  checksum: string;
  manifest_toml: string;
  publisher_key: string;
  publisher_sig: string;
  registry_sig: string | null;
  dependencies: Record<string, unknown>;
  yanked: boolean;
  published_at: string;
  downloads: number;
}

/** Attestation response from GET /api/v1/packages/{name}/{version}/attestation. Matches api/attestation.rs AttestationResponse. */
export interface RegistryAttestation {
  name: string;
  version: string;
  checksum: string;
  publisher_key: string;
  publisher_sig: string;
  registry_sig: string | null;
  key_id: string | null;
  registry_key: string | null;
  published_at: string;
}

// ---- RegistryClient Class ----

/**
 * HTTP client for the clawdstrike-registry API.
 *
 * Each method maps to a registry API endpoint:
 * - search()          -> GET /api/v1/search?q=...&limit=...&offset=...
 * - getPackageInfo()  -> GET /api/v1/packages/{name}
 * - getPopular()      -> GET /api/v1/popular?limit=...
 * - getPackageStats() -> GET /api/v1/packages/{name}/stats
 * - getAttestation()  -> GET /api/v1/packages/{name}/{version}/attestation
 * - getDownloadUrl()  -> pure function returning download URL
 */
export class RegistryClient {
  private baseUrl: string;

  constructor(baseUrl: string = "http://localhost:8080") {
    // Strip trailing slash to avoid double-slash in URLs
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  /**
   * Search for packages matching a query string.
   *
   * Fail-open for browsing: on network error or non-ok response,
   * returns an empty result set with an error field rather than throwing.
   */
  async search(
    query: string,
    limit = 20,
    offset = 0,
  ): Promise<RegistrySearchResponse> {
    try {
      const params = new URLSearchParams({
        q: query,
        limit: String(limit),
        offset: String(offset),
      });
      const response = await fetch(
        `${this.baseUrl}/api/v1/search?${params.toString()}`,
      );

      if (!response.ok) {
        return {
          packages: [],
          total: 0,
          error: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      return (await response.json()) as RegistrySearchResponse;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Unknown network error";
      return { packages: [], total: 0, error: message };
    }
  }

  /**
   * Get detailed info for a specific package, including all version summaries.
   *
   * Throws on network error or non-ok response since this is a specific
   * lookup (not browsing).
   */
  async getPackageInfo(name: string): Promise<RegistryPackageInfo> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/packages/${encodeURIComponent(name)}`,
    );

    if (!response.ok) {
      throw new Error(
        `Failed to get package info for '${name}': HTTP ${response.status}`,
      );
    }

    return (await response.json()) as RegistryPackageInfo;
  }

  /**
   * Get popular packages ranked by download count.
   *
   * Returns an empty array on error (fail-open for browsing).
   */
  async getPopular(limit = 20): Promise<RegistryPopularPackage[]> {
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      const response = await fetch(
        `${this.baseUrl}/api/v1/popular?${params.toString()}`,
      );

      if (!response.ok) {
        return [];
      }

      return (await response.json()) as RegistryPopularPackage[];
    } catch {
      return [];
    }
  }

  /**
   * Get download statistics for a specific package.
   *
   * Throws on network error or non-ok response.
   */
  async getPackageStats(name: string): Promise<RegistryPackageStats> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/packages/${encodeURIComponent(name)}/stats`,
    );

    if (!response.ok) {
      throw new Error(
        `Failed to get stats for '${name}': HTTP ${response.status}`,
      );
    }

    return (await response.json()) as RegistryPackageStats;
  }

  /**
   * Get detailed info for a specific version, including manifest TOML,
   * checksum, and publisher/registry signatures.
   *
   * Throws on network error or non-ok response.
   */
  async getVersionInfo(
    name: string,
    version: string,
  ): Promise<RegistryVersionInfo> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
    );

    if (!response.ok) {
      throw new Error(
        `Failed to get version info for '${name}@${version}': HTTP ${response.status}`,
      );
    }

    return (await response.json()) as RegistryVersionInfo;
  }

  /**
   * Get the publish attestation for a specific package version.
   *
   * Returns publisher and registry signatures for verification.
   * Throws on network error or non-ok response.
   */
  async getAttestation(
    name: string,
    version: string,
  ): Promise<RegistryAttestation> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/attestation`,
    );

    if (!response.ok) {
      throw new Error(
        `Failed to get attestation for '${name}@${version}': HTTP ${response.status}`,
      );
    }

    return (await response.json()) as RegistryAttestation;
  }

  /**
   * Get the download URL for a specific package version.
   *
   * This is a pure function that constructs the URL without making
   * any network requests. The actual download is handled by the
   * install flow (Plan 06-03).
   */
  getDownloadUrl(name: string, version: string): string {
    return `${this.baseUrl}/api/v1/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/download`;
  }
}

// ---- Singleton ----

/** Default RegistryClient instance for the workbench. */
export const registryClient = new RegistryClient();
