/**
 * Registry Client Tests
 *
 * Tests for the RegistryClient class that provides typed access
 * to the clawdstrike-registry HTTP API. Uses vi.fn() to mock
 * global fetch so no network calls are made.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  RegistryClient,
  type RegistrySearchResponse,
  type RegistryPackageInfo,
  type RegistryPopularPackage,
  type RegistryAttestation,
} from "../registry-client";

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("RegistryClient", () => {
  let client: RegistryClient;

  beforeEach(() => {
    client = new RegistryClient("http://localhost:8080");
    mockFetch.mockReset();
  });

  // Test 1: search returns typed SearchResponse
  it("search returns typed SearchResponse with packages array and total count", async () => {
    const mockResponse: RegistrySearchResponse = {
      packages: [
        {
          name: "@acme/egress-guard",
          description: "Custom egress allowlist guard",
          latest_version: "1.2.0",
        },
        {
          name: "@corp/egress-monitor",
          description: null,
          latest_version: "0.3.1",
        },
      ],
      total: 2,
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await client.search("egress");

    expect(mockFetch).toHaveBeenCalledOnce();
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("api/v1/search");
    expect(calledUrl).toContain("q=egress");

    expect(result.packages).toHaveLength(2);
    expect(result.total).toBe(2);
    expect(result.packages[0].name).toBe("@acme/egress-guard");
    expect(result.packages[0].description).toBe(
      "Custom egress allowlist guard",
    );
    expect(result.packages[0].latest_version).toBe("1.2.0");
    expect(result.packages[1].description).toBeNull();
  });

  // Test 2: getPackageInfo returns PackageInfoResponse
  it("getPackageInfo returns PackageInfoResponse with name, description, versions array", async () => {
    const mockResponse: RegistryPackageInfo = {
      name: "@acme/guard",
      description: "A custom guard plugin",
      created_at: "2026-01-15T10:00:00Z",
      updated_at: "2026-03-10T14:30:00Z",
      total_downloads: 4200,
      versions: [
        {
          version: "1.0.0",
          pkg_type: "guard",
          checksum: "abc123def456",
          yanked: false,
          published_at: "2026-01-15T10:00:00Z",
          downloads: 3000,
        },
        {
          version: "1.1.0",
          pkg_type: "guard",
          checksum: "789ghi012jkl",
          yanked: false,
          published_at: "2026-03-10T14:30:00Z",
          downloads: 1200,
        },
      ],
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await client.getPackageInfo("@acme/guard");

    expect(mockFetch).toHaveBeenCalledOnce();
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("api/v1/packages/");
    expect(calledUrl).toContain(encodeURIComponent("@acme/guard"));

    expect(result.name).toBe("@acme/guard");
    expect(result.description).toBe("A custom guard plugin");
    expect(result.total_downloads).toBe(4200);
    expect(result.versions).toHaveLength(2);
    expect(result.versions[0].version).toBe("1.0.0");
    expect(result.versions[0].yanked).toBe(false);
    expect(result.versions[1].downloads).toBe(1200);
  });

  // Test 3: getPopular returns array of PopularPackage
  it("getPopular returns array of PopularPackage with name, description, totalDownloads, latestVersion", async () => {
    const mockResponse: RegistryPopularPackage[] = [
      {
        name: "@official/secret-leak",
        description: "Enhanced secret leak detection",
        total_downloads: 50000,
        latest_version: "2.0.0",
      },
      {
        name: "@community/kql-adapter",
        description: null,
        total_downloads: 12000,
        latest_version: "1.5.3",
      },
    ];

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await client.getPopular(10);

    expect(mockFetch).toHaveBeenCalledOnce();
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("api/v1/popular");
    expect(calledUrl).toContain("limit=10");

    expect(result).toHaveLength(2);
    expect(result[0].name).toBe("@official/secret-leak");
    expect(result[0].total_downloads).toBe(50000);
    expect(result[0].latest_version).toBe("2.0.0");
    expect(result[1].description).toBeNull();
  });

  // Test 4: getAttestation returns attestation with registryKey and publisherKey
  it("getAttestation returns attestation with registryKey and publisherKey", async () => {
    const mockResponse: RegistryAttestation = {
      name: "@acme/guard",
      version: "1.0.0",
      checksum: "abc123",
      publisher_key: "pub_hex_key",
      publisher_sig: "pub_hex_sig",
      registry_sig: "reg_hex_sig",
      key_id: "kid1",
      registry_key: "reg_hex_key",
      published_at: "2026-01-15T10:00:00Z",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    });

    const result = await client.getAttestation("@acme/guard", "1.0.0");

    expect(mockFetch).toHaveBeenCalledOnce();
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("api/v1/packages/");
    expect(calledUrl).toContain("attestation");

    expect(result.publisher_key).toBe("pub_hex_key");
    expect(result.publisher_sig).toBe("pub_hex_sig");
    expect(result.registry_key).toBe("reg_hex_key");
    expect(result.registry_sig).toBe("reg_hex_sig");
    expect(result.checksum).toBe("abc123");
  });

  // Test 5: search with network error returns empty result with error field
  it("search with network error returns empty result with error field", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Network error"));

    const result = await client.search("egress");

    expect(result.packages).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.error).toBe("Network error");
  });

  // Test 6: constructor accepts custom baseUrl
  it("constructor accepts custom baseUrl for non-default registry endpoints", async () => {
    const customClient = new RegistryClient(
      "https://registry.clawdstrike.io/v2",
    );

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ packages: [], total: 0 }),
    });

    await customClient.search("test");

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl.startsWith("https://registry.clawdstrike.io/v2/")).toBe(true);
  });

  // Additional test: getDownloadUrl returns correct URL without fetching
  it("getDownloadUrl returns the download URL without making a fetch call", () => {
    const url = client.getDownloadUrl("@acme/guard", "1.0.0");

    expect(url).toBe(
      "http://localhost:8080/api/v1/packages/%40acme%2Fguard/1.0.0/download",
    );
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // Additional test: getPackageStats returns stats
  it("getPackageStats returns package download statistics", async () => {
    const mockStats = {
      name: "@acme/guard",
      total_downloads: 4200,
      versions: [
        { version: "1.0.0", downloads: 3000, published_at: "2026-01-15T10:00:00Z" },
        { version: "1.1.0", downloads: 1200, published_at: "2026-03-10T14:30:00Z" },
      ],
      first_published: "2026-01-15T10:00:00Z",
      latest_version: "1.1.0",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockStats),
    });

    const result = await client.getPackageStats("@acme/guard");

    expect(mockFetch).toHaveBeenCalledOnce();
    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("api/v1/packages/");
    expect(calledUrl).toContain("stats");

    expect(result.name).toBe("@acme/guard");
    expect(result.total_downloads).toBe(4200);
    expect(result.versions).toHaveLength(2);
  });

  // Additional test: getPackageInfo throws on 404
  it("getPackageInfo throws on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
    });

    await expect(client.getPackageInfo("@nonexistent/pkg")).rejects.toThrow();
  });

  // Additional test: trailing slash stripped from baseUrl
  it("strips trailing slash from baseUrl", async () => {
    const slashClient = new RegistryClient("http://localhost:8080/");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ packages: [], total: 0 }),
    });

    await slashClient.search("test");

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl.startsWith("http://localhost:8080/api/v1/search")).toBe(true);
    // No double slash
    expect(calledUrl).not.toContain("8080//");
  });
});
