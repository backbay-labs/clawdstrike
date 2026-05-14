import { useState, useEffect, useCallback, useRef } from "react";
import {
  IconSearch,
  IconLoader2,
  IconPlugConnected,
} from "@tabler/icons-react";
import { PluginCard } from "./plugin-card";
import { pluginRegistry } from "@/lib/plugins/plugin-registry";
import {
  registryClient,
  type RegistrySearchResult,
} from "@/lib/plugins/registry-client";
import { installPlugin, uninstallPlugin } from "@/lib/plugins/plugin-installer";
import {
  extractRegistryPackageMetadata,
  selectLatestInstallableVersion,
} from "@/lib/plugins/registry-package";
import type {
  PluginManifest,
  PluginTrustTier,
  RegisteredPlugin,
} from "@/lib/plugins/types";

// ---- Helpers ----

/** Convert a registry search result to a minimal PluginManifest for display. */
function asManifest(r: RegistrySearchResult): PluginManifest {
  return {
    id: r.name,
    name: r.name,
    displayName: r.name.replace(/^@[^/]+\//, "").replace(/-/g, " "),
    description: r.description ?? "",
    version: r.latest_version ?? "0.0.0",
    publisher: r.name.startsWith("@") ? r.name.split("/")[0].slice(1) : "unknown",
    categories: [],
    trust: "community" as PluginTrustTier,
    activationEvents: [],
  };
}

// ---- PluginsBrowser ----

export function PluginsBrowser() {
  const [searchQuery, setSearchQuery] = useState("");
  const [installedPlugins, setInstalledPlugins] = useState<RegisteredPlugin[]>(
    () => pluginRegistry.getAll(),
  );
  const [availablePlugins, setAvailablePlugins] = useState<
    RegistrySearchResult[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [registryError, setRegistryError] = useState<string | null>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ---- Subscribe to plugin registry changes ----
  useEffect(() => {
    const refresh = () => setInstalledPlugins(pluginRegistry.getAll());

    const unsub1 = pluginRegistry.subscribe("registered", refresh);
    const unsub2 = pluginRegistry.subscribe("unregistered", refresh);
    const unsub3 = pluginRegistry.subscribe("stateChanged", refresh);

    return () => {
      unsub1();
      unsub2();
      unsub3();
    };
  }, []);

  // ---- Fetch popular plugins on mount ----
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const popular = await registryClient.getPopular(20);
        if (!cancelled) {
          setAvailablePlugins(
            popular.map((p) => ({
              name: p.name,
              description: p.description,
              latest_version: p.latest_version,
            })),
          );
          setRegistryError(null);
        }
      } catch {
        if (!cancelled) {
          setRegistryError("Registry unavailable");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // ---- Search with debounce ----
  const handleSearch = useCallback((query: string) => {
    setSearchQuery(query);

    if (searchTimerRef.current) {
      clearTimeout(searchTimerRef.current);
    }

    if (!query.trim()) {
      // Reset to popular plugins
      setLoading(true);
      registryClient.getPopular(20).then(
        (popular) => {
          setAvailablePlugins(
            popular.map((p) => ({
              name: p.name,
              description: p.description,
              latest_version: p.latest_version,
            })),
          );
          setRegistryError(null);
          setLoading(false);
        },
        () => {
          setRegistryError("Registry unavailable");
          setLoading(false);
        },
      );
      return;
    }

    searchTimerRef.current = setTimeout(async () => {
      setLoading(true);
      const result = await registryClient.search(query.trim());
      if (result.error) {
        setRegistryError(result.error);
        setAvailablePlugins([]);
      } else {
        setRegistryError(null);
        setAvailablePlugins(result.packages);
      }
      setLoading(false);
    }, 300);
  }, []);

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (searchTimerRef.current) {
        clearTimeout(searchTimerRef.current);
      }
    };
  }, []);

  // ---- Filter installed plugins by search query ----
  const filteredInstalled = searchQuery.trim()
    ? installedPlugins.filter(
        (p) =>
          p.manifest.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.manifest.displayName
            .toLowerCase()
            .includes(searchQuery.toLowerCase()) ||
          p.manifest.description
            .toLowerCase()
            .includes(searchQuery.toLowerCase()),
      )
    : installedPlugins;

  // ---- Filter available plugins to exclude already-installed ----
  const installedIds = new Set(installedPlugins.map((p) => p.manifest.id));
  const filteredAvailable = availablePlugins.filter(
    (p) => !installedIds.has(p.name),
  );

  // ---- Install/Uninstall callbacks ----

  /**
   * Fetch the full manifest from the registry before installing.
   * The stub from asManifest() only has name/version/description; the real
   * package info (with accurate version, checksums) is resolved here so
   * the loader can fetch the actual package tarball containing the full
   * manifest (main, permissions, contributions).
   */
  const handleInstallFromRegistry = useCallback(
    async (stub: RegistrySearchResult) => {
      try {
        // Resolve the newest non-yanked release from the package history.
        const info = await registryClient.getPackageInfo(stub.name);
        const version = selectLatestInstallableVersion(
          info.versions,
          stub.latest_version,
        );
        const downloadUrl = registryClient.getDownloadUrl(stub.name, version);

        // Fetch the signed release metadata and the package archive so we can
        // recover the real bundle entrypoint instead of synthesizing one.
        const versionInfo = await registryClient.getVersionInfo(stub.name, version);
        const archiveResponse = await fetch(downloadUrl);
        if (!archiveResponse.ok) {
          throw new Error(
            `Failed to download ${stub.name}@${version}: HTTP ${archiveResponse.status}`,
          );
        }
        const archiveBuffer = await archiveResponse.arrayBuffer();
        const packageMetadata = extractRegistryPackageMetadata(archiveBuffer);

        // Build the install manifest from registry metadata plus the packaged
        // entrypoint so the loader can resolve the shipped bundle.
        const manifest: PluginManifest = {
          ...asManifest(stub),
          version,
          displayName:
            typeof packageMetadata.packageJson?.displayName === "string"
              ? packageMetadata.packageJson.displayName
              : asManifest(stub).displayName,
          description:
            typeof packageMetadata.packageJson?.description === "string"
              ? packageMetadata.packageJson.description
              : info.description ?? stub.description ?? "",
          main: packageMetadata.entrypoint ?? undefined,
          installation: {
            downloadUrl,
            size: Math.max(packageMetadata.size, 1),
            checksum: versionInfo.checksum,
            signature: versionInfo.publisher_sig,
            publisherKey: versionInfo.publisher_key,
          },
        };

        await installPlugin(manifest);
      } catch (err) {
        console.error(`Failed to install plugin ${stub.name}:`, err);
      }
    },
    [],
  );

  const handleUninstall = useCallback(async (pluginId: string) => {
    try {
      await uninstallPlugin(pluginId);
    } catch (err) {
      console.error(`Failed to uninstall plugin ${pluginId}:`, err);
    }
  }, []);

  return (
    <div className="space-y-8">
      {/* Search input */}
      <div className="relative">
        <IconSearch
          size={14}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6f7f9a]/50"
        />
        <input
          type="text"
          placeholder="Search plugins..."
          value={searchQuery}
          onChange={(e) => handleSearch(e.target.value)}
          className="w-full rounded-lg bg-[#131721]/50 border border-[#2d3240]/40 text-sm text-[#ece7dc] placeholder-[#6f7f9a]/50 pl-9 pr-3 py-2 focus:outline-none focus:border-[#d4a84b]/40 transition-colors"
        />
      </div>

      {/* Installed Plugins section */}
      <section>
        <h2 className="font-syne font-bold text-sm text-[#ece7dc] mb-4 flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#3dbf84]" />
          Installed Plugins
          {filteredInstalled.length > 0 && (
            <span className="text-[9px] font-mono text-[#6f7f9a] ml-1">
              ({filteredInstalled.length})
            </span>
          )}
        </h2>
        {filteredInstalled.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-10 text-center flex flex-col items-center">
            <div className="w-10 h-10 rounded-xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-3">
              <IconPlugConnected
                size={18}
                className="text-[#6f7f9a]"
              />
            </div>
            <p className="text-[12px] font-medium text-[#6f7f9a] mb-1">
              No plugins installed yet
            </p>
            <p className="text-[11px] text-[#6f7f9a]/60 max-w-[300px] leading-relaxed">
              Browse available plugins below and install one to extend the workbench
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredInstalled.map((p) => (
              <PluginCard
                key={p.manifest.id}
                manifest={p.manifest}
                state={p.state}
                error={p.error}
                onUninstall={() => handleUninstall(p.manifest.id)}
              />
            ))}
          </div>
        )}
      </section>

      {/* Available Plugins section */}
      <section>
        <h2 className="font-syne font-bold text-sm text-[#ece7dc] mb-4 flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b]" />
          Available Plugins
          {!loading && filteredAvailable.length > 0 && (
            <span className="text-[9px] font-mono text-[#6f7f9a] ml-1">
              ({filteredAvailable.length})
            </span>
          )}
        </h2>
        {loading ? (
          <div className="flex items-center justify-center py-12 gap-2">
            <IconLoader2
              size={16}
              className="animate-spin text-[#d4a84b]"
            />
            <span className="text-[12px] text-[#6f7f9a]">Loading...</span>
          </div>
        ) : registryError ? (
          <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-10 text-center flex flex-col items-center">
            <p className="text-[12px] font-medium text-[#6f7f9a] mb-1">
              Connect to a registry to browse available plugins
            </p>
            <p className="text-[11px] text-[#6f7f9a]/60 max-w-[300px] leading-relaxed">
              {registryError}
            </p>
          </div>
        ) : filteredAvailable.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-10 text-center">
            <p className="text-[12px] font-medium text-[#6f7f9a]">
              {searchQuery.trim()
                ? "No plugins match your search"
                : "No available plugins found"}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredAvailable.map((p) => (
              <PluginCard
                key={p.name}
                manifest={asManifest(p)}
                state="not-installed"
                onInstall={() => handleInstallFromRegistry(p)}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
