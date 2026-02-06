/**
 * MarketplaceView - Discover and share community policies
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { clsx } from "clsx";
import { useConnection } from "@/context/ConnectionContext";
import { loadMarketplaceFeedSources, saveMarketplaceFeedSources } from "@/services/marketplaceSettings";
import { loadMarketplaceProvenanceSettings } from "@/services/marketplaceProvenanceSettings";
import {
  getMarketplaceDiscoveryStatus,
  installMarketplacePolicy,
  isTauri,
  listMarketplacePolicies,
  verifyMarketplaceAttestation,
  type MarketplaceDiscoveryEvent,
  type MarketplaceDiscoveryStatus,
  type MarketplaceListResponse,
  type MarketplacePolicyDto,
  type NotaryVerifyResult,
} from "@/services/tauri";

type PolicyCategory = "all" | "compliance" | "ai-safety" | "enterprise" | "minimal" | "custom";

const CATEGORIES: { id: PolicyCategory; label: string }[] = [
  { id: "all", label: "All" },
  { id: "compliance", label: "Compliance" },
  { id: "ai-safety", label: "AI Safety" },
  { id: "enterprise", label: "Enterprise" },
  { id: "minimal", label: "Minimal" },
  { id: "custom", label: "Custom" },
];

type AttestationCacheEntry =
  | { status: "pending" }
  | { status: "done"; result: NotaryVerifyResult }
  | { status: "error"; error: string };

export function MarketplaceView() {
  const { status, daemonUrl } = useConnection();

  const [category, setCategory] = useState<PolicyCategory>("all");
  const [search, setSearch] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState<MarketplacePolicyDto | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<MarketplaceListResponse | null>(null);

  const [discoveryStatus, setDiscoveryStatus] = useState<MarketplaceDiscoveryStatus | null>(null);
  const [discoveredFeeds, setDiscoveredFeeds] = useState<MarketplaceDiscoveryEvent[]>([]);

  const [provenanceSettings] = useState(() => loadMarketplaceProvenanceSettings());
  const [requireVerifiedAttestations, setRequireVerifiedAttestations] = useState(
    provenanceSettings.requireVerified
  );
  const trustedAttesters = useMemo(
    () => provenanceSettings.trustedAttesters.map((a) => a.trim().toLowerCase()).filter(Boolean),
    [provenanceSettings.trustedAttesters]
  );
  const defaultNotaryUrl = provenanceSettings.notaryUrl;
  const [attestationCache, setAttestationCache] = useState<Record<string, AttestationCacheEntry>>(
    {}
  );

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const sources = loadMarketplaceFeedSources();
      const res = await listMarketplacePolicies(sources);
      setData(res);
    } catch (e) {
      setData(null);
      setError(e instanceof Error ? e.message : "Failed to load marketplace feed");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!isTauri()) return;

    getMarketplaceDiscoveryStatus().then(setDiscoveryStatus).catch(() => {
      // ignore
    });

    let unlisten: (() => void) | null = null;
    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        unlisten = await listen<MarketplaceDiscoveryEvent>("marketplace_discovery", (e) => {
          const payload = e.payload;
          if (!payload?.announcement?.feed_uri) return;
          setDiscoveredFeeds((prev) => {
            const uri = payload.announcement.feed_uri;
            const withoutDup = prev.filter((x) => x.announcement.feed_uri !== uri);
            return [payload, ...withoutDup].slice(0, 20);
          });
        });
      } catch {
        // ignore
      }
    })();

    return () => {
      unlisten?.();
    };
  }, []);

  const handleAddDiscoveredSource = async (feedUri: string) => {
    const current = loadMarketplaceFeedSources();
    if (current.includes(feedUri)) return;
    saveMarketplaceFeedSources([...current, feedUri]);
    await refresh();
  };

  const verifyAttestation = useCallback(async (notaryUrl: string, uid: string) => {
    const key = toAttestationKey(notaryUrl, uid);
    setAttestationCache((prev) => ({ ...prev, [key]: { status: "pending" } }));
    try {
      const result = await verifyMarketplaceAttestation(notaryUrl, uid);
      setAttestationCache((prev) => ({ ...prev, [key]: { status: "done", result } }));
    } catch (e) {
      const message = e instanceof Error ? e.message : "Verification failed";
      setAttestationCache((prev) => ({ ...prev, [key]: { status: "error", error: message } }));
    }
  }, []);

  useEffect(() => {
    if (!requireVerifiedAttestations) return;
    if (!isTauri()) return;

    const policies = data?.policies ?? [];
    const pointers = policies
      .map((policy) => resolveAttestationPointer(policy, defaultNotaryUrl))
      .filter((p): p is AttestationPointer => p !== null);

    const missing = pointers.filter((p) => {
      const key = toAttestationKey(p.notaryUrl, p.uid);
      return attestationCache[key] === undefined;
    });
    if (missing.length === 0) return;

    setAttestationCache((prev) => {
      const next = { ...prev };
      for (const p of missing) {
        const key = toAttestationKey(p.notaryUrl, p.uid);
        if (next[key] === undefined) {
          next[key] = { status: "pending" };
        }
      }
      return next;
    });

    let cancelled = false;
    const queue = missing.slice();
    const workers = Array.from({ length: 3 }, async () => {
      while (!cancelled) {
        const p = queue.shift();
        if (!p) break;
        await verifyAttestation(p.notaryUrl, p.uid);
      }
    });

    Promise.all(workers).catch(() => {
      // ignore
    });

    return () => {
      cancelled = true;
    };
  }, [
    requireVerifiedAttestations,
    data,
    defaultNotaryUrl,
    attestationCache,
    verifyAttestation,
  ]);

  const filteredPolicies = useMemo(() => {
    const policies = data?.policies ?? [];
    return policies.filter((policy) => {
      const policyCategory = normalizeCategory(policy.category);
      if (category !== "all" && policyCategory !== category) return false;
      if (search) {
        const searchLower = search.toLowerCase();
        const matchesSearch =
          policy.title.toLowerCase().includes(searchLower) ||
          policy.description.toLowerCase().includes(searchLower) ||
          policy.entry_id.toLowerCase().includes(searchLower) ||
          policy.tags.some((t) => t.toLowerCase().includes(searchLower));
        if (!matchesSearch) return false;
      }

      if (requireVerifiedAttestations) {
        const pointer = resolveAttestationPointer(policy, defaultNotaryUrl);
        if (!pointer) return false;
        const key = toAttestationKey(pointer.notaryUrl, pointer.uid);
        const cached = attestationCache[key];
        if (!cached || cached.status === "pending") return false;
        if (cached.status === "error") return false;
        if (!cached.result.valid) return false;

        if (trustedAttesters.length > 0) {
          const attester = cached.result.attester?.trim().toLowerCase();
          if (!attester) return false;
          if (!trustedAttesters.includes(attester)) return false;
        }
      }

      return true;
    });
  }, [
    category,
    search,
    data,
    requireVerifiedAttestations,
    defaultNotaryUrl,
    attestationCache,
    trustedAttesters,
  ]);

  const attestationPointers = useMemo(() => {
    const policies = data?.policies ?? [];
    const pointers = policies
      .map((policy) => resolveAttestationPointer(policy, defaultNotaryUrl))
      .filter((p): p is AttestationPointer => p !== null);

    const seen = new Set<string>();
    const out: AttestationPointer[] = [];
    for (const p of pointers) {
      const key = toAttestationKey(p.notaryUrl, p.uid);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(p);
    }
    return out;
  }, [data, defaultNotaryUrl]);

  const pendingAttestationCount = useMemo(() => {
    let pending = 0;
    for (const p of attestationPointers) {
      const key = toAttestationKey(p.notaryUrl, p.uid);
      const cached = attestationCache[key];
      if (!cached || cached.status === "pending") pending += 1;
    }
    return pending;
  }, [attestationPointers, attestationCache]);

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <h1 className="text-lg font-semibold text-sdr-text-primary">Policy Marketplace</h1>
          <p className="text-sm text-sdr-text-muted mt-0.5">
            Discover and install signed policy bundles
          </p>
          {data && (
            <p className="text-xs text-sdr-text-muted mt-1">
              Feed: {data.feed_id} · Signed by {formatKey(data.signer_public_key)}
            </p>
          )}
        </div>

        {/* Search and filters */}
        <div className="px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary/50">
          <div className="flex items-center gap-4">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sdr-text-muted" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search policies..."
                className="w-full pl-9 pr-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
              />
            </div>

            {/* Category tabs */}
            <div className="flex items-center gap-1">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setCategory(cat.id)}
                  className={clsx(
                    "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                    category === cat.id
                      ? "bg-sdr-accent-blue/20 text-sdr-accent-blue"
                      : "text-sdr-text-secondary hover:text-sdr-text-primary hover:bg-sdr-bg-tertiary"
                  )}
                >
                  {cat.label}
                </button>
              ))}
            </div>

            <button
              onClick={() => setRequireVerifiedAttestations(!requireVerifiedAttestations)}
              className={clsx(
                "px-3 py-1.5 text-sm font-medium rounded-md transition-colors border",
                requireVerifiedAttestations
                  ? "bg-sdr-accent-green/10 text-sdr-accent-green border-sdr-accent-green/40"
                  : "text-sdr-text-secondary hover:text-sdr-text-primary hover:bg-sdr-bg-tertiary border-sdr-border"
              )}
              title={
                trustedAttesters.length > 0
                  ? `Verified only (trusted attesters: ${trustedAttesters.length})`
                  : "Verified only"
              }
            >
              Verified only
            </button>
          </div>
        </div>

        {/* Policy grid */}
        <div className="flex-1 overflow-y-auto p-4">
          {discoveredFeeds.length > 0 && (
            <div className="mb-4 p-3 rounded-md border border-sdr-border bg-sdr-bg-secondary text-xs text-sdr-text-muted">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sdr-text-primary font-medium">Discovered feeds</div>
                  <div className="mt-0.5">
                    Gossip is untrusted. Adding a source still requires signature verification.
                  </div>
                </div>
                {discoveryStatus && (
                  <div className="text-right">
                    <div>{discoveryStatus.running ? "Discovery running" : "Discovery stopped"}</div>
                    {discoveryStatus.peer_id && <div className="opacity-80">{formatKey(discoveryStatus.peer_id)}</div>}
                  </div>
                )}
              </div>
              <ul className="mt-2 space-y-1">
                {discoveredFeeds.slice(0, 5).map((d) => (
                  <li key={d.announcement.feed_uri} className="flex items-center justify-between gap-3">
                    <span className="font-mono">{d.announcement.feed_uri}</span>
                    <button
                      onClick={() => handleAddDiscoveredSource(d.announcement.feed_uri)}
                      className="px-2 py-1 rounded border border-sdr-border hover:bg-sdr-bg-tertiary"
                    >
                      Add to sources
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {isLoading ? (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              Loading marketplace…
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center h-full text-sdr-text-muted">
              <p className="text-sm">Failed to load marketplace</p>
              <p className="text-xs mt-1">{error}</p>
              <button
                onClick={refresh}
                className="mt-3 px-3 py-1.5 text-sm rounded-md border border-sdr-border hover:bg-sdr-bg-tertiary"
              >
                Retry
              </button>
            </div>
          ) : filteredPolicies.length === 0 ? (
            requireVerifiedAttestations ? (
              <div className="flex flex-col items-center justify-center h-full text-sdr-text-muted">
                {attestationPointers.length === 0 ? (
                  <>
                    <p className="text-sm">No verifiable attestations</p>
                    <p className="text-xs mt-1">
                      Configure a notary URL in Settings, or use a feed that provides <code>notary_url</code>.
                    </p>
                  </>
                ) : pendingAttestationCount > 0 ? (
                  <>
                    <p className="text-sm">Verifying attestations…</p>
                    <p className="text-xs mt-1">
                      Checking {pendingAttestationCount} attestation{pendingAttestationCount === 1 ? "" : "s"} via notary
                    </p>
                  </>
                ) : (
                  <p className="text-sm">No verified policies found</p>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-sdr-text-muted">
                No policies found
              </div>
            )
          ) : (
            <div className="space-y-3">
              {(data?.warnings?.length ?? 0) > 0 && (
                <div className="p-3 rounded-md border border-sdr-border bg-sdr-bg-secondary text-xs text-sdr-text-muted">
                  Some entries were skipped:
                  <ul className="list-disc pl-5 mt-1 space-y-0.5">
                    {data?.warnings?.slice(0, 5).map((w) => <li key={w}>{w}</li>)}
                  </ul>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredPolicies.map((policy) => {
                  const attestationUid = getAttestationUid(policy);
                  const pointer = resolveAttestationPointer(policy, defaultNotaryUrl);
                  const key = pointer ? toAttestationKey(pointer.notaryUrl, pointer.uid) : null;
                  const cached = key ? attestationCache[key] : undefined;
                  return (
                    <PolicyCard
                      key={policy.entry_id}
                      policy={policy}
                      attestationUid={attestationUid}
                      attestationStatus={cached}
                      onClick={() => setSelectedPolicy(policy)}
                    />
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selectedPolicy && (
        <PolicyDetailPanel
          policy={selectedPolicy}
          daemonUrl={daemonUrl}
          connected={status === "connected"}
          defaultNotaryUrl={defaultNotaryUrl}
          trustedAttesters={trustedAttesters}
          attestationCache={attestationCache}
          onVerifyAttestation={verifyAttestation}
          onClose={() => setSelectedPolicy(null)}
        />
      )}
    </div>
  );
}

interface PolicyCardProps {
  policy: MarketplacePolicyDto;
  attestationUid: string | null;
  attestationStatus?: AttestationCacheEntry;
  onClick: () => void;
}

function PolicyCard({ policy, attestationUid, attestationStatus, onClick }: PolicyCardProps) {
  const policyVersion = policy.signed_bundle.bundle.policy.version;
  const author = policy.author ?? "Unknown";
  const hasSigner = Boolean(policy.bundle_public_key);
  const attestationPill = getAttestationPill(attestationUid, attestationStatus);

  return (
    <button
      onClick={onClick}
      className="text-left p-4 bg-sdr-bg-secondary rounded-lg border border-sdr-border hover:border-sdr-accent-blue/50 transition-colors"
    >
      <div className="flex items-start justify-between mb-2">
        <div>
          <h3 className="font-medium text-sdr-text-primary">{policy.title}</h3>
          <div className="flex items-center gap-1 text-xs text-sdr-text-muted mt-0.5">
            <span>{author}</span>
            {hasSigner && <VerifiedBadge />}
            {attestationPill}
          </div>
        </div>
        <span className="text-xs text-sdr-text-muted">v{policyVersion}</span>
      </div>

      <p className="text-sm text-sdr-text-secondary line-clamp-2 mb-3">
        {policy.description}
      </p>

      <div className="flex flex-wrap gap-1 mt-3">
        {policy.tags.slice(0, 3).map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 text-xs bg-sdr-bg-tertiary text-sdr-text-muted rounded"
          >
            {tag}
          </span>
        ))}
      </div>
    </button>
  );
}

interface PolicyDetailPanelProps {
  policy: MarketplacePolicyDto;
  daemonUrl: string;
  connected: boolean;
  defaultNotaryUrl: string | null;
  trustedAttesters: string[];
  attestationCache: Record<string, AttestationCacheEntry>;
  onVerifyAttestation: (notaryUrl: string, uid: string) => Promise<void>;
  onClose: () => void;
}

function PolicyDetailPanel({
  policy,
  daemonUrl,
  connected,
  defaultNotaryUrl,
  trustedAttesters,
  attestationCache,
  onVerifyAttestation,
  onClose,
}: PolicyDetailPanelProps) {
  const [isInstalling, setIsInstalling] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);
  const [installSuccess, setInstallSuccess] = useState<string | null>(null);

  const handleInstall = async () => {
    setInstallError(null);
    setInstallSuccess(null);
    setIsInstalling(true);
    try {
      await installMarketplacePolicy(daemonUrl, policy.signed_bundle);
      setInstallSuccess("Policy installed successfully");
    } catch (e) {
      setInstallError(e instanceof Error ? e.message : "Install failed");
    } finally {
      setIsInstalling(false);
    }
  };

  const author = policy.author ?? "Unknown";
  const policyVersion = policy.signed_bundle.bundle.policy.version;
  const policyHash = policy.signed_bundle.bundle.policy_hash;
  const bundleSigner = policy.bundle_public_key ?? null;

  const attestationUid = getAttestationUid(policy);
  const attestationPointer = resolveAttestationPointer(policy, defaultNotaryUrl);
  const attestationKey = attestationPointer
    ? toAttestationKey(attestationPointer.notaryUrl, attestationPointer.uid)
    : null;
  const attestationCached = attestationKey ? attestationCache[attestationKey] : undefined;

  const isAttestationPending = attestationCached?.status === "pending";
  const attestationResult = attestationCached?.status === "done" ? attestationCached.result : null;
  const attestationError = attestationCached?.status === "error" ? attestationCached.error : null;
  const attester = attestationResult?.attester?.trim().toLowerCase() ?? null;
  const attesterTrusted =
    trustedAttesters.length === 0 ? true : attester ? trustedAttesters.includes(attester) : false;

  return (
    <div className="w-96 border-l border-sdr-border bg-sdr-bg-secondary flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border">
        <h2 className="font-medium text-sdr-text-primary">{policy.title}</h2>
        <button
          onClick={onClose}
          className="p-1 text-sdr-text-muted hover:text-sdr-text-primary rounded"
        >
          <CloseIcon />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Author */}
        <div className="flex items-center gap-2">
          <div className="w-10 h-10 rounded-full bg-sdr-bg-tertiary flex items-center justify-center text-sdr-text-muted">
            {author[0]}
          </div>
          <div>
            <div className="flex items-center gap-1">
              <span className="text-sm font-medium text-sdr-text-primary">{author}</span>
              {bundleSigner && <VerifiedBadge />}
            </div>
            <span className="text-xs text-sdr-text-muted">v{policyVersion}</span>
          </div>
        </div>

        {/* Description */}
        <div>
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Description
          </h3>
          <p className="text-sm text-sdr-text-secondary">{policy.description}</p>
        </div>

        {/* Tags */}
        <div>
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Tags
          </h3>
          <div className="flex flex-wrap gap-1">
            {policy.tags.map((tag) => (
              <span
                key={tag}
                className="px-2 py-0.5 text-xs bg-sdr-bg-tertiary text-sdr-text-secondary rounded"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>

        {/* Signing */}
        <div className="text-sm text-sdr-text-secondary">
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Signing
          </h3>
          <p>Policy hash: {formatKey(policyHash)}</p>
          <p>Bundle signer: {bundleSigner ? formatKey(bundleSigner) : "missing public_key"}</p>
        </div>

        {/* Provenance */}
        <div className="text-sm text-sdr-text-secondary">
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Provenance
          </h3>
          {attestationUid ? (
            <div className="space-y-1">
              <p>Attestation UID: {formatKey(attestationUid)}</p>
              <p>
                Notary: {attestationPointer ? attestationPointer.notaryUrl : defaultNotaryUrl ?? "unset"}
              </p>
              {attestationResult && (
                <>
                  <p>
                    Status:{" "}
                    {attestationResult.valid ? (
                      <span className="text-sdr-accent-green">valid</span>
                    ) : (
                      <span className="text-sdr-accent-red">invalid</span>
                    )}
                  </p>
                  {attestationResult.attester && <p>Attester: {formatKey(attestationResult.attester)}</p>}
                  {attestationResult.attested_at && <p>Attested at: {attestationResult.attested_at}</p>}
                  {!attesterTrusted && (
                    <p className="text-sdr-accent-red">Untrusted attester (see Settings → Marketplace Provenance)</p>
                  )}
                </>
              )}
              {attestationError && <p className="text-sdr-accent-red">Verify error: {attestationError}</p>}
              {!attestationResult && !attestationError && (
                <p className="text-xs text-sdr-text-muted">
                  Not verified yet.
                </p>
              )}
              <button
                onClick={() => {
                  if (!attestationPointer || isAttestationPending) return;
                  onVerifyAttestation(attestationPointer.notaryUrl, attestationPointer.uid).catch(() => {
                    // errors are surfaced via cached status
                  });
                }}
                disabled={!attestationPointer || isAttestationPending}
                className="mt-2 px-3 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors disabled:opacity-50"
              >
                {isAttestationPending ? "Verifying..." : "Verify attestation"}
              </button>
            </div>
          ) : (
            <p className="text-xs text-sdr-text-muted">No attestation provided.</p>
          )}
        </div>

        {installError && (
          <div className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-sm text-red-200">
            {installError}
          </div>
        )}
        {installSuccess && (
          <div className="p-3 rounded-md border border-green-500/40 bg-green-500/10 text-sm text-green-200">
            {installSuccess}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="p-4 border-t border-sdr-border">
        <button
          onClick={handleInstall}
          disabled={!connected || isInstalling}
          className="w-full px-4 py-2.5 bg-sdr-accent-blue text-white font-medium rounded-md hover:bg-sdr-accent-blue/90 disabled:opacity-50 transition-colors"
        >
          {!connected ? "Connect to install" : isInstalling ? "Installing..." : "Install Policy"}
        </button>
      </div>
    </div>
  );
}

function VerifiedBadge() {
  return (
    <svg className="w-3.5 h-3.5 text-sdr-accent-blue" viewBox="0 0 20 20" fill="currentColor">
      <path
        fillRule="evenodd"
        d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function AttestationPill({ kind }: { kind: "attested" | "verified" | "invalid" | "error" }) {
  const className = clsx(
    "px-1.5 py-0.5 rounded border text-[10px] uppercase tracking-wide",
    kind === "verified" && "border-sdr-accent-green/40 text-sdr-accent-green bg-sdr-accent-green/10",
    kind === "attested" && "border-sdr-border text-sdr-text-muted bg-sdr-bg-tertiary",
    kind === "invalid" && "border-sdr-accent-red/40 text-sdr-accent-red bg-sdr-accent-red/10",
    kind === "error" && "border-sdr-accent-red/40 text-sdr-accent-red bg-sdr-accent-red/10"
  );

  const label = kind === "verified" ? "verified" : kind === "attested" ? "attested" : kind;

  return <span className={className}>{label}</span>;
}

function getAttestationPill(attestationUid: string | null, status?: AttestationCacheEntry) {
  if (!attestationUid) return null;
  if (!status) return <AttestationPill kind="attested" />;
  if (status.status === "pending") return <AttestationPill kind="attested" />;
  if (status.status === "error") return <AttestationPill kind="error" />;
  return status.result.valid ? <AttestationPill kind="verified" /> : <AttestationPill kind="invalid" />;
}

interface AttestationPointer {
  uid: string;
  notaryUrl: string;
}

function toAttestationKey(notaryUrl: string, uid: string): string {
  return `${notaryUrl.trim()}::${uid.trim()}`.toLowerCase();
}

function getAttestationUid(policy: MarketplacePolicyDto): string | null {
  const fromEntry = normalizeString(policy.attestation_uid);
  if (fromEntry) return fromEntry;

  const fromMetadata = extractAttestationPointerFromMetadata(policy.signed_bundle.bundle.metadata);
  return fromMetadata?.uid ?? null;
}

function resolveAttestationPointer(
  policy: MarketplacePolicyDto,
  defaultNotaryUrl: string | null
): AttestationPointer | null {
  const uid = getAttestationUid(policy);
  if (!uid) return null;

  const fromEntryNotary = normalizeString(policy.notary_url);
  const fromMetadata = extractAttestationPointerFromMetadata(policy.signed_bundle.bundle.metadata);
  const notaryUrl = fromEntryNotary ?? fromMetadata?.notaryUrl ?? defaultNotaryUrl ?? null;
  if (!notaryUrl) return null;

  return { uid, notaryUrl };
}

function extractAttestationPointerFromMetadata(
  metadata: unknown
): { uid: string; notaryUrl: string | null } | null {
  const obj = asObject(metadata);
  if (!obj) return null;

  const directUid = normalizeString(obj.attestation_uid) ?? normalizeString(obj.attestationUid);
  const directNotary = normalizeString(obj.notary_url) ?? normalizeString(obj.notaryUrl);
  if (directUid) return { uid: directUid, notaryUrl: directNotary };

  const attestation = asObject(obj.attestation);
  if (attestation) {
    const uid = normalizeString(attestation.uid) ?? normalizeString(attestation.attestation_uid);
    const notaryUrl = normalizeString(attestation.notary_url) ?? normalizeString(attestation.notaryUrl);
    if (uid) return { uid, notaryUrl };
  }

  const marketplace = asObject(obj.marketplace);
  if (marketplace) {
    const uid = normalizeString(marketplace.attestation_uid) ?? normalizeString(marketplace.attestationUid);
    const notaryUrl = normalizeString(marketplace.notary_url) ?? normalizeString(marketplace.notaryUrl);
    if (uid) return { uid, notaryUrl };
  }

  return null;
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null) return null;
  if (Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function normalizeCategory(category: string | null | undefined): PolicyCategory {
  switch ((category ?? "").toLowerCase()) {
    case "compliance":
      return "compliance";
    case "ai-safety":
    case "ai_safety":
    case "ai safety":
      return "ai-safety";
    case "enterprise":
      return "enterprise";
    case "minimal":
      return "minimal";
    default:
      return "custom";
  }
}

function formatKey(key: string): string {
  const trimmed = key.trim();
  if (trimmed.length <= 16) return trimmed;
  return `${trimmed.slice(0, 8)}…${trimmed.slice(-8)}`;
}

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8" />
      <path d="M21 21l-4.35-4.35" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}
