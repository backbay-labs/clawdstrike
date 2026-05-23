import { useCallback, useMemo, useState } from "react";
import {
  FINDING_ENVELOPE_SCHEMA,
  type FindingEnvelope,
  type ProtocolSeverity,
} from "@/features/swarm/swarm-protocol";
import { useSwarmFeed } from "@/features/swarm/stores/swarm-feed-store";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import type { OperatorIdentity } from "@/lib/workbench/operator-types";
import {
  fetchSwarmBlobLookup,
  fetchVerifiedBlobArtifact,
  fetchVerifiedFindingBlob,
  requestSwarmBlobPin,
  type SwarmBlobPinResponse,
} from "@/features/swarm/swarm-blob-client";
import type { Intel } from "@/lib/workbench/sentinel-types";
import type { FindingBlobRef } from "@/features/swarm/swarm-protocol";

export const PROTOCOL_SEVERITY_TAGS: readonly ProtocolSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export function issuerIdFromPublicKey(publicKey: string): string {
  return `aegis:ed25519:${publicKey}`;
}

export function inferEnvelopeSeverity(intel: Intel): ProtocolSeverity {
  const taggedSeverity = intel.tags.find((tag): tag is ProtocolSeverity =>
    PROTOCOL_SEVERITY_TAGS.includes(tag as ProtocolSeverity),
  );
  if (taggedSeverity) {
    return taggedSeverity;
  }
  if (intel.confidence >= 0.9) {
    return "high";
  }
  if (intel.confidence >= 0.75) {
    return "medium";
  }
  return "low";
}

export function inferSignalCount(intel: Intel): number {
  const maybeSignalCount =
    typeof intel.receipt.evidence === "object" &&
    intel.receipt.evidence !== null &&
    "signal_count" in intel.receipt.evidence
      ? intel.receipt.evidence.signal_count
      : null;

  if (typeof maybeSignalCount === "number" && Number.isFinite(maybeSignalCount)) {
    return maybeSignalCount;
  }

  return Math.max(1, intel.derivedFrom.length);
}

export function buildFindingEnvelope(
  intel: Intel,
  publishedAt: number,
  feedSeq: number,
  issuerId: string,
): FindingEnvelope {
  const findingId = intel.derivedFrom[0] ?? intel.id;
  const relatedFindingIds =
    intel.derivedFrom.length > 1 ? intel.derivedFrom.slice(1) : undefined;

  return {
    schema: FINDING_ENVELOPE_SCHEMA,
    findingId,
    issuerId,
    feedId: issuerId,
    feedSeq,
    publishedAt,
    title: intel.title,
    summary: intel.description,
    severity: inferEnvelopeSeverity(intel),
    confidence: intel.confidence,
    status: "promoted",
    signalCount: inferSignalCount(intel),
    tags: intel.tags,
    blobRefs: [],
    ...(relatedFindingIds ? { relatedFindingIds } : {}),
  };
}

export function resolvePublisherIdentity(
  intel: Intel,
  currentOperator: OperatorIdentity | null,
): {
  fingerprint: string;
  issuerId: string;
} | null {
  const publisherPublicKey = currentOperator?.publicKey ?? intel.signerPublicKey;
  if (!publisherPublicKey) {
    return null;
  }

  return {
    fingerprint: currentOperator?.fingerprint ?? intel.author,
    issuerId: issuerIdFromPublicKey(publisherPublicKey),
  };
}

export function truncateDigest(digest: string): string {
  if (digest.length <= 23) {
    return digest;
  }

  return `${digest.slice(0, 12)}...${digest.slice(-8)}`;
}

export interface DiscoveredSwarmBlobRef {
  key: string;
  swarmId: string;
  findingId: string;
  title: string;
  publishedAt: number;
  ref: FindingBlobRef;
}

export type BlobVerificationState =
  | {
      status: "verifying";
    }
  | {
      status: "verified";
      sourceUri: string;
      artifactCount: number;
    }
  | {
      status: "failed";
      message: string;
      canRequestPin: boolean;
    }
  | {
      status: "pinning";
    }
  | {
      status: "pinned";
      response: SwarmBlobPinResponse;
    };

export type HubTrustHydrationStatus = "idle" | "pending" | "success" | "error";

export function SwarmArtifactsPanel({
  intel,
  swarmIds,
  requestedBy,
}: {
  intel: Intel;
  swarmIds: string[];
  requestedBy?: string;
}) {
  const { connection, getCredentials } = useFleetConnection();
  const { projectedFindingRecords } = useSwarmFeed();
  const [states, setStates] = useState<Record<string, BlobVerificationState | undefined>>({});

  const discoveredBlobRefs = useMemo(() => {
    const relatedFindingIds = new Set([intel.derivedFrom[0] ?? intel.id, ...intel.derivedFrom.slice(1)]);
    const scopedSwarmIds = new Set(swarmIds);
    const seen = new Set<string>();
    const discovered: DiscoveredSwarmBlobRef[] = [];

    for (const record of projectedFindingRecords) {
      if (scopedSwarmIds.size > 0 && !scopedSwarmIds.has(record.swarmId)) {
        continue;
      }

      const envelopeFindingIds = [
        ...(record.sourceFindingIds ?? []),
        record.envelope.findingId,
        ...(record.envelope.relatedFindingIds ?? []),
      ];
      if (!envelopeFindingIds.some((findingId) => relatedFindingIds.has(findingId))) {
        continue;
      }

      for (const ref of record.envelope.blobRefs) {
        const key = `${record.swarmId}:${record.envelope.feedId}:${record.envelope.findingId}:${ref.digest}`;
        if (seen.has(key)) {
          continue;
        }

        seen.add(key);
        discovered.push({
          key,
          swarmId: record.swarmId,
          findingId: record.envelope.findingId,
          title: record.envelope.title,
          publishedAt: record.envelope.publishedAt,
          ref,
        });
      }
    }

    return discovered.sort((left, right) => right.publishedAt - left.publishedAt);
  }, [intel.derivedFrom, intel.id, projectedFindingRecords, swarmIds]);

  const hasFleetConnection = Boolean(connection.hushdUrl);

  const handleVerifyBlob = useCallback(
    async (blobRef: DiscoveredSwarmBlobRef) => {
      if (!connection.hushdUrl) {
        setStates((prev) => ({
          ...prev,
          [blobRef.key]: {
            status: "failed",
            message: "Configure a fleet hushd endpoint to verify this blob.",
            canRequestPin: false,
          },
        }));
        return;
      }

      setStates((prev) => ({
        ...prev,
        [blobRef.key]: { status: "verifying" },
      }));

      let bytesAvailable: boolean | null = null;

      try {
        const creds = getCredentials();
        const lookup = await fetchSwarmBlobLookup(
          {
            hushdUrl: connection.hushdUrl,
            apiKey: creds.apiKey || undefined,
          },
          blobRef.ref.digest,
        );
        bytesAvailable = lookup.bytesAvailable;

        const lookupMatch =
          lookup.refs.find((entry) => entry.blobId === blobRef.ref.blobId) ?? lookup.refs[0];
        const effectiveRef: FindingBlobRef =
          blobRef.ref.publish?.uri || !lookupMatch?.publish
            ? blobRef.ref
            : {
                ...blobRef.ref,
                publish: lookupMatch.publish,
              };
        const result = await fetchVerifiedFindingBlob(effectiveRef);
        let verifiedArtifactCount = 0;
        for (const artifact of result.blob.artifacts) {
          await fetchVerifiedBlobArtifact(artifact);
          verifiedArtifactCount += 1;
        }

        setStates((prev) => ({
          ...prev,
          [blobRef.key]: {
            status: "verified",
            sourceUri: result.sourceUri,
            artifactCount: verifiedArtifactCount,
          },
        }));
      } catch (error) {
        const message = error instanceof Error ? error.message : "Blob verification failed";
        const canRequestPin =
          bytesAvailable === false || /usable fetch uri/i.test(message);

        setStates((prev) => ({
          ...prev,
          [blobRef.key]: {
            status: "failed",
            message,
            canRequestPin,
          },
        }));
      }
    },
    [getCredentials, connection.hushdUrl],
  );

  const handleRequestPin = useCallback(
    async (blobRef: DiscoveredSwarmBlobRef) => {
      if (!connection.hushdUrl) {
        return;
      }

      setStates((prev) => ({
        ...prev,
        [blobRef.key]: { status: "pinning" },
      }));

      try {
        const pinCreds = getCredentials();
        const response = await requestSwarmBlobPin(
          {
            hushdUrl: connection.hushdUrl,
            apiKey: pinCreds.apiKey || undefined,
          },
          {
            digest: blobRef.ref.digest,
            requestedBy,
            note: `intel:${intel.id} blob:${blobRef.ref.blobId}`,
          },
        );

        setStates((prev) => ({
          ...prev,
          [blobRef.key]: {
            status: "pinned",
            response,
          },
        }));
      } catch (error) {
        const message = error instanceof Error ? error.message : "Pin request failed";

        setStates((prev) => ({
          ...prev,
          [blobRef.key]: {
            status: "failed",
            message,
            canRequestPin: true,
          },
        }));
      }
    },
    [getCredentials, connection.hushdUrl, intel.id, requestedBy],
  );

  return (
    <div className="mt-4 rounded-lg border border-[#2d3240]/40 bg-[#131721]/25 p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-[11px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Swarm Artifacts
          </p>
          <p className="mt-1 text-[11px] text-[#6f7f9a]">
            {discoveredBlobRefs.length === 0
              ? "No swarm artifacts published for this intel yet."
              : `${discoveredBlobRefs.length} blob ref${discoveredBlobRefs.length === 1 ? "" : "s"} discovered from related swarm findings.`}
          </p>
        </div>
        <p className="text-[10px] font-mono text-[#6f7f9a]">
          {hasFleetConnection ? "Fleet hushd configured" : "Fleet hushd required"}
        </p>
      </div>

      {discoveredBlobRefs.length === 0 ? null : (
        <div className="mt-4 space-y-3">
          {discoveredBlobRefs.map((blobRef) => {
            const state = states[blobRef.key];
            const statusLabel =
              state?.status === "verifying"
                ? "Verifying manifest + artifacts"
                : state?.status === "verified"
                  ? state.artifactCount === 0
                    ? "Manifest verified"
                    : `Manifest + ${state.artifactCount} artifact${state.artifactCount === 1 ? "" : "s"} verified`
                  : state?.status === "pinning"
                    ? "Requesting pin intent"
                    : state?.status === "pinned"
                      ? "Pin intent recorded"
                      : state?.status === "failed"
                        ? "Verification blocked"
                        : "Ready to verify";

            return (
              <div
                key={blobRef.key}
                className="rounded-lg border border-[#2d3240]/40 bg-[#0b0d13]/30 px-3 py-3"
              >
                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <p className="text-[10px] font-mono text-[#ece7dc]">
                      {blobRef.ref.blobId}
                    </p>
                    <p className="mt-1 text-[10px] text-[#6f7f9a]">
                      {blobRef.title} · {blobRef.findingId} · {blobRef.swarmId}
                    </p>
                    <p className="mt-1 text-[10px] font-mono text-[#d4a84b]">
                      {truncateDigest(blobRef.ref.digest)}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-md border border-[#2d3240]/50 bg-[#131721]/60 px-2 py-1 text-[10px] font-mono text-[#ece7dc]">
                      {statusLabel}
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleVerifyBlob(blobRef)}
                      disabled={!hasFleetConnection || state?.status === "verifying" || state?.status === "pinning"}
                      className="rounded-md border border-[#d4a84b]/30 bg-[#d4a84b]/10 px-3 py-1.5 text-[10px] font-mono text-[#d4a84b] transition-colors hover:bg-[#d4a84b]/20 disabled:cursor-not-allowed disabled:border-[#2d3240]/30 disabled:bg-transparent disabled:text-[#6f7f9a]/50"
                    >
                      Verify blob
                    </button>
                    {state?.status === "failed" && state.canRequestPin && (
                      <button
                        type="button"
                        onClick={() => void handleRequestPin(blobRef)}
                        disabled={!hasFleetConnection}
                        className="rounded-md border border-[#5b8def]/30 bg-[#5b8def]/10 px-3 py-1.5 text-[10px] font-mono text-[#5b8def] transition-colors hover:bg-[#5b8def]/20 disabled:cursor-not-allowed disabled:border-[#2d3240]/30 disabled:bg-transparent disabled:text-[#6f7f9a]/50"
                      >
                        Request hushd pin
                      </button>
                    )}
                  </div>
                </div>

                <div className="mt-2 space-y-1 text-[10px] text-[#6f7f9a]">
                  {blobRef.ref.publish?.uri ? (
                    <p className="break-all">{blobRef.ref.publish.uri}</p>
                  ) : (
                    <p>No fetch URI published for this blob ref.</p>
                  )}
                  {state?.status === "verified" && (
                    <>
                      <p className="break-all text-[#3dbf84]">Manifest source · {state.sourceUri}</p>
                      <p className="text-[#3dbf84]">
                        {state.artifactCount === 0
                          ? "Manifest verified only because this blob published no fetchable artifacts."
                          : `Fetched and verified ${state.artifactCount} artifact byte stream${state.artifactCount === 1 ? "" : "s"}.`}
                      </p>
                    </>
                  )}
                  {state?.status === "failed" && (
                    <p className="text-[#c45c5c]">{state.message}</p>
                  )}
                  {state?.status === "pinned" && (
                    <p className="text-[#5b8def]">
                      request {state.response.requestId} · {state.response.status}
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
