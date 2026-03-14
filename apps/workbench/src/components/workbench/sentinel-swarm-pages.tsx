import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { fetchSwarmHubConfig, publishSwarmFinding } from "@/lib/workbench/fleet-client";
import { useSentinels } from "@/lib/workbench/sentinel-store";
import { useFindings } from "@/lib/workbench/finding-store";
import { useIntel } from "@/lib/workbench/intel-store";
import { promoteToIntel, signIntel } from "@/lib/workbench/intel-forge";
import {
  FINDING_ENVELOPE_SCHEMA,
  createHeadAnnouncement,
  type FindingEnvelope,
  type HeadAnnouncement,
  type ProtocolSeverity,
} from "@/lib/workbench/swarm-protocol";
import { useSwarms } from "@/lib/workbench/swarm-store";
import { useSwarmFeed } from "@/lib/workbench/swarm-feed-store";
import { useOperator } from "@/lib/workbench/operator-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import type { OperatorIdentity } from "@/lib/workbench/operator-types";
import type { SentinelMutablePatch } from "@/lib/workbench/sentinel-manager";
import {
  fetchSwarmBlobLookup,
  fetchVerifiedBlobArtifact,
  fetchVerifiedFindingBlob,
  requestSwarmBlobPin,
  type SwarmBlobPinResponse,
} from "@/lib/workbench/swarm-blob-client";
import { FAIL_CLOSED_HUB_TRUST_POLICY } from "@/lib/workbench/swarm-trust-policy";
import { SentinelList } from "./sentinels/sentinel-list";
import { SentinelCreate } from "./sentinels/sentinel-create";
import { SentinelDetail } from "./sentinels/sentinel-detail";
import { FindingsIntelPage } from "./findings/findings-intel-page";
import { FindingDetail } from "./findings/finding-detail";
import { IntelDetail } from "./intel/intel-detail";
import type {
  Intel,
  IntelShareability,
  Sentinel,
} from "@/lib/workbench/sentinel-types";
import type { FindingBlobRef } from "@/lib/workbench/swarm-protocol";

const PROTOCOL_SEVERITY_TAGS: readonly ProtocolSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

function issuerIdFromPublicKey(publicKey: string): string {
  return `aegis:ed25519:${publicKey}`;
}

function inferEnvelopeSeverity(intel: Intel): ProtocolSeverity {
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

function inferSignalCount(intel: Intel): number {
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

function buildFindingEnvelope(
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

function resolvePublisherIdentity(
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

function truncateDigest(digest: string): string {
  if (digest.length <= 23) {
    return digest;
  }

  return `${digest.slice(0, 12)}...${digest.slice(-8)}`;
}

interface DiscoveredSwarmBlobRef {
  key: string;
  swarmId: string;
  findingId: string;
  title: string;
  publishedAt: number;
  ref: FindingBlobRef;
}

type BlobVerificationState =
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

type HubTrustHydrationStatus = "idle" | "pending" | "success" | "error";

function SwarmArtifactsPanel({
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

export function SentinelsPage() {
  const { sentinels } = useSentinels();
  return <SentinelList sentinels={sentinels} />;
}

export function SentinelCreatePage() {
  const { createSentinel } = useSentinels();
  const navigate = useNavigate();
  const handleCreated = useCallback(() => {
    navigate("/sentinels");
  }, [navigate]);
  return <SentinelCreate onCreated={handleCreated} createFn={createSentinel} />;
}

export function SentinelDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { sentinels, updateSentinel } = useSentinels();
  const sentinel = sentinels.find((s) => s.id === id);

  const handleUpdate = useCallback(
    (updated: Sentinel) => {
      const patch: SentinelMutablePatch = {
        name: updated.name,
        goals: updated.goals,
        schedule: updated.schedule,
        status: updated.status,
        policy: updated.policy,
        mode: updated.mode,
        runtime: updated.runtime,
        fleetAgentId: updated.fleetAgentId,
      };
      updateSentinel(updated.id, patch);
    },
    [updateSentinel],
  );

  if (!sentinel) {
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
        Sentinel not found
      </div>
    );
  }

  return (
    <SentinelDetail
      sentinel={sentinel}
      onUpdate={handleUpdate}
    />
  );
}

export function FindingsPage() {
  return <FindingsIntelPage />;
}

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const {
    findings,
    confirm,
    dismiss,
    markFalsePositive,
    promote,
    addAnnotation,
  } = useFindings();
  const { upsertLocalIntel } = useIntel();
  const navigate = useNavigate();
  const finding = findings.find((f) => f.id === id);

  const promoteFinding = useCallback(
    (findingId: string) => {
      const targetFinding = findings.find((entry) => entry.id === findingId);
      if (!targetFinding) return;

      const intel = promoteToIntel(targetFinding, [], {
        authorFingerprint: targetFinding.createdBy || "operator",
        shareability: "private",
      });

      upsertLocalIntel(intel);
      promote(findingId, "operator", intel.id);
    },
    [findings, promote, upsertLocalIntel],
  );

  if (!finding) {
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
        Finding not found
      </div>
    );
  }

  return (
    <FindingDetail
      finding={finding}
      onConfirm={(fid: string) => confirm(fid, "operator")}
      onDismiss={(fid: string) => dismiss(fid, "operator")}
      onPromote={promoteFinding}
      onMarkFalsePositive={(fid: string) =>
        markFalsePositive(fid, "operator")
      }
      onAddAnnotation={(fid: string, text: string) =>
        addAnnotation(fid, {
          id: `ann_${Date.now()}`,
          text,
          createdBy: "operator",
          createdAt: new Date().toISOString(),
        })
      }
      onBack={() => navigate("/findings")}
    />
  );
}

export function IntelDetailPage() {
  const { id } = useParams<{ id: string }>();
  const {
    localIntel,
    upsertLocalIntel,
    ingestSwarmIntel,
    getIntelById,
    getIntelSource,
    getSwarmIntelRecords,
  } = useIntel();
  const { swarms, activeSwarm, addIntelRef } = useSwarms();
  const {
    ingestFindingEnvelope,
    ingestHeadAnnouncement,
    getLatestFindingSeq,
    setTrustPolicy,
  } = useSwarmFeed();
  const { connection, getAuthenticatedConnection } = useFleetConnection();
  const { currentOperator, getSecretKey } = useOperator();
  const navigate = useNavigate();
  const [hubTrustHydrationByConnection, setHubTrustHydrationByConnection] = useState<
    Record<string, HubTrustHydrationStatus>
  >({});
  const [isPublishing, setIsPublishing] = useState(false);
  const [publishError, setPublishError] = useState<string | null>(null);
  const intel = id ? getIntelById(id) : undefined;
  const source = id ? getIntelSource(id) : undefined;
  const swarmRecords = id ? getSwarmIntelRecords(id) : [];
  const targetSwarm = activeSwarm ?? swarms[0];
  const editableLocalIntel = localIntel.find((entry) => entry.id === id);
  const hubTrustConnectionKey = useMemo(() => {
    if (!targetSwarm?.id || !connection.hushdUrl) {
      return null;
    }

    return `${targetSwarm.id}:${connection.hushdUrl}`;
  }, [connection.hushdUrl, targetSwarm?.id]);
  const hubTrustHydrationStatus = hubTrustConnectionKey
    ? hubTrustHydrationByConnection[hubTrustConnectionKey] ?? "idle"
    : "success";
  const canShareToSwarm =
    Boolean(targetSwarm) &&
    (Boolean(intel?.signerPublicKey && intel.signature) || currentOperator !== null) &&
    hubTrustHydrationStatus === "success";

  useEffect(() => {
    if (!targetSwarm?.id || !hubTrustConnectionKey) {
      return;
    }

    let cancelled = false;
    setHubTrustHydrationByConnection((current) =>
      current[hubTrustConnectionKey] === "pending"
        ? current
        : {
            ...current,
            [hubTrustConnectionKey]: "pending",
          },
    );
    setTrustPolicy(targetSwarm.id, FAIL_CLOSED_HUB_TRUST_POLICY);

    void (async () => {
      try {
        const hubConfig = await fetchSwarmHubConfig(getAuthenticatedConnection());
        if (cancelled) {
          return;
        }
        setTrustPolicy(targetSwarm.id, hubConfig.trustPolicy);
        setHubTrustHydrationByConnection((current) => ({
          ...current,
          [hubTrustConnectionKey]: "success",
        }));
      } catch (error) {
        if (cancelled) {
          return;
        }
        setTrustPolicy(targetSwarm.id, FAIL_CLOSED_HUB_TRUST_POLICY);
        setHubTrustHydrationByConnection((current) => ({
          ...current,
          [hubTrustConnectionKey]: "error",
        }));
        console.warn("[sentinel-swarm-pages] failed to hydrate swarm trust policy:", error);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    getAuthenticatedConnection,
    connection.hushdUrl,
    hubTrustConnectionKey,
    setTrustPolicy,
    targetSwarm?.id,
  ]);

  const handleChangeShareability = useCallback(
    (targetIntel: Intel, shareability: IntelShareability) => {
      if (!editableLocalIntel) {
        return;
      }

      upsertLocalIntel({
        ...targetIntel,
        shareability,
      });
    },
    [editableLocalIntel, upsertLocalIntel],
  );

  const handleShareToSwarm = useCallback(
    async (targetIntel: Intel) => {
      if (!targetSwarm || isPublishing) {
        return;
      }
      if (hubTrustConnectionKey !== null && hubTrustHydrationStatus !== "success") {
        setTrustPolicy(targetSwarm.id, FAIL_CLOSED_HUB_TRUST_POLICY);
        return;
      }

      setIsPublishing(true);
      setPublishError(null);

      try {
        let nextIntel: Intel =
          targetIntel.shareability === "private"
            ? { ...targetIntel, shareability: "swarm" }
            : targetIntel;

        if (!nextIntel.signerPublicKey || !nextIntel.signature) {
          if (!currentOperator) {
            return;
          }

          const secretKey = await getSecretKey();
          if (!secretKey) {
            return;
          }

          nextIntel = await signIntel(
            {
              ...nextIntel,
              author: currentOperator.fingerprint,
            },
            secretKey,
            currentOperator.publicKey,
          );
        }

        const publishedAt = Date.now();
        const publisherIdentity = resolvePublisherIdentity(nextIntel, currentOperator);
        if (!publisherIdentity) {
          return;
        }
        const nextFeedSeq =
          (getLatestFindingSeq(targetSwarm.id, publisherIdentity.issuerId) ?? 0) + 1;
        const envelope = buildFindingEnvelope(
          nextIntel,
          publishedAt,
          nextFeedSeq,
          publisherIdentity.issuerId,
        );
        let headAnnouncement: HeadAnnouncement;
        if (connection.hushdUrl) {
          try {
            const publishResponse = await publishSwarmFinding(getAuthenticatedConnection(), envelope);
            headAnnouncement = publishResponse.headAnnouncement;
          } catch (error) {
            const message =
              error instanceof Error ? error.message : "Unknown publish error";
            console.warn("[sentinel-swarm-pages] failed to publish finding to hushd:", error);
            setPublishError(`Publish failed: ${message}`);
            return;
          }
        } else {
          headAnnouncement = await createHeadAnnouncement({
            factId: `head:${targetSwarm.id}:${nextIntel.id}:${nextFeedSeq}`,
            entryCount: nextFeedSeq,
            head: envelope,
            announcedAt: publishedAt,
          });
        }

        const findingIngestResult = await ingestFindingEnvelope({
          swarmId: targetSwarm.id,
          envelope,
          receivedAt: publishedAt,
        });
        if (!findingIngestResult.accepted) {
          setPublishError(
            `Local ingest rejected: ${findingIngestResult.reason ?? "unknown reason"}`,
          );
          return;
        }
        if (editableLocalIntel) {
          upsertLocalIntel(nextIntel);
        }
        addIntelRef(targetSwarm.id, {
          intelId: nextIntel.id,
          publishedBy: publisherIdentity.fingerprint,
          publishedAt,
          version: nextIntel.version,
        });
        ingestSwarmIntel({
          swarmId: targetSwarm.id,
          intel: nextIntel,
          receivedAt: publishedAt,
          publishedBy: publisherIdentity.fingerprint,
        });
        ingestHeadAnnouncement({
          swarmId: targetSwarm.id,
          lane: "findings",
          announcement: headAnnouncement,
          receivedAt: publishedAt,
        });
      } finally {
        setIsPublishing(false);
      }
    },
    [
      addIntelRef,
      connection,
      currentOperator,
      editableLocalIntel,
      getLatestFindingSeq,
      getSecretKey,
      ingestFindingEnvelope,
      ingestHeadAnnouncement,
      ingestSwarmIntel,
      isPublishing,
      hubTrustHydrationStatus,
      hubTrustConnectionKey,
      setTrustPolicy,
      targetSwarm,
      upsertLocalIntel,
    ],
  );

  if (!id || !intel) {
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
        Intel not found
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-6">
      <IntelDetail
        intel={intel}
        onBack={() => navigate("/findings?tab=intel")}
        onNavigateToFinding={(findingId: string) => navigate(`/findings/${findingId}`)}
        onChangeShareability={editableLocalIntel ? handleChangeShareability : undefined}
        onShareToSwarm={canShareToSwarm && !isPublishing ? handleShareToSwarm : undefined}
        shareStatus={
          isPublishing
            ? "publishing"
            : publishError
              ? "error"
              : undefined
        }
        shareStatusMessage={publishError ?? undefined}
      />

      {swarmRecords.length > 0 && (
        <div className="mx-auto max-w-6xl px-6">
          <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-[11px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                  Swarm Provenance
                </p>
                <p className="mt-1 text-[11px] text-[#6f7f9a]">
                  {source ?? "unknown"} source with {swarmRecords.length} recorded swarm
                  {swarmRecords.length === 1 ? "" : "s"}.
                </p>
              </div>
              {targetSwarm && (
                <p className="text-[10px] font-mono text-[#d4a84b]">
                  Share target: {targetSwarm.name}
                </p>
              )}
            </div>

            <div className="mt-4 space-y-2">
              {swarmRecords.map((record) => (
                <div
                  key={`${record.swarmId}:${record.intel.id}`}
                  className="rounded-lg border border-[#2d3240]/40 bg-[#131721]/40 px-3 py-2"
                >
                  <p className="text-[10px] font-mono text-[#ece7dc]">
                    {record.swarmId}
                    {record.publishedBy ? ` · ${record.publishedBy}` : ""}
                  </p>
                  <p className="mt-1 text-[10px] text-[#6f7f9a]">
                    Received {new Date(record.receivedAt).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>

            <SwarmArtifactsPanel
              intel={intel}
              swarmIds={swarmRecords.map((record) => record.swarmId)}
              requestedBy={currentOperator?.fingerprint ?? intel.author}
            />
          </div>
        </div>
      )}
    </div>
  );
}
