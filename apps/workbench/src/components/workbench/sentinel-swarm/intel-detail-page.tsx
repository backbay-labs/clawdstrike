import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { fetchSwarmHubConfig, publishSwarmFinding } from "@/features/fleet/fleet-client";
import { useIntel } from "@/features/findings/stores/intel-store";
import { signIntel } from "@/lib/workbench/intel-forge";
import {
  createHeadAnnouncement,
  type HeadAnnouncement,
} from "@/features/swarm/swarm-protocol";
import { useSwarms } from "@/features/swarm/stores/swarm-store";
import { useSwarmFeed } from "@/features/swarm/stores/swarm-feed-store";
import { useOperator } from "@/features/operator/stores/operator-store";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { FAIL_CLOSED_HUB_TRUST_POLICY } from "@/features/swarm/swarm-trust-policy";
import type {
  Intel,
  IntelShareability,
} from "@/lib/workbench/sentinel-types";
import { IntelDetail } from "../intel/intel-detail";
import {
  buildFindingEnvelope,
  resolvePublisherIdentity,
  SwarmArtifactsPanel,
  type HubTrustHydrationStatus,
} from "./_shared";
import { logger } from "@/lib/logger";

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
        logger.warn("[sentinel-swarm-pages] failed to hydrate swarm trust policy:", error);
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
            logger.warn("[sentinel-swarm-pages] failed to publish finding to hushd:", error);
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

export default IntelDetailPage;
