import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { IntelDetailPage } from "../../sentinel-swarm-pages";
import { IntelProvider, useIntel } from "@/lib/workbench/intel-store";
import { SwarmFeedProvider, useSwarmFeed } from "@/lib/workbench/swarm-feed-store";
import { SwarmProvider, createSwarm } from "@/lib/workbench/swarm-store";
import { OperatorProvider } from "@/lib/workbench/operator-store";
import { createOperatorIdentity } from "@/lib/workbench/operator-crypto";
import { signIntel } from "@/lib/workbench/intel-forge";
import { FleetConnectionProvider } from "@/lib/workbench/use-fleet-connection";
import { hashRawBytesSha256 } from "@/lib/workbench/swarm-blob-client";
import type { Intel } from "@/lib/workbench/sentinel-types";
import { useSwarms } from "@/lib/workbench/swarm-store";
import type { OperatorIdentity } from "@/lib/workbench/operator-types";
import { FAIL_CLOSED_HUB_TRUST_POLICY } from "@/lib/workbench/swarm-trust-policy";
import {
  FINDING_BLOB_SCHEMA,
  FINDING_ENVELOPE_SCHEMA,
  HUB_CONFIG_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
  createHeadAnnouncement,
  hashProtocolPayload,
  type FindingBlob,
  type FindingBlobRef,
  type FindingEnvelope,
  type HubConfig,
  type RevocationEnvelope,
} from "@/lib/workbench/swarm-protocol";

const INTEL_STORAGE_KEY = "clawdstrike_workbench_intel";
const SWARM_STORAGE_KEY = "clawdstrike_workbench_swarms";
const SWARM_FEED_STORAGE_KEY = "clawdstrike_workbench_swarm_feed";
const OPERATOR_STORAGE_KEY = "clawdstrike_workbench_operator";
const HUSHD_URL_STORAGE_KEY = "clawdstrike_hushd_url";
const CONTROL_API_URL_STORAGE_KEY = "clawdstrike_control_api_url";
const STRICT_HUB_CONFIG: HubConfig = {
  schema: HUB_CONFIG_SCHEMA,
  hubId: "hub_strict_01",
  displayName: "Strict Hub",
  updatedAt: 1_715_000_000_000,
  bootstrapPeers: [],
  relayPeers: [],
  replay: {
    maxEntriesPerSync: 100,
    checkpointInterval: 25,
    retentionMs: 86_400_000,
  },
  blobs: {
    maxInlineBytes: 4096,
    requireDigest: true,
    providers: [],
  },
  trustPolicy: {
    trustedIssuers: [],
    blockedIssuers: [],
    requireAttestation: true,
    requireWitnessProofs: false,
    allowedSchemas: [FINDING_ENVELOPE_SCHEMA],
  },
};
const PERMISSIVE_HUB_CONFIG: HubConfig = {
  ...STRICT_HUB_CONFIG,
  hubId: "hub_permissive_01",
  displayName: "Permissive Hub",
  trustPolicy: {
    ...STRICT_HUB_CONFIG.trustPolicy,
    requireAttestation: false,
  },
};

function makeIntel(overrides: Partial<Intel> = {}): Intel {
  return {
    id: "int_share_01",
    type: "advisory",
    title: "Lateral movement advisory",
    description: "Credential replay behavior was confirmed across one session chain.",
    content: {
      kind: "advisory",
      narrative: "Escalate and rotate the impacted credentials.",
      recommendations: ["Rotate credentials", "Review session lineage"],
    },
    derivedFrom: ["fnd_share_01"],
    confidence: 0.94,
    tags: ["high", "credential", "replay"],
    mitre: [
      {
        techniqueId: "T1078",
        techniqueName: "Valid Accounts",
        tactic: "Defense Evasion",
      },
    ],
    shareability: "private",
    signature: "",
    signerPublicKey: "",
    receipt: {
      id: "rcpt_share_01",
      timestamp: new Date(1_715_000_000_000).toISOString(),
      verdict: "allow",
      guard: "intel_forge",
      policyName: "intel_promotion",
      action: {
        type: "file_access",
        target: "intel:int_share_01",
      },
      evidence: {
        content_hash: "pending",
        signal_count: 4,
      },
      signature: "",
      publicKey: "",
      valid: false,
    },
    author: "feedfacefeedface",
    createdAt: 1_715_000_000_000,
    version: 1,
    ...overrides,
  };
}

function Snapshot() {
  const { getSwarmIntelRecords, getIntelById } = useIntel();
  const { swarms, activeSwarm } = useSwarms();
  const { findingEnvelopeRecords, getTrustPolicy, headAnnouncementRecords } = useSwarmFeed();

  return (
    <pre data-testid="snapshot">
      {JSON.stringify({
        activeSwarmId: activeSwarm?.id ?? null,
        sharedIntelCount: swarms[0]?.sharedIntel.length ?? 0,
        intelShareability: getIntelById("int_share_01")?.shareability ?? null,
        swarmRecordCount: getSwarmIntelRecords("int_share_01")?.length ?? 0,
        findingEnvelopeCount: findingEnvelopeRecords.length,
        headAnnouncementCount: headAnnouncementRecords.length,
        trustPolicy: activeSwarm ? getTrustPolicy(activeSwarm.id) : null,
        firstFindingEnvelope: findingEnvelopeRecords[0]
          ? {
              swarmId: findingEnvelopeRecords[0].swarmId,
              findingId: findingEnvelopeRecords[0].envelope.findingId,
              title: findingEnvelopeRecords[0].envelope.title,
              issuerId: findingEnvelopeRecords[0].envelope.issuerId,
              feedId: findingEnvelopeRecords[0].envelope.feedId,
            }
          : null,
        firstHeadAnnouncement: headAnnouncementRecords[0]
          ? {
              issuerId: headAnnouncementRecords[0].announcement.issuerId,
              feedId: headAnnouncementRecords[0].announcement.feedId,
            }
          : null,
      })}
    </pre>
  );
}

function renderIntelDetailPage(intelId = "int_share_01") {
  return render(
    <MemoryRouter initialEntries={[`/intel/${intelId}`]}>
      <OperatorProvider>
        <FleetConnectionProvider>
          <IntelProvider>
            <SwarmFeedProvider>
              <SwarmProvider>
                <Snapshot />
                <Routes>
                  <Route path="/intel/:id" element={<IntelDetailPage />} />
                </Routes>
              </SwarmProvider>
            </SwarmFeedProvider>
          </IntelProvider>
        </FleetConnectionProvider>
      </OperatorProvider>
    </MemoryRouter>,
  );
}

function readSnapshot() {
  return JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}");
}

function expectNoPersistedSwarmShareState() {
  expect(JSON.parse(localStorage.getItem(INTEL_STORAGE_KEY) ?? "{}").swarmIntel ?? []).toHaveLength(0);
  expect(JSON.parse(localStorage.getItem(SWARM_STORAGE_KEY) ?? "{}").swarms[0].sharedIntel ?? []).toHaveLength(
    0,
  );
  expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").findingEnvelopes ?? []).toHaveLength(0);
  expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").headAnnouncements ?? []).toHaveLength(0);
}

async function seedIntelDetailPage({
  signerIntel,
  currentOperator,
}: {
  signerIntel?: Intel;
  currentOperator?: OperatorIdentity;
} = {}) {
  const signer = await createOperatorIdentity("Signer Alpha");
  const signedIntel = await signIntel(
    signerIntel ??
      makeIntel({
        author: signer.identity.fingerprint,
      }),
    signer.secretKeyHex,
    signer.identity.publicKey,
  );
  const swarm = createSwarm({
    name: "Trusted Swarm",
    type: "trusted",
  });

  localStorage.setItem(
    INTEL_STORAGE_KEY,
    JSON.stringify({
      localIntel: [signedIntel],
      swarmIntel: [],
      activeIntelId: signedIntel.id,
    }),
  );
  localStorage.setItem(
    SWARM_STORAGE_KEY,
    JSON.stringify({
      swarms: [swarm],
      activeSwarmId: swarm.id,
      invitationTracking: {},
    }),
  );
  if (currentOperator) {
    localStorage.setItem(
      OPERATOR_STORAGE_KEY,
      JSON.stringify(currentOperator),
    );
  }

  return {
    signedIntel,
    signerIdentity: signer.identity,
    swarm,
  };
}

function persistSwarmIntelState(intel: Intel, swarmId: string) {
  localStorage.setItem(
    INTEL_STORAGE_KEY,
    JSON.stringify({
      localIntel: [intel],
      swarmIntel: [
        {
          swarmId,
          intel,
          receivedAt: 1_715_000_001_000,
          publishedBy: "operator",
        },
      ],
      activeIntelId: intel.id,
    }),
  );
}

function makeSwarmFindingEnvelopeRecord({
  swarmId,
  findingId,
  blobRefs,
  title = "Lateral movement advisory",
  summary = "Credential replay behavior was confirmed across one session chain.",
  feedSeq = 7,
  publishedAt = 1_715_000_001_200,
  relatedFindingIds,
}: {
  swarmId: string;
  findingId: string;
  blobRefs: FindingBlobRef[];
  title?: string;
  summary?: string;
  feedSeq?: number;
  publishedAt?: number;
  relatedFindingIds?: string[];
}) {
  return {
    swarmId,
    receivedAt: publishedAt + 300,
    envelope: {
      schema: FINDING_ENVELOPE_SCHEMA,
      findingId,
      issuerId: `aegis:ed25519:${"c".repeat(64)}`,
      feedId: `aegis:ed25519:${"c".repeat(64)}`,
      feedSeq,
      publishedAt,
      title,
      summary,
      severity: "high",
      confidence: 0.94,
      status: "promoted",
      signalCount: 1,
      tags: ["high", "credential", "replay"],
      blobRefs,
      ...(relatedFindingIds ? { relatedFindingIds } : {}),
    },
  };
}

function persistSwarmFeedRecords(
  records: ReturnType<typeof makeSwarmFindingEnvelopeRecord>[],
  revocations: ReturnType<typeof makeSwarmRevocationEnvelopeRecord>[] = [],
) {
  localStorage.setItem(
    SWARM_FEED_STORAGE_KEY,
    JSON.stringify({
      findingEnvelopes: records,
      headAnnouncements: [],
      revocationEnvelopes: revocations,
    }),
  );
}

function makeSwarmRevocationEnvelopeRecord({
  swarmId,
  findingId,
  feedId = `aegis:ed25519:${"c".repeat(64)}`,
  action = "revoke",
  replacementFindingId,
  feedSeq = 8,
  issuedAt = 1_715_000_001_400,
}: {
  swarmId: string;
  findingId: string;
  feedId?: string;
  action?: RevocationEnvelope["action"];
  replacementFindingId?: string;
  feedSeq?: number;
  issuedAt?: number;
}) {
  return {
    swarmId,
    receivedAt: issuedAt + 200,
    envelope: {
      schema: REVOCATION_ENVELOPE_SCHEMA,
      revocationId: `rev_${findingId}_${action}`,
      issuerId: `aegis:ed25519:${"c".repeat(64)}`,
      feedId,
      feedSeq,
      issuedAt,
      action,
      target: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: findingId,
      },
      ...(action === "supersede" && replacementFindingId
        ? {
            replacement: {
              schema: FINDING_ENVELOPE_SCHEMA,
              id: replacementFindingId,
            },
          }
        : {}),
      reason:
        action === "supersede"
          ? "Superseded by a replacement finding."
          : "Revoked after analyst review.",
    } satisfies RevocationEnvelope,
  };
}

function persistSwarmFeedState({
  swarmId,
  findingId,
  blobRefs,
  title = "Lateral movement advisory",
  summary = "Credential replay behavior was confirmed across one session chain.",
}: {
  swarmId: string;
  findingId: string;
  blobRefs: FindingBlobRef[];
  title?: string;
  summary?: string;
}) {
  persistSwarmFeedRecords([
    makeSwarmFindingEnvelopeRecord({
      swarmId,
      findingId,
      blobRefs,
      title,
      summary,
    }),
  ]);
}

function seedSavedFleetConnection() {
  localStorage.setItem(HUSHD_URL_STORAGE_KEY, "http://localhost:9876");
  localStorage.setItem(CONTROL_API_URL_STORAGE_KEY, "http://localhost:9877");
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

function bytesResponse(bytes: Uint8Array, init?: ResponseInit): Response {
  const stableBytes = Uint8Array.from(bytes);
  return new Response(stableBytes.buffer as ArrayBuffer, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream" },
    ...init,
  });
}

async function makeBlobFixture(): Promise<{
  blob: FindingBlob;
  ref: FindingBlobRef;
  artifactBytesByUri: Record<string, Uint8Array>;
}> {
  const primaryArtifactBytes = new TextEncoder().encode(
    JSON.stringify({
      findingId: "fnd_share_01",
      evidence: ["session replay", "credential handoff"],
    }),
  );
  const transcriptArtifactBytes = new TextEncoder().encode(
    "operator=signer-alpha\nfinding=fnd_share_01\naction=rotate-credentials\n",
  );
  const primaryArtifactUri = "https://blob.example/artifacts/artifact_01J7INTEL.json";
  const transcriptArtifactUri = "https://blob.example/artifacts/artifact_01J7TRANSCRIPT.txt";
  const blob: FindingBlob = {
    schema: FINDING_BLOB_SCHEMA,
    blobId: "blob_01J7INTEL",
    findingId: "fnd_share_01",
    issuerId: `aegis:ed25519:${"b".repeat(64)}`,
    createdAt: 1_715_000_000_100,
    manifest: {
      bundleType: "evidence",
      artifactCount: 2,
      summary: {
        hasTranscript: true,
      },
    },
    artifacts: [
      {
        artifactId: "artifact_01J7INTEL",
        kind: "json",
        mediaType: "application/json",
        digest: await hashRawBytesSha256(primaryArtifactBytes),
        byteLength: primaryArtifactBytes.byteLength,
        name: "artifact.json",
        publish: {
          uri: primaryArtifactUri,
          publishedAt: 1_715_000_000_160,
        },
      },
      {
        artifactId: "artifact_01J7TRANSCRIPT",
        kind: "transcript",
        mediaType: "text/plain",
        digest: await hashRawBytesSha256(transcriptArtifactBytes),
        byteLength: transcriptArtifactBytes.byteLength,
        name: "transcript.txt",
        publish: {
          uri: transcriptArtifactUri,
          publishedAt: 1_715_000_000_170,
        },
      },
    ],
    publish: {
      uri: "https://blob.example/blobs/blob_01J7INTEL.json",
      publishedAt: 1_715_000_000_150,
    },
  };
  const blobBody = new TextEncoder().encode(JSON.stringify(blob));
  const ref: FindingBlobRef = {
    blobId: blob.blobId,
    digest: await hashProtocolPayload(blob),
    mediaType: "application/json",
    byteLength: blobBody.byteLength,
    publish: {
      uri: blob.publish?.uri,
      publishedAt: blob.publish?.publishedAt,
    },
  };

  return {
    blob,
    ref,
    artifactBytesByUri: {
      [primaryArtifactUri]: primaryArtifactBytes,
      [transcriptArtifactUri]: transcriptArtifactBytes,
    },
  };
}

function installFleetFetchMock({
  blob,
  ref,
  hubConfig,
  hubConfigPromise,
  hubConfigError,
  artifactBytesByUri = {},
  bytesAvailable = true,
  includeBlobUri = true,
  pinRecorded = false,
  publishFindingResponse,
  onPublishFinding,
}: {
  blob?: FindingBlob;
  ref?: FindingBlobRef;
  hubConfig?: HubConfig;
  hubConfigPromise?: Promise<HubConfig>;
  hubConfigError?: Error;
  artifactBytesByUri?: Record<string, Uint8Array>;
  bytesAvailable?: boolean;
  includeBlobUri?: boolean;
  pinRecorded?: boolean;
  publishFindingResponse?: {
    body: unknown;
    init?: ResponseInit;
  };
  onPublishFinding?: (request: {
    url: string;
    body: FindingEnvelope;
  }) => void;
}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);

    if (url === "/_proxy/hushd/health") {
      return jsonResponse({ status: "ok" });
    }

    if (url === "/_proxy/hushd/api/v1/agents/status?include_stale=true") {
      return jsonResponse({
        generated_at: new Date(1_715_000_000_000).toISOString(),
        stale_after_secs: 90,
        endpoints: [],
        runtimes: [],
      });
    }

    if (url === "/_proxy/hushd/api/v1/policy") {
      return jsonResponse({ yaml: "", name: "default" });
    }

    if (url === "/_proxy/hushd/api/v1/swarm/hub/config") {
      if (hubConfigPromise) {
        return jsonResponse(await hubConfigPromise);
      }
      if (hubConfigError) {
        throw hubConfigError;
      }
      return jsonResponse(hubConfig ?? PERMISSIVE_HUB_CONFIG);
    }

    const findingPublishMatch = url.match(/^\/_proxy\/hushd\/api\/v1\/swarm\/feeds\/(.+)\/findings$/);
    if (findingPublishMatch) {
      const publishedFinding = JSON.parse(String(init?.body ?? "{}")) as FindingEnvelope;
      onPublishFinding?.({
        url,
        body: publishedFinding,
      });
      if (publishFindingResponse) {
        return jsonResponse(publishFindingResponse.body, publishFindingResponse.init);
      }
      return jsonResponse({
        accepted: true,
        idempotent: false,
        feedId: publishedFinding.feedId,
        issuerId: publishedFinding.issuerId,
        feedSeq: publishedFinding.feedSeq,
        findingId: publishedFinding.findingId,
        headAnnouncement: await createHeadAnnouncement({
          factId: `head:${publishedFinding.feedId}:${publishedFinding.findingId}:${publishedFinding.feedSeq}`,
          entryCount: publishedFinding.feedSeq,
          head: publishedFinding,
          announcedAt: publishedFinding.publishedAt,
        }),
      });
    }

    if (ref && url === `/_proxy/hushd/api/v1/swarm/blobs/${ref.digest}`) {
      return jsonResponse({
        schema: "clawdstrike.swarm.blob_lookup.v1",
        digest: ref.digest,
        bytesAvailable,
        refs: [
          {
            blobId: ref.blobId,
            feedId: `aegis:ed25519:${"c".repeat(64)}`,
            issuerId: `aegis:ed25519:${"c".repeat(64)}`,
            feedSeq: 7,
            findingId: "fnd_share_01",
            mediaType: ref.mediaType,
            byteLength: ref.byteLength,
            ...(includeBlobUri ? { publish: ref.publish } : {}),
          },
        ],
      });
    }

    if (url === "/_proxy/hushd/api/v1/swarm/blobs/pin" && ref) {
      return jsonResponse(
        {
          accepted: true,
          recorded: pinRecorded,
          requestId: "pinreq_01J7INTEL",
          digest: ref.digest,
          status: pinRecorded ? "recorded" : "accepted",
          recordedAt: 1_715_000_000_400,
        },
        { status: 202 },
      );
    }

    if (blob && url === ref?.publish?.uri) {
      return jsonResponse(blob);
    }

    const artifactBytes = artifactBytesByUri[url];
    if (artifactBytes) {
      return bytesResponse(artifactBytes);
    }

    throw new Error(`Unhandled fetch in test: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
  sessionStorage.clear();
});

describe("IntelDetailPage", () => {
  it("shares intel through the real page path and restores durable swarm state after reload", async () => {
    await seedIntelDetailPage();
    const view = renderIntelDetailPage();

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));
    fireEvent.click(screen.getByRole("button", { name: "Share to Swarm" }));

    await waitFor(() => {
      expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
        sharedIntelCount: 1,
        intelShareability: "swarm",
        swarmRecordCount: 1,
        findingEnvelopeCount: 1,
        headAnnouncementCount: 1,
        firstFindingEnvelope: {
          findingId: "fnd_share_01",
          title: "Lateral movement advisory",
        },
      });
    });

    await waitFor(() => {
      expect(JSON.parse(localStorage.getItem(INTEL_STORAGE_KEY) ?? "{}").swarmIntel).toHaveLength(1);
      expect(JSON.parse(localStorage.getItem(SWARM_STORAGE_KEY) ?? "{}").swarms[0].sharedIntel).toHaveLength(1);
      expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").findingEnvelopes).toHaveLength(1);
      expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").headAnnouncements).toHaveLength(1);
    });

    await waitFor(() => {
      expect(JSON.parse(localStorage.getItem(INTEL_STORAGE_KEY) ?? "{}").localIntel[0].shareability).toBe(
        "swarm",
      );
    });

    view.unmount();

    renderIntelDetailPage();

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      sharedIntelCount: 1,
      intelShareability: "swarm",
      swarmRecordCount: 1,
      findingEnvelopeCount: 1,
      headAnnouncementCount: 1,
    });
  });

  it("publishes to the hushd swarm route before persisting local durable state when a saved fleet connection exists", async () => {
    const { signedIntel } = await seedIntelDetailPage();
    seedSavedFleetConnection();
    const publishRequests: Array<{ url: string; body: FindingEnvelope }> = [];
    installFleetFetchMock({
      onPublishFinding: (request) => {
        publishRequests.push(request);
      },
    });

    renderIntelDetailPage(signedIntel.id);

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));

    await waitFor(() => {
      expect((screen.getByRole("button", { name: "Share to Swarm" }) as HTMLButtonElement).disabled).toBe(
        false,
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Share to Swarm" }));

    const expectedIssuerId = `aegis:ed25519:${signedIntel.signerPublicKey}`;
    await waitFor(() => {
      expect(readSnapshot()).toMatchObject({
        sharedIntelCount: 1,
        swarmRecordCount: 1,
        findingEnvelopeCount: 1,
        headAnnouncementCount: 1,
        firstFindingEnvelope: {
          issuerId: expectedIssuerId,
          feedId: expectedIssuerId,
          findingId: signedIntel.derivedFrom[0] ?? signedIntel.id,
        },
        firstHeadAnnouncement: {
          issuerId: expectedIssuerId,
          feedId: expectedIssuerId,
        },
      });
    });

    await waitFor(() => {
      expect(publishRequests).toHaveLength(1);
    });

    expect(publishRequests[0]).toMatchObject({
      url: `/_proxy/hushd/api/v1/swarm/feeds/${encodeURIComponent(expectedIssuerId)}/findings`,
      body: {
        findingId: signedIntel.derivedFrom[0] ?? signedIntel.id,
        feedId: expectedIssuerId,
        issuerId: expectedIssuerId,
      },
    });

    await waitFor(() => {
      expect(JSON.parse(localStorage.getItem(INTEL_STORAGE_KEY) ?? "{}").swarmIntel ?? []).toHaveLength(1);
    });
    expect(JSON.parse(localStorage.getItem(SWARM_STORAGE_KEY) ?? "{}").swarms[0].sharedIntel ?? []).toHaveLength(
      1,
    );
    expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").findingEnvelopes ?? []).toHaveLength(1);
    expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").headAnnouncements ?? []).toHaveLength(1);
  });

  it("fails closed when hushd finding publish returns accepted false", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { signedIntel } = await seedIntelDetailPage();
    seedSavedFleetConnection();
    const expectedIssuerId = `aegis:ed25519:${signedIntel.signerPublicKey}`;
    const publishRejectedHead = await createHeadAnnouncement({
      factId: `head:test:${expectedIssuerId}:${signedIntel.derivedFrom[0] ?? signedIntel.id}:1`,
      entryCount: 1,
      head: {
        schema: FINDING_ENVELOPE_SCHEMA,
        findingId: signedIntel.derivedFrom[0] ?? signedIntel.id,
        issuerId: expectedIssuerId,
        feedId: expectedIssuerId,
        feedSeq: 1,
        publishedAt: 1_715_000_000_000,
        title: signedIntel.title,
        summary: signedIntel.description,
        severity: "high",
        confidence: signedIntel.confidence,
        status: "promoted",
        signalCount: 4,
        tags: signedIntel.tags,
        blobRefs: [],
      },
      announcedAt: 1_715_000_000_000,
    });
    const publishRequests: Array<{ url: string; body: FindingEnvelope }> = [];
    installFleetFetchMock({
      publishFindingResponse: {
        body: {
          accepted: false,
          idempotent: false,
          feedId: expectedIssuerId,
          issuerId: expectedIssuerId,
          feedSeq: 1,
          findingId: signedIntel.derivedFrom[0] ?? signedIntel.id,
          headAnnouncement: publishRejectedHead,
        },
      },
      onPublishFinding: (request) => {
        publishRequests.push(request);
      },
    });

    renderIntelDetailPage(signedIntel.id);

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));

    await waitFor(() => {
      expect((screen.getByRole("button", { name: "Share to Swarm" }) as HTMLButtonElement).disabled).toBe(
        false,
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Share to Swarm" }));

    await waitFor(() => {
      expect(publishRequests).toHaveLength(1);
    });

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 650));
    });

    expect(readSnapshot()).toMatchObject({
      sharedIntelCount: 0,
      swarmRecordCount: 0,
      findingEnvelopeCount: 0,
      headAnnouncementCount: 0,
    });
    expectNoPersistedSwarmShareState();
    expect(warnSpy).toHaveBeenCalled();
  });

  it("hydrates a strict hub trust policy through the live route and blocks unsigned share persistence", async () => {
    const { swarm } = await seedIntelDetailPage();
    seedSavedFleetConnection();
    const fetchMock = installFleetFetchMock({
      hubConfig: STRICT_HUB_CONFIG,
    });

    renderIntelDetailPage();

    await waitFor(() => {
      expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
        activeSwarmId: swarm.id,
        trustPolicy: STRICT_HUB_CONFIG.trustPolicy,
      });
    });

    await waitFor(() => {
      const requestedUrls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(requestedUrls).toContain("/_proxy/hushd/api/v1/swarm/hub/config");
    });

    await waitFor(() => {
      const persistedFeed = JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}");
      expect(persistedFeed.trustPolicies).toMatchObject({
        [swarm.id]: STRICT_HUB_CONFIG.trustPolicy,
      });
    });

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));
    fireEvent.click(screen.getByRole("button", { name: "Share to Swarm" }));

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 650));
    });

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      activeSwarmId: swarm.id,
      sharedIntelCount: 0,
      swarmRecordCount: 0,
      findingEnvelopeCount: 0,
      headAnnouncementCount: 0,
      trustPolicy: STRICT_HUB_CONFIG.trustPolicy,
    });

    expect(JSON.parse(localStorage.getItem(INTEL_STORAGE_KEY) ?? "{}").swarmIntel ?? []).toHaveLength(0);
    expect(JSON.parse(localStorage.getItem(SWARM_STORAGE_KEY) ?? "{}").swarms[0].sharedIntel ?? []).toHaveLength(
      0,
    );
    expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").findingEnvelopes ?? []).toHaveLength(0);
    expect(JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}").headAnnouncements ?? []).toHaveLength(0);
  });

  it("fails closed while live hub trust hydration is unresolved and persists no partial share state", async () => {
    const { swarm } = await seedIntelDetailPage();
    seedSavedFleetConnection();
    const fetchMock = installFleetFetchMock({
      hubConfigPromise: new Promise<HubConfig>(() => {}),
    });

    renderIntelDetailPage();

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));
    const pendingShareButton = screen.getByRole("button", { name: "Share to Swarm" });
    expect((pendingShareButton as HTMLButtonElement).disabled).toBe(true);

    await waitFor(() => {
      const requestedUrls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(requestedUrls).toContain("/_proxy/hushd/api/v1/swarm/hub/config");
    });

    await waitFor(() => {
      expect(readSnapshot()).toMatchObject({
        activeSwarmId: swarm.id,
        trustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
        sharedIntelCount: 0,
        swarmRecordCount: 0,
        findingEnvelopeCount: 0,
        headAnnouncementCount: 0,
      });
    });

    await waitFor(() => {
      const persistedFeed = JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}");
      expect(persistedFeed.trustPolicies).toMatchObject({
        [swarm.id]: FAIL_CLOSED_HUB_TRUST_POLICY,
      });
    });

    const shareButton = screen.getByRole("button", { name: "Share to Swarm" });
    expect((shareButton as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(shareButton);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 650));
    });

    expect(readSnapshot()).toMatchObject({
      activeSwarmId: swarm.id,
      sharedIntelCount: 0,
      swarmRecordCount: 0,
      findingEnvelopeCount: 0,
      headAnnouncementCount: 0,
    });
    expectNoPersistedSwarmShareState();
  });

  it("keeps live hub sharing disabled after trust hydration fails and persists no partial share state", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { swarm } = await seedIntelDetailPage();
    seedSavedFleetConnection();
    const fetchMock = installFleetFetchMock({
      hubConfigError: new Error("hub config unavailable"),
    });

    renderIntelDetailPage();

    await waitFor(() => {
      const requestedUrls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(requestedUrls).toContain("/_proxy/hushd/api/v1/swarm/hub/config");
    });

    await waitFor(() => {
      expect(readSnapshot()).toMatchObject({
        activeSwarmId: swarm.id,
        trustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
        sharedIntelCount: 0,
        swarmRecordCount: 0,
        findingEnvelopeCount: 0,
        headAnnouncementCount: 0,
      });
    });

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));

    const shareButton = screen.getByRole("button", { name: "Share to Swarm" });
    expect((shareButton as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(shareButton);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 650));
    });

    expect(readSnapshot()).toMatchObject({
      activeSwarmId: swarm.id,
      sharedIntelCount: 0,
      swarmRecordCount: 0,
      findingEnvelopeCount: 0,
      headAnnouncementCount: 0,
    });
    expectNoPersistedSwarmShareState();
    expect(warnSpy).toHaveBeenCalled();
  });

  it("attributes durable feed and head issuer to the publishing operator when re-sharing signed intel", async () => {
    const publisher = await createOperatorIdentity("Publisher Bravo");
    const { signerIdentity } = await seedIntelDetailPage({
      currentOperator: publisher.identity,
    });
    const view = renderIntelDetailPage();
    const publisherIssuerId = `aegis:ed25519:${publisher.identity.publicKey}`;
    const signerIssuerId = `aegis:ed25519:${signerIdentity.publicKey}`;

    fireEvent.click(screen.getByRole("button", { name: "Swarm" }));
    fireEvent.click(screen.getByRole("button", { name: "Share to Swarm" }));

    await waitFor(() => {
      expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
        firstFindingEnvelope: {
          issuerId: publisherIssuerId,
          feedId: publisherIssuerId,
        },
        firstHeadAnnouncement: {
          issuerId: publisherIssuerId,
          feedId: publisherIssuerId,
        },
      });
    });

    await waitFor(() => {
      const persistedFeed = JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}");
      expect(persistedFeed.findingEnvelopes).toHaveLength(1);
      expect(persistedFeed.headAnnouncements).toHaveLength(1);
    });

    const persistedFeed = JSON.parse(localStorage.getItem(SWARM_FEED_STORAGE_KEY) ?? "{}");
    expect(persistedFeed.findingEnvelopes[0]?.envelope).toMatchObject({
      issuerId: publisherIssuerId,
      feedId: publisherIssuerId,
    });
    expect(persistedFeed.headAnnouncements[0]?.announcement).toMatchObject({
      issuerId: publisherIssuerId,
      feedId: publisherIssuerId,
    });
    expect(persistedFeed.findingEnvelopes[0]?.envelope.issuerId).not.toBe(signerIssuerId);
    expect(persistedFeed.headAnnouncements[0]?.announcement.issuerId).not.toBe(signerIssuerId);

    view.unmount();
  });

  it("verifies a discovered swarm blob ref end-to-end from the intel detail route", async () => {
    const swarmId = "swarm_trusted_01";
    const { blob, ref, artifactBytesByUri } = await makeBlobFixture();
    const { signedIntel } = await seedIntelDetailPage();
    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedState({
      swarmId,
      findingId: signedIntel.derivedFrom[0] ?? "fnd_share_01",
      blobRefs: [ref],
    });
    seedSavedFleetConnection();
    const fetchMock = installFleetFetchMock({
      blob,
      ref,
      artifactBytesByUri,
    });

    renderIntelDetailPage(signedIntel.id);

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    expect(screen.getByText(ref.blobId)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Verify blob" }));

    await waitFor(() => {
      expect(screen.getByText("Manifest + 2 artifacts verified")).toBeTruthy();
    });

    await waitFor(() => {
      const requestedUrls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(requestedUrls).toEqual(
        expect.arrayContaining([
          blob.publish?.uri ?? "",
          blob.artifacts[0]?.publish?.uri ?? "",
          blob.artifacts[1]?.publish?.uri ?? "",
        ]),
      );
    });
  });

  it("blocks route success when any published artifact bytes fail verification", async () => {
    const swarmId = "swarm_trusted_01";
    const { blob, ref, artifactBytesByUri } = await makeBlobFixture();
    const { signedIntel } = await seedIntelDetailPage();
    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedState({
      swarmId,
      findingId: signedIntel.derivedFrom[0] ?? "fnd_share_01",
      blobRefs: [ref],
    });
    seedSavedFleetConnection();
    const tamperedTranscriptUri = blob.artifacts[1]?.publish?.uri ?? "";
    const tamperedTranscriptBytes = new Uint8Array(artifactBytesByUri[tamperedTranscriptUri]);
    tamperedTranscriptBytes[0] = tamperedTranscriptBytes[0] ^ 0xff;
    const fetchMock = installFleetFetchMock({
      blob,
      ref,
      artifactBytesByUri: {
        ...artifactBytesByUri,
        [tamperedTranscriptUri]: tamperedTranscriptBytes,
      },
    });

    renderIntelDetailPage();

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Verify blob" }));

    await waitFor(() => {
      expect(screen.getByText("Verification blocked")).toBeTruthy();
    });
    expect(screen.getByText(/artifact digest mismatch/i)).toBeTruthy();
    expect(screen.queryByText("Manifest + 2 artifacts verified")).toBeNull();

    await waitFor(() => {
      const requestedUrls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(requestedUrls).toEqual(
        expect.arrayContaining([blob.publish?.uri ?? "", tamperedTranscriptUri]),
      );
    });
  });

  it("verifies published artifacts sequentially instead of fanning out all artifact fetches", async () => {
    const swarmId = "swarm_trusted_01";
    const { blob, ref, artifactBytesByUri } = await makeBlobFixture();
    const { signedIntel } = await seedIntelDetailPage();
    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedState({
      swarmId,
      findingId: signedIntel.derivedFrom[0] ?? "fnd_share_01",
      blobRefs: [ref],
    });
    seedSavedFleetConnection();

    const artifactFetchCalls: string[] = [];
    const releaseArtifactFetches: Array<() => void> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);

      if (url === "/_proxy/hushd/health") {
        return jsonResponse({ status: "ok" });
      }

      if (url === "/_proxy/hushd/api/v1/agents/status?include_stale=true") {
        return jsonResponse({
          generated_at: new Date(1_715_000_000_000).toISOString(),
          stale_after_secs: 90,
          endpoints: [],
          runtimes: [],
        });
      }

      if (url === "/_proxy/hushd/api/v1/policy") {
        return jsonResponse({ yaml: "", name: "default" });
      }

      if (url === "/_proxy/hushd/api/v1/swarm/hub/config") {
        return jsonResponse(PERMISSIVE_HUB_CONFIG);
      }

      if (url === `/_proxy/hushd/api/v1/swarm/blobs/${ref.digest}`) {
        return jsonResponse({
          schema: "clawdstrike.swarm.blob_lookup.v1",
          digest: ref.digest,
          bytesAvailable: true,
          refs: [
            {
              blobId: ref.blobId,
              feedId: `aegis:ed25519:${"c".repeat(64)}`,
              issuerId: `aegis:ed25519:${"c".repeat(64)}`,
              feedSeq: 7,
              findingId: "fnd_share_01",
              mediaType: ref.mediaType,
              byteLength: ref.byteLength,
              publish: ref.publish,
            },
          ],
        });
      }

      if (url === ref.publish?.uri) {
        return jsonResponse(blob);
      }

      const artifactBytes = artifactBytesByUri[url];
      if (artifactBytes) {
        artifactFetchCalls.push(url);
        return new Promise<Response>((resolve) => {
          releaseArtifactFetches.push(() => resolve(bytesResponse(artifactBytes)));
        });
      }

      throw new Error(`Unhandled fetch in test: ${url}`);
    });

    vi.stubGlobal("fetch", fetchMock);

    renderIntelDetailPage(signedIntel.id);

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Verify blob" }));

    await waitFor(() => {
      expect(artifactFetchCalls).toHaveLength(1);
    });

    releaseArtifactFetches[0]?.();

    await waitFor(() => {
      expect(artifactFetchCalls).toHaveLength(2);
    });

    releaseArtifactFetches[1]?.();

    await waitFor(() => {
      expect(screen.getByText("Manifest + 2 artifacts verified")).toBeTruthy();
    });
  });

  it("requests hushd pin intent when a discovered blob ref lacks a usable fetch URI", async () => {
    const swarmId = "swarm_trusted_01";
    const { ref } = await makeBlobFixture();
    const { signedIntel } = await seedIntelDetailPage();
    const missingUriRef: FindingBlobRef = {
      ...ref,
      publish: undefined,
    };
    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedState({
      swarmId,
      findingId: signedIntel.derivedFrom[0] ?? "fnd_share_01",
      blobRefs: [missingUriRef],
    });
    seedSavedFleetConnection();
    installFleetFetchMock({
      ref,
      bytesAvailable: false,
      includeBlobUri: false,
      pinRecorded: true,
    });

    renderIntelDetailPage();

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Verify blob" }));

    expect(await screen.findByRole("button", { name: "Request hushd pin" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Request hushd pin" }));

    await waitFor(() => {
      expect(screen.getByText("Pin intent recorded")).toBeTruthy();
    });
  });

  it("shows a stable empty artifact state when related swarm findings do not publish blob refs", async () => {
    const swarmId = "swarm_trusted_01";
    const { signedIntel } = await seedIntelDetailPage();
    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedState({
      swarmId,
      findingId: signedIntel.derivedFrom[0] ?? "fnd_share_01",
      blobRefs: [],
    });

    renderIntelDetailPage();

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    expect(screen.getByText("No swarm artifacts published for this intel yet.")).toBeTruthy();
  });

  it("ignores revoked finding blob refs when projecting swarm artifacts", async () => {
    const swarmId = "swarm_trusted_01";
    const { signedIntel } = await seedIntelDetailPage();
    const revokedRef: FindingBlobRef = {
      blobId: "blob_01J7REVOKED",
      digest: `0x${"4".repeat(64)}`,
      mediaType: "application/json",
      byteLength: 144,
      publish: {
        uri: "https://blob.example/blobs/blob_01J7REVOKED.json",
        publishedAt: 1_715_000_001_090,
      },
    };
    const findingRecord = makeSwarmFindingEnvelopeRecord({
      swarmId,
      findingId: signedIntel.derivedFrom[0] ?? "fnd_share_01",
      blobRefs: [revokedRef],
      title: "Revoked finding",
    });

    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedRecords(
      [findingRecord],
      [
        makeSwarmRevocationEnvelopeRecord({
          swarmId,
          findingId: findingRecord.envelope.findingId,
          feedId: findingRecord.envelope.feedId,
          action: "revoke",
          feedSeq: 8,
          issuedAt: 1_715_000_001_400,
        }),
      ],
    );

    renderIntelDetailPage(signedIntel.id);

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    expect(screen.queryByText(revokedRef.blobId)).toBeNull();
    expect(screen.getByText("No swarm artifacts published for this intel yet.")).toBeTruthy();
  });

  it("follows superseded finding replacements when projecting swarm artifacts", async () => {
    const swarmId = "swarm_trusted_01";
    const { signedIntel } = await seedIntelDetailPage();
    const originalRef: FindingBlobRef = {
      blobId: "blob_01J7SOURCE",
      digest: `0x${"5".repeat(64)}`,
      mediaType: "application/json",
      byteLength: 188,
      publish: {
        uri: "https://blob.example/blobs/blob_01J7SOURCE.json",
        publishedAt: 1_715_000_001_120,
      },
    };
    const replacementRef: FindingBlobRef = {
      blobId: "blob_01J7REPLACEMENT",
      digest: `0x${"6".repeat(64)}`,
      mediaType: "application/json",
      byteLength: 208,
      publish: {
        uri: "https://blob.example/blobs/blob_01J7REPLACEMENT.json",
        publishedAt: 1_715_000_001_220,
      },
    };
    const sourceFindingId = signedIntel.derivedFrom[0] ?? "fnd_share_01";
    const replacementFindingId = "fnd_share_01_replacement";
    const sourceRecord = makeSwarmFindingEnvelopeRecord({
      swarmId,
      findingId: sourceFindingId,
      blobRefs: [originalRef],
      title: "Original finding",
      feedSeq: 7,
      publishedAt: 1_715_000_001_200,
    });
    const replacementRecord = makeSwarmFindingEnvelopeRecord({
      swarmId,
      findingId: replacementFindingId,
      blobRefs: [replacementRef],
      title: "Replacement finding",
      feedSeq: 8,
      publishedAt: 1_715_000_001_300,
    });

    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedRecords(
      [sourceRecord, replacementRecord],
      [
        makeSwarmRevocationEnvelopeRecord({
          swarmId,
          findingId: sourceFindingId,
          feedId: sourceRecord.envelope.feedId,
          action: "supersede",
          replacementFindingId,
          feedSeq: 9,
          issuedAt: 1_715_000_001_450,
        }),
      ],
    );

    renderIntelDetailPage(signedIntel.id);

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    expect(screen.getByText(replacementRef.blobId)).toBeTruthy();
    expect(screen.queryByText(originalRef.blobId)).toBeNull();
    expect(screen.getByText("1 blob ref discovered from related swarm findings.")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Verify blob" })).toHaveLength(1);
  });

  it("only discovers blob refs for the fallback intel id when derivedFrom is empty", async () => {
    const swarmId = "swarm_trusted_01";
    const baseIntel = makeIntel();
    const { signedIntel } = await seedIntelDetailPage({
      signerIntel: {
        ...baseIntel,
        id: "int_fallback_01",
        derivedFrom: [],
        receipt: {
          ...baseIntel.receipt,
          action: {
            ...baseIntel.receipt.action,
            target: "intel:int_fallback_01",
          },
        },
      },
    });
    const unrelatedRef: FindingBlobRef = {
      blobId: "blob_01J7UNRELATED",
      digest: `0x${"1".repeat(64)}`,
      mediaType: "application/json",
      byteLength: 128,
      publish: {
        uri: "https://blob.example/blobs/blob_01J7UNRELATED.json",
        publishedAt: 1_715_000_001_050,
      },
    };
    const fallbackRef: FindingBlobRef = {
      blobId: "blob_01J7FALLBACK",
      digest: `0x${"2".repeat(64)}`,
      mediaType: "application/json",
      byteLength: 192,
      publish: {
        uri: "https://blob.example/blobs/blob_01J7FALLBACK.json",
        publishedAt: 1_715_000_001_150,
      },
    };

    persistSwarmIntelState(signedIntel, swarmId);
    persistSwarmFeedRecords([
      makeSwarmFindingEnvelopeRecord({
        swarmId,
        findingId: "fnd_unrelated_01",
        blobRefs: [unrelatedRef],
        title: "Unrelated finding",
      }),
      makeSwarmFindingEnvelopeRecord({
        swarmId,
        findingId: signedIntel.id,
        blobRefs: [fallbackRef],
        title: "Fallback finding",
        feedSeq: 8,
        publishedAt: 1_715_000_001_300,
      }),
    ]);

    renderIntelDetailPage(signedIntel.id);

    expect(await screen.findByText("Swarm Artifacts")).toBeTruthy();
    expect(screen.getByText(fallbackRef.blobId)).toBeTruthy();
    expect(screen.queryByText(unrelatedRef.blobId)).toBeNull();
    expect(screen.getByText("1 blob ref discovered from related swarm findings.")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Verify blob" })).toHaveLength(1);
  });
});
