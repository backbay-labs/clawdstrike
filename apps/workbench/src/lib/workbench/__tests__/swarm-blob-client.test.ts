import { describe, expect, it, vi } from "vitest";
import {
  FINDING_BLOB_SCHEMA,
  hashProtocolPayload,
  type FindingBlob,
  type FindingBlobArtifact,
  type FindingBlobRef,
  type ProtocolDigest,
} from "../swarm-protocol";
import {
  fetchSwarmBlobLookup,
  fetchVerifiedBlobArtifact,
  fetchVerifiedFindingBlob,
  requestSwarmBlobPin,
} from "../swarm-blob-client";

const PUBLIC_KEY = "b".repeat(64);
const ISSUER_ID = `aegis:ed25519:${PUBLIC_KEY}`;

function makeConn() {
  return {
    hushdUrl: "http://localhost:9876",
    apiKey: "hushd-token",
  };
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

function bytesResponse(bytes: Uint8Array, init?: ResponseInit): Response {
  return new Response(bytes as unknown as BodyInit, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream" },
    ...init,
  });
}

function streamingResponse(
  chunks: Uint8Array[],
  init?: ResponseInit,
): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(Uint8Array.from(chunk));
        }
        controller.close();
      },
    }),
    {
      status: 200,
      ...init,
    },
  );
}

async function sha256Hex(bytes: Uint8Array): Promise<ProtocolDigest> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- DOM lib typing mismatch
  const digestBuffer = await crypto.subtle.digest("SHA-256", bytes as any);
  const digest = Array.from(new Uint8Array(digestBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `0x${digest}`;
}

async function makeBlobFixture(): Promise<{
  blob: FindingBlob;
  ref: FindingBlobRef;
  artifact: FindingBlobArtifact;
  artifactBytes: Uint8Array;
}> {
  const artifactBytes = new TextEncoder().encode(
    JSON.stringify({
      summary: "terminal transcript",
      lines: ["curl https://example.invalid", "exit 1"],
    }),
  );

  const artifactDigest = await sha256Hex(artifactBytes);
  const artifact: FindingBlobArtifact = {
    artifactId: "artifact_01J7BLOB",
    kind: "json",
    mediaType: "application/json",
    digest: artifactDigest,
    byteLength: artifactBytes.byteLength,
    name: "transcript.json",
    publish: {
      uri: "https://blob.example/artifacts/artifact_01J7BLOB.json",
      publishedAt: 1_715_000_000_200,
    },
  };

  const blob: FindingBlob = {
    schema: FINDING_BLOB_SCHEMA,
    blobId: "blob_01J7BLOB",
    findingId: "fnd_01J7FINDING",
    issuerId: ISSUER_ID,
    createdAt: 1_715_000_000_100,
    manifest: {
      bundleType: "evidence",
      artifactCount: 1,
      summary: {
        hasTranscript: true,
      },
    },
    artifacts: [artifact],
    publish: {
      uri: "https://blob.example/blobs/blob_01J7BLOB.json",
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

  return { blob, ref, artifact, artifactBytes };
}

describe("fetchSwarmBlobLookup", () => {
  it("fetches and validates a hushd blob lookup response", async () => {
    const { ref } = await makeBlobFixture();
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({
        schema: "clawdstrike.swarm.blob_lookup.v1",
        digest: ref.digest,
        bytesAvailable: false,
        refs: [
          {
            blobId: ref.blobId,
            feedId: "fed.alpha",
            issuerId: ISSUER_ID,
            feedSeq: 7,
            findingId: "fnd_01J7FINDING",
            mediaType: ref.mediaType,
            byteLength: ref.byteLength,
            publish: ref.publish,
          },
        ],
      }),
    );

    const result = await fetchSwarmBlobLookup(makeConn(), ref.digest, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.digest).toBe(ref.digest);
    expect(result.bytesAvailable).toBe(false);
    expect(result.refs[0]?.blobId).toBe(ref.blobId);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0]?.[0]).toBe(`/_proxy/hushd/api/v1/swarm/blobs/${ref.digest}`);
  });

  it("rejects malformed hushd blob lookup responses", async () => {
    const { ref } = await makeBlobFixture();
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        schema: "clawdstrike.swarm.blob_lookup.v1",
        digest: "not-a-digest",
        bytesAvailable: false,
        refs: {},
      }),
    );

    await expect(
      fetchSwarmBlobLookup(makeConn(), ref.digest, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/blob lookup response/i);
  });
});

describe("fetchVerifiedFindingBlob", () => {
  it("fetches a FindingBlob document and verifies its canonical digest", async () => {
    const { blob, ref } = await makeBlobFixture();
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(blob));

    const result = await fetchVerifiedFindingBlob(ref, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.blob).toEqual(blob);
    expect(result.digest).toBe(ref.digest);
    expect(result.sourceUri).toBe(ref.publish?.uri);
    expect(fetchImpl.mock.calls[0]?.[0]).toBe(ref.publish?.uri);
  });

  it("rejects redirects when fetching an untrusted FindingBlob document", async () => {
    const { blob, ref } = await makeBlobFixture();
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(blob));

    await fetchVerifiedFindingBlob(ref, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(fetchImpl.mock.calls[0]?.[1]).toMatchObject({
      redirect: "error",
    });
  });

  it("rejects a fetched FindingBlob when the digest does not match the ref", async () => {
    const { blob, ref } = await makeBlobFixture();
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        ...blob,
        manifest: {
          ...blob.manifest,
          summary: {
            hasTranscript: false,
          },
        },
      }),
    );

    await expect(
      fetchVerifiedFindingBlob(ref, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/digest mismatch/i);
  });

  it("rejects embedded credentials in an untrusted blob publish URI before fetching", async () => {
    const { blob, ref } = await makeBlobFixture();
    const fetchImpl = vi.fn(async () => jsonResponse(blob));

    await expect(
      fetchVerifiedFindingBlob(
        {
          ...ref,
          publish: {
            ...ref.publish,
            uri: "https://sentinel:secret@blob.example/blobs/blob_01J7BLOB.json",
          },
        },
        {
          fetchImpl: fetchImpl as unknown as typeof fetch,
        },
      ),
    ).rejects.toThrow(/embedded credentials/i);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fails closed when a blob ref lacks a usable fetch URI", async () => {
    const { ref } = await makeBlobFixture();
    const fetchImpl = vi.fn();

    await expect(
      fetchVerifiedFindingBlob(
        {
          ...ref,
          publish: undefined,
        },
        { fetchImpl: fetchImpl as unknown as typeof fetch },
      ),
    ).rejects.toThrow(/usable fetch uri/i);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects oversized FindingBlob responses without relying on Content-Length", async () => {
    const { blob, ref } = await makeBlobFixture();
    const oversizedBlob: FindingBlob = {
      ...blob,
      manifest: {
        ...blob.manifest,
        padding: "x".repeat(1_048_576),
      },
    };
    const oversizedBytes = new TextEncoder().encode(JSON.stringify(oversizedBlob));
    const splitAt = Math.floor(oversizedBytes.byteLength / 2);
    const fetchImpl = vi.fn(async () =>
      streamingResponse(
        [oversizedBytes.slice(0, splitAt), oversizedBytes.slice(splitAt)],
        {
          headers: { "Content-Type": "application/json" },
        },
      ),
    );

    await expect(
      fetchVerifiedFindingBlob(
        {
          ...ref,
          digest: await hashProtocolPayload(oversizedBlob),
        },
        {
          fetchImpl: fetchImpl as unknown as typeof fetch,
        },
      ),
    ).rejects.toThrow(/too large/i);
  });
});

describe("fetchVerifiedBlobArtifact", () => {
  it("fetches raw artifact bytes and verifies byte length and raw-byte sha256", async () => {
    const { artifact, artifactBytes } = await makeBlobFixture();
    const fetchImpl = vi.fn(async () => bytesResponse(artifactBytes));

    const result = await fetchVerifiedBlobArtifact(artifact, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result.digest).toBe(artifact.digest);
    expect(result.byteLength).toBe(artifact.byteLength);
    expect(Array.from(result.bytes)).toEqual(Array.from(artifactBytes));
    expect(result.sourceUri).toBe(artifact.publish?.uri);
  });

  it("rejects redirects when fetching an untrusted blob artifact", async () => {
    const { artifact, artifactBytes } = await makeBlobFixture();
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      bytesResponse(artifactBytes),
    );

    await fetchVerifiedBlobArtifact(artifact, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(fetchImpl.mock.calls[0]?.[1]).toMatchObject({
      redirect: "error",
    });
  });

  it("rejects artifact fetch when the byte length mismatches metadata", async () => {
    const { artifact, artifactBytes } = await makeBlobFixture();
    const fetchImpl = vi.fn(async () => bytesResponse(artifactBytes.slice(0, artifactBytes.length - 1)));

    await expect(
      fetchVerifiedBlobArtifact(artifact, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/byte length/i);
  });

  it("rejects artifact fetch when the raw-byte digest mismatches metadata", async () => {
    const { artifact, artifactBytes } = await makeBlobFixture();
    const tampered = new Uint8Array(artifactBytes);
    tampered[0] = tampered[0] ^ 0xff;
    const fetchImpl = vi.fn(async () => bytesResponse(tampered));

    await expect(
      fetchVerifiedBlobArtifact(artifact, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/digest mismatch/i);
  });

  it("rejects embedded credentials in an untrusted artifact publish URI before fetching", async () => {
    const { artifact, artifactBytes } = await makeBlobFixture();
    const fetchImpl = vi.fn(async () => bytesResponse(artifactBytes));

    await expect(
      fetchVerifiedBlobArtifact(
        {
          ...artifact,
          publish: {
            ...artifact.publish,
            uri: "https://sentinel:secret@blob.example/artifacts/artifact_01J7BLOB.json",
          },
        },
        {
          fetchImpl: fetchImpl as unknown as typeof fetch,
        },
      ),
    ).rejects.toThrow(/embedded credentials/i);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fails closed when an artifact lacks a usable fetch URI", async () => {
    const { artifact } = await makeBlobFixture();
    const fetchImpl = vi.fn();

    await expect(
      fetchVerifiedBlobArtifact(
        {
          ...artifact,
          publish: {
            uri: "ipfs://artifact_01J7BLOB",
          },
        },
        {
          fetchImpl: fetchImpl as unknown as typeof fetch,
        },
      ),
    ).rejects.toThrow(/usable fetch uri/i);

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects oversized artifact responses", async () => {
    const { artifact } = await makeBlobFixture();
    const oversizedBytes = new Uint8Array(10_485_760 + 32);
    oversizedBytes.fill(0x5a);
    const fetchImpl = vi.fn(async () =>
      bytesResponse(oversizedBytes, {
        headers: {
          "Content-Type": "application/octet-stream",
          "Content-Length": String(oversizedBytes.byteLength),
        },
      }),
    );

    await expect(
      fetchVerifiedBlobArtifact(
        {
          ...artifact,
          digest: await sha256Hex(oversizedBytes),
          byteLength: oversizedBytes.byteLength,
        },
        {
          fetchImpl: fetchImpl as unknown as typeof fetch,
        },
      ),
    ).rejects.toThrow(/too large/i);
  });
});

describe("requestSwarmBlobPin", () => {
  it("posts blob pin intent to hushd and validates the response shape", async () => {
    const { ref } = await makeBlobFixture();
    let seenBody: unknown;
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      seenBody = JSON.parse(String(init?.body));
      return jsonResponse(
        {
          accepted: true,
          recorded: true,
          requestId: "pinreq_01J7BLOB",
          digest: ref.digest,
          status: "recorded",
          recordedAt: 1_715_000_000_400,
        },
        { status: 202 },
      );
    });

    const result = await requestSwarmBlobPin(
      makeConn(),
      {
        digest: ref.digest,
        requestedBy: "workbench-test",
        note: "pin for later retrieval",
      },
      {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    );

    expect(result).toEqual({
      accepted: true,
      recorded: true,
      requestId: "pinreq_01J7BLOB",
      digest: ref.digest,
      status: "recorded",
      recordedAt: 1_715_000_000_400,
    });
    expect(fetchImpl.mock.calls[0]?.[0]).toBe("/_proxy/hushd/api/v1/swarm/blobs/pin");
    expect(seenBody).toEqual({
      digest: ref.digest,
      requestedBy: "workbench-test",
      note: "pin for later retrieval",
    });
  });
});
