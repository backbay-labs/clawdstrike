import {
  hashProtocolPayload,
  isFindingBlob,
  isProtocolDigest,
  type DurablePublishMetadata,
  type FindingBlob,
  type FindingBlobArtifact,
  type FindingBlobRef,
  type ProtocolDigest,
} from "./swarm-protocol";
import { validateFleetUrl } from "./fleet-url-policy";
import { httpFetch } from "./http-transport";

const DEV = import.meta.env.DEV;
const SWARM_BLOB_LOOKUP_SCHEMA = "clawdstrike.swarm.blob_lookup.v1" as const;
const MAX_JSON_RESPONSE_BYTES = 1_048_576;
const MAX_ARTIFACT_RESPONSE_BYTES = 10_485_760;

const WITNESS_PROOF_PROVIDERS = ["witness", "notary", "spine", "other"] as const;
const DURABLE_PUBLISH_METADATA_KEYS = [
  "uri",
  "publishedAt",
  "notaryRecordId",
  "notaryEnvelopeHash",
  "witnessProofs",
] as const;
const SWARM_BLOB_LOOKUP_REF_KEYS = [
  "blobId",
  "feedId",
  "issuerId",
  "feedSeq",
  "findingId",
  "mediaType",
  "byteLength",
  "publish",
] as const;
const SWARM_BLOB_LOOKUP_RESPONSE_KEYS = [
  "schema",
  "digest",
  "bytesAvailable",
  "refs",
] as const;
const SWARM_BLOB_PIN_RESPONSE_KEYS = [
  "accepted",
  "recorded",
  "requestId",
  "digest",
  "status",
  "recordedAt",
] as const;
const WITNESS_PROOF_REF_KEYS = ["provider", "digest", "uri"] as const;

export interface SwarmBlobLookupRef {
  blobId: string;
  feedId: string;
  issuerId: string;
  feedSeq: number;
  findingId: string;
  mediaType: string;
  byteLength: number;
  publish?: DurablePublishMetadata;
}

export interface SwarmBlobLookupResponse {
  schema: typeof SWARM_BLOB_LOOKUP_SCHEMA;
  digest: ProtocolDigest;
  bytesAvailable: boolean;
  refs: SwarmBlobLookupRef[];
}

export interface SwarmBlobPinIntent {
  digest: ProtocolDigest;
  requestedBy?: string;
  note?: string;
}

export interface SwarmBlobPinResponse {
  accepted: boolean;
  recorded: boolean;
  requestId: string;
  digest: ProtocolDigest;
  status: string;
  recordedAt: number;
}

export interface VerifiedFindingBlobResult {
  blob: FindingBlob;
  digest: ProtocolDigest;
  sourceUri: string;
}

export interface VerifiedBlobArtifactResult {
  artifact: FindingBlobArtifact;
  bytes: Uint8Array;
  digest: ProtocolDigest;
  byteLength: number;
  sourceUri: string;
}

export interface BlobByteDigester {
  digest(bytes: Uint8Array): Promise<ProtocolDigest>;
}

export interface SwarmBlobClientFetchOptions {
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
}

export interface SwarmBlobArtifactFetchOptions extends SwarmBlobClientFetchOptions {
  byteDigester?: BlobByteDigester;
}

export interface SwarmBlobConnection {
  hushdUrl: string;
  apiKey?: string;
}

const defaultBlobByteDigester: BlobByteDigester = {
  digest: hashRawBytesSha256,
};

export async function fetchSwarmBlobLookup(
  connection: SwarmBlobConnection,
  digest: ProtocolDigest,
  options: SwarmBlobClientFetchOptions = {},
): Promise<SwarmBlobLookupResponse> {
  if (!isProtocolDigest(digest)) {
    throw new Error("[swarm-blob-client] blob lookup requires a 0x-prefixed sha256 digest");
  }

  const baseUrl = normalizeHushdUrl(connection.hushdUrl);
  const response = await fetchJson(
    proxyHushdUrl(`${baseUrl}/api/v1/swarm/blobs/${digest}`),
    {
      fetchImpl: options.fetchImpl,
      signal: options.signal,
      headers: createHushdHeaders(connection.apiKey),
    },
  );
  const lookup = parseSwarmBlobLookupResponse(response);

  if (lookup.digest !== digest) {
    throw new Error("[swarm-blob-client] blob lookup response digest mismatch");
  }

  return lookup;
}

export async function fetchVerifiedFindingBlob(
  ref: FindingBlobRef,
  options: SwarmBlobClientFetchOptions = {},
): Promise<VerifiedFindingBlobResult> {
  assertByteLengthWithinLimit(
    ref.byteLength,
    MAX_JSON_RESPONSE_BYTES,
    "FindingBlob ref",
  );
  const sourceUri = requireFetchUri(ref.publish, "FindingBlob ref");
  const response = await fetchJson(sourceUri, {
    fetchImpl: options.fetchImpl,
    redirect: "error",
    signal: options.signal,
  });

  if (!isFindingBlob(response)) {
    throw new Error("[swarm-blob-client] fetched FindingBlob is invalid");
  }

  const digest = await hashProtocolPayload(response);
  if (digest !== ref.digest) {
    throw new Error("[swarm-blob-client] FindingBlob digest mismatch");
  }

  return {
    blob: response,
    digest,
    sourceUri,
  };
}

export async function fetchVerifiedBlobArtifact(
  artifact: FindingBlobArtifact,
  options: SwarmBlobArtifactFetchOptions = {},
): Promise<VerifiedBlobArtifactResult> {
  assertByteLengthWithinLimit(
    artifact.byteLength,
    MAX_ARTIFACT_RESPONSE_BYTES,
    "FindingBlob artifact",
  );
  const sourceUri = requireFetchUri(artifact.publish, "FindingBlob artifact");
  const bytes = await fetchBytes(sourceUri, {
    fetchImpl: options.fetchImpl,
    redirect: "error",
    signal: options.signal,
  });

  if (bytes.byteLength !== artifact.byteLength) {
    throw new Error(
      `[swarm-blob-client] artifact byte length mismatch: expected ${artifact.byteLength}, got ${bytes.byteLength}`,
    );
  }

  const digester = options.byteDigester ?? defaultBlobByteDigester;
  const digest = await digester.digest(bytes);
  if (digest !== artifact.digest) {
    throw new Error("[swarm-blob-client] artifact digest mismatch");
  }

  return {
    artifact,
    bytes,
    digest,
    byteLength: bytes.byteLength,
    sourceUri,
  };
}

export async function requestSwarmBlobPin(
  connection: SwarmBlobConnection,
  request: SwarmBlobPinIntent,
  options: SwarmBlobClientFetchOptions = {},
): Promise<SwarmBlobPinResponse> {
  if (!isProtocolDigest(request.digest)) {
    throw new Error("[swarm-blob-client] blob pin requires a 0x-prefixed sha256 digest");
  }

  const baseUrl = normalizeHushdUrl(connection.hushdUrl);
  const response = await fetchJson(
    proxyHushdUrl(`${baseUrl}/api/v1/swarm/blobs/pin`),
    {
      fetchImpl: options.fetchImpl,
      signal: options.signal,
      method: "POST",
      headers: createHushdHeaders(connection.apiKey),
      body: JSON.stringify({
        digest: request.digest,
        ...(request.requestedBy ? { requestedBy: request.requestedBy } : {}),
        ...(request.note ? { note: request.note } : {}),
      }),
    },
  );

  const parsed = parseSwarmBlobPinResponse(response);
  if (parsed.digest !== request.digest) {
    throw new Error("[swarm-blob-client] blob pin response digest mismatch");
  }

  return parsed;
}

export async function hashRawBytesSha256(bytes: Uint8Array): Promise<ProtocolDigest> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Bun/@types mismatch
  const digestBuffer = await crypto.subtle.digest("SHA-256", bytes as any);
  const digest = Array.from(new Uint8Array(digestBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `0x${digest}`;
}

function parseSwarmBlobLookupResponse(value: unknown): SwarmBlobLookupResponse {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, SWARM_BLOB_LOOKUP_RESPONSE_KEYS) ||
    value.schema !== SWARM_BLOB_LOOKUP_SCHEMA ||
    !isProtocolDigest(value.digest) ||
    typeof value.bytesAvailable !== "boolean" ||
    !Array.isArray(value.refs) ||
    !value.refs.every((entry) => isSwarmBlobLookupRef(entry))
  ) {
    throw new Error("[swarm-blob-client] invalid blob lookup response");
  }

  return value as unknown as SwarmBlobLookupResponse;
}

function parseSwarmBlobPinResponse(value: unknown): SwarmBlobPinResponse {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, SWARM_BLOB_PIN_RESPONSE_KEYS) ||
    typeof value.accepted !== "boolean" ||
    typeof value.recorded !== "boolean" ||
    !isNonEmptyString(value.requestId) ||
    !isProtocolDigest(value.digest) ||
    !isNonEmptyString(value.status) ||
    !isSafeNonNegativeInteger(value.recordedAt)
  ) {
    throw new Error("[swarm-blob-client] invalid blob pin response");
  }

  return value as unknown as SwarmBlobPinResponse;
}

function isSwarmBlobLookupRef(value: unknown): value is SwarmBlobLookupRef {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, SWARM_BLOB_LOOKUP_REF_KEYS) &&
    isNonEmptyString(value.blobId) &&
    isNonEmptyString(value.feedId) &&
    isNonEmptyString(value.issuerId) &&
    isSafeNonNegativeInteger(value.feedSeq) &&
    isNonEmptyString(value.findingId) &&
    isNonEmptyString(value.mediaType) &&
    isSafeNonNegativeInteger(value.byteLength) &&
    (value.publish === undefined || isDurablePublishMetadata(value.publish))
  );
}

function isDurablePublishMetadata(value: unknown): value is DurablePublishMetadata {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, DURABLE_PUBLISH_METADATA_KEYS) &&
    (value.uri === undefined || isNonEmptyString(value.uri)) &&
    (value.publishedAt === undefined || isSafeNonNegativeInteger(value.publishedAt)) &&
    (value.notaryRecordId === undefined || typeof value.notaryRecordId === "string") &&
    (value.notaryEnvelopeHash === undefined || isProtocolDigest(value.notaryEnvelopeHash)) &&
    (value.witnessProofs === undefined ||
      (Array.isArray(value.witnessProofs) &&
        value.witnessProofs.every((entry) => isWitnessProofRef(entry))))
  );
}

function isWitnessProofRef(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, WITNESS_PROOF_REF_KEYS) &&
    typeof value.provider === "string" &&
    (WITNESS_PROOF_PROVIDERS as readonly string[]).includes(value.provider) &&
    isProtocolDigest(value.digest) &&
    (value.uri === undefined || typeof value.uri === "string")
  );
}

function requireFetchUri(publish: DurablePublishMetadata | undefined, label: string): string {
  const uri = publish?.uri?.trim();
  if (!uri) {
    throw new Error(`[swarm-blob-client] ${label} is missing a usable fetch URI`);
  }

  const validation = validateFleetUrl(uri);
  if (!validation.valid) {
    throw new Error(
      `[swarm-blob-client] ${label} is missing a usable fetch URI: ${validation.reason}`,
    );
  }

  return uri;
}

function normalizeHushdUrl(hushdUrl: string): string {
  const normalized = hushdUrl.trim().replace(/\/+$/, "");
  if (!normalized) {
    throw new Error("[swarm-blob-client] hushd URL is required");
  }

  const validation = validateFleetUrl(normalized);
  if (!validation.valid) {
    throw new Error(`[swarm-blob-client] invalid hushd URL: ${validation.reason}`);
  }

  return normalized;
}

function proxyHushdUrl(absoluteUrl: string): string {
  if (!DEV) return absoluteUrl;

  try {
    const parsed = new URL(absoluteUrl);
    return `/_proxy/hushd${parsed.pathname}${parsed.search}`;
  } catch {
    return absoluteUrl;
  }
}

function createHushdHeaders(apiKey?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }

  return headers;
}

async function fetchJson(
  url: string,
  init: RequestInit & SwarmBlobClientFetchOptions,
): Promise<unknown> {
  const response = await runFetch(url, init);
  assertContentLengthWithinLimit(response, MAX_JSON_RESPONSE_BYTES, "JSON response");
  const bytes = await readResponseBytesWithLimit(
    response,
    MAX_JSON_RESPONSE_BYTES,
    "JSON response",
  );
  const text = new TextDecoder().decode(bytes);

  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid JSON";
    throw new Error(`[swarm-blob-client] invalid JSON response: ${message}`);
  }
}

async function fetchBytes(
  url: string,
  init: RequestInit & SwarmBlobClientFetchOptions,
): Promise<Uint8Array> {
  const response = await runFetch(url, init);
  assertContentLengthWithinLimit(
    response,
    MAX_ARTIFACT_RESPONSE_BYTES,
    "artifact response",
  );
  return readResponseBytesWithLimit(
    response,
    MAX_ARTIFACT_RESPONSE_BYTES,
    "artifact response",
  );
}

async function runFetch(
  url: string,
  init: RequestInit & SwarmBlobClientFetchOptions,
): Promise<Response> {
  const { fetchImpl, ...requestInit } = init;
  const fetchFn = fetchImpl ?? httpFetch;
  const response = await fetchFn(url, requestInit);

  if (!response.ok) {
    throw new Error(`[swarm-blob-client] request failed with HTTP ${response.status}`);
  }

  return response;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function hasOnlyKeys<T extends string>(value: Record<string, unknown>, allowedKeys: readonly T[]): boolean {
  return Object.keys(value).every((key) => (allowedKeys as readonly string[]).includes(key));
}

function assertByteLengthWithinLimit(
  byteLength: number,
  maxBytes: number,
  label: string,
): void {
  if (byteLength > maxBytes) {
    throw new Error(
      `[swarm-blob-client] ${label} too large (${byteLength} bytes exceeds ${maxBytes} limit)`,
    );
  }
}

function assertContentLengthWithinLimit(
  response: Response,
  maxBytes: number,
  label: string,
): void {
  const contentLength = response.headers.get("Content-Length");
  if (!contentLength) {
    return;
  }

  const parsed = Number.parseInt(contentLength, 10);
  if (Number.isFinite(parsed) && parsed > maxBytes) {
    throw new Error(
      `[swarm-blob-client] ${label} too large (${parsed} bytes exceeds ${maxBytes} limit)`,
    );
  }
}

async function readResponseBytesWithLimit(
  response: Response,
  maxBytes: number,
  label: string,
): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    assertByteLengthWithinLimit(bytes.byteLength, maxBytes, label);
    return bytes;
  }

  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (!value) {
      continue;
    }

    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error(
        `[swarm-blob-client] ${label} too large (${total} bytes exceeds ${maxBytes} limit)`,
      );
    }

    chunks.push(Uint8Array.from(value));
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return combined;
}
