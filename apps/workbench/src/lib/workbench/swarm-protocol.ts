/**
 * Canonical Sentinel Swarm protocol objects and hashing helpers.
 *
 * Task #2 freezes JSON-safe, versioned payload shapes without wiring them into
 * any transport yet. Objects stay plain JSON so they can converge with a
 * future `@backbay/witness` verifier instead of relying on ad hoc hashing.
 */

export const SWARM_PROTOCOL_VERSION = "v1" as const;

const SWARM_PROTOCOL_NAMESPACE = "clawdstrike.swarm" as const;

export const FINDING_ENVELOPE_SCHEMA =
  `${SWARM_PROTOCOL_NAMESPACE}.finding_envelope.${SWARM_PROTOCOL_VERSION}` as const;
export const FINDING_BLOB_SCHEMA =
  `${SWARM_PROTOCOL_NAMESPACE}.finding_blob.${SWARM_PROTOCOL_VERSION}` as const;
export const HEAD_ANNOUNCEMENT_SCHEMA =
  `${SWARM_PROTOCOL_NAMESPACE}.head_announcement.${SWARM_PROTOCOL_VERSION}` as const;
export const REVOCATION_ENVELOPE_SCHEMA =
  `${SWARM_PROTOCOL_NAMESPACE}.revocation_envelope.${SWARM_PROTOCOL_VERSION}` as const;
export const HUB_CONFIG_SCHEMA =
  `${SWARM_PROTOCOL_NAMESPACE}.hub_config.${SWARM_PROTOCOL_VERSION}` as const;

export const SWARM_PROTOCOL_COMPATIBILITY = Object.freeze({
  canonicalization: "plain-json-sorted-keys-v1",
  digestAlgorithm: "sha-256",
  digestEncoding: "0x-lower-hex",
  intendedVerifier: "@backbay/witness",
});

export const SWARM_PROTOCOL_HASH_PROFILE = Object.freeze({
  id: "witness-json-sha256-v1",
  canonicalization: SWARM_PROTOCOL_COMPATIBILITY.canonicalization,
  hashAlgorithm: "sha256",
  digestFormat: "0x-prefixed-lowercase-hex",
  stripsFields: ["payload.publish", "blobRefs[].publish", "artifacts[].publish"] as const,
  targetCompatibility: SWARM_PROTOCOL_COMPATIBILITY.intendedVerifier,
});

export type SwarmProtocolSchema =
  | typeof FINDING_ENVELOPE_SCHEMA
  | typeof FINDING_BLOB_SCHEMA
  | typeof HEAD_ANNOUNCEMENT_SCHEMA
  | typeof REVOCATION_ENVELOPE_SCHEMA
  | typeof HUB_CONFIG_SCHEMA;

export type ProtocolDigest = `0x${string}`;

export type ProtocolJsonPrimitive = string | number | boolean | null;
export type ProtocolJsonValue =
  | ProtocolJsonPrimitive
  | ProtocolJsonObject
  | ProtocolJsonValue[];

export interface ProtocolJsonObject {
  [key: string]: ProtocolJsonValue;
}

export type ProtocolSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingEnvelopeStatus =
  | "emerging"
  | "confirmed"
  | "promoted"
  | "dismissed"
  | "false_positive"
  | "archived";

const PROTOCOL_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const FINDING_ENVELOPE_STATUSES = [
  "emerging",
  "confirmed",
  "promoted",
  "dismissed",
  "false_positive",
  "archived",
] as const;
const FINDING_BLOB_ARTIFACT_KINDS = [
  "receipt",
  "transcript",
  "screenshot",
  "network_log",
  "file",
  "json",
] as const;
const WITNESS_PROOF_PROVIDERS = ["witness", "notary", "spine", "other"] as const;
const REVOCATION_ACTIONS = ["revoke", "supersede"] as const;
const SWARM_PROTOCOL_SCHEMAS = [
  FINDING_ENVELOPE_SCHEMA,
  FINDING_BLOB_SCHEMA,
  HEAD_ANNOUNCEMENT_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
  HUB_CONFIG_SCHEMA,
] as const;
const TARGET_REFERENCE_SCHEMAS = [
  FINDING_ENVELOPE_SCHEMA,
  FINDING_BLOB_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
] as const;
const ISSUER_ID_PREFIX = "aegis:ed25519:" as const;
const HEX_64_RE = /^[0-9a-f]{64}$/;
const HEX_128_RE = /^[0-9a-f]{128}$/;

const PROTOCOL_ATTESTATION_KEYS = ["algorithm", "publicKey", "signature"] as const;
const WITNESS_PROOF_REF_KEYS = ["provider", "digest", "uri"] as const;
const DURABLE_PUBLISH_METADATA_KEYS = [
  "uri",
  "publishedAt",
  "notaryRecordId",
  "notaryEnvelopeHash",
  "witnessProofs",
] as const;
const FINDING_BLOB_REF_KEYS = ["blobId", "digest", "mediaType", "byteLength", "publish"] as const;
const FINDING_ENVELOPE_KEYS = [
  "schema",
  "findingId",
  "issuerId",
  "feedId",
  "feedSeq",
  "publishedAt",
  "title",
  "summary",
  "severity",
  "confidence",
  "status",
  "signalCount",
  "tags",
  "relatedFindingIds",
  "blobRefs",
  "attestation",
  "publish",
] as const;
const FINDING_BLOB_ARTIFACT_KEYS = [
  "artifactId",
  "kind",
  "mediaType",
  "digest",
  "byteLength",
  "name",
  "publish",
] as const;
const FINDING_BLOB_KEYS = [
  "schema",
  "blobId",
  "findingId",
  "issuerId",
  "createdAt",
  "manifest",
  "artifacts",
  "proofRefs",
  "publish",
] as const;
const HEAD_ANNOUNCEMENT_CHECKPOINT_REF_KEYS = [
  "logId",
  "checkpointSeq",
  "envelopeHash",
] as const;
const HEAD_ANNOUNCEMENT_KEYS = [
  "schema",
  "factId",
  "feedId",
  "issuerId",
  "headSeq",
  "headEnvelopeHash",
  "entryCount",
  "checkpointRef",
  "announcedAt",
] as const;
const PROTOCOL_TARGET_REFERENCE_KEYS = ["schema", "id", "digest"] as const;
const REVOCATION_ENVELOPE_KEYS = [
  "schema",
  "revocationId",
  "issuerId",
  "feedId",
  "feedSeq",
  "issuedAt",
  "action",
  "target",
  "replacement",
  "reason",
  "attestation",
  "publish",
] as const;
const HUB_ENDPOINT_KEYS = ["id", "url", "protocols"] as const;
const HUB_REPLAY_CONFIG_KEYS = ["maxEntriesPerSync", "checkpointInterval", "retentionMs"] as const;
const HUB_BLOB_CONFIG_KEYS = ["maxInlineBytes", "requireDigest", "providers"] as const;
const HUB_TRUST_POLICY_KEYS = [
  "trustedIssuers",
  "blockedIssuers",
  "requireAttestation",
  "requireWitnessProofs",
  "allowedSchemas",
] as const;
const HUB_CONFIG_KEYS = [
  "schema",
  "hubId",
  "displayName",
  "updatedAt",
  "bootstrapPeers",
  "relayPeers",
  "replay",
  "blobs",
  "trustPolicy",
] as const;

export interface ProtocolAttestation {
  algorithm: "ed25519";
  publicKey: string;
  signature: string;
}

export interface WitnessProofRef {
  provider: "witness" | "notary" | "spine" | "other";
  digest: ProtocolDigest;
  uri?: string;
}

export interface DurablePublishMetadata {
  uri?: string;
  publishedAt?: number;
  notaryRecordId?: string;
  notaryEnvelopeHash?: ProtocolDigest;
  witnessProofs?: WitnessProofRef[];
}

export interface FindingBlobRef {
  blobId: string;
  digest: ProtocolDigest;
  mediaType: string;
  byteLength: number;
  publish?: DurablePublishMetadata;
}

export interface FindingEnvelope {
  schema: typeof FINDING_ENVELOPE_SCHEMA;
  findingId: string;
  issuerId: string;
  feedId: string;
  feedSeq: number;
  publishedAt: number;
  title: string;
  summary: string;
  severity: ProtocolSeverity;
  confidence: number;
  status: FindingEnvelopeStatus;
  signalCount: number;
  tags: string[];
  relatedFindingIds?: string[];
  blobRefs: FindingBlobRef[];
  attestation?: ProtocolAttestation;
  publish?: DurablePublishMetadata;
}

export type FindingBlobArtifactKind =
  | "receipt"
  | "transcript"
  | "screenshot"
  | "network_log"
  | "file"
  | "json";

export interface FindingBlobArtifact {
  artifactId: string;
  kind: FindingBlobArtifactKind;
  mediaType: string;
  digest: ProtocolDigest;
  byteLength: number;
  name?: string;
  publish?: DurablePublishMetadata;
}

export interface FindingBlob {
  schema: typeof FINDING_BLOB_SCHEMA;
  blobId: string;
  findingId: string;
  issuerId: string;
  createdAt: number;
  manifest: ProtocolJsonObject;
  artifacts: FindingBlobArtifact[];
  proofRefs?: WitnessProofRef[];
  publish?: DurablePublishMetadata;
}

export interface HeadAnnouncementCheckpointRef {
  logId: string;
  checkpointSeq: number;
  envelopeHash: ProtocolDigest;
}

export interface HeadAnnouncement {
  schema: typeof HEAD_ANNOUNCEMENT_SCHEMA;
  factId: string;
  feedId: string;
  issuerId: string;
  headSeq: number;
  headEnvelopeHash: ProtocolDigest;
  entryCount: number;
  checkpointRef?: HeadAnnouncementCheckpointRef;
  announcedAt: number;
}

export interface ProtocolTargetReference {
  schema:
    | typeof FINDING_ENVELOPE_SCHEMA
    | typeof FINDING_BLOB_SCHEMA
    | typeof REVOCATION_ENVELOPE_SCHEMA;
  id: string;
  digest?: ProtocolDigest;
}

export interface RevocationEnvelope {
  schema: typeof REVOCATION_ENVELOPE_SCHEMA;
  revocationId: string;
  issuerId: string;
  feedId: string;
  feedSeq: number;
  issuedAt: number;
  action: "revoke" | "supersede";
  target: ProtocolTargetReference;
  replacement?: ProtocolTargetReference;
  reason: string;
  attestation?: ProtocolAttestation;
  publish?: DurablePublishMetadata;
}

export interface HubEndpoint {
  id: string;
  url: string;
  protocols: string[];
}

export interface HubReplayConfig {
  maxEntriesPerSync: number;
  checkpointInterval: number;
  retentionMs: number;
}

export interface HubBlobConfig {
  maxInlineBytes: number;
  requireDigest: boolean;
  providers: HubEndpoint[];
}

export interface HubTrustPolicy {
  trustedIssuers: string[];
  blockedIssuers: string[];
  requireAttestation: boolean;
  requireWitnessProofs: boolean;
  allowedSchemas: SwarmProtocolSchema[];
}

export interface HubConfig {
  schema: typeof HUB_CONFIG_SCHEMA;
  hubId: string;
  displayName: string;
  updatedAt: number;
  bootstrapPeers: HubEndpoint[];
  relayPeers: HubEndpoint[];
  replay: HubReplayConfig;
  blobs: HubBlobConfig;
  trustPolicy: HubTrustPolicy;
}

export type SwarmProtocolPayload =
  | FindingEnvelope
  | FindingBlob
  | HeadAnnouncement
  | RevocationEnvelope
  | HubConfig;

export interface FindingEnvelopeSignableFields
  extends Omit<FindingEnvelope, "attestation" | "publish" | "blobRefs"> {
  blobRefs: Array<Omit<FindingBlobRef, "publish">>;
}

export interface RevocationEnvelopeSignableFields
  extends Omit<RevocationEnvelope, "attestation" | "publish"> {}

export interface CreateHeadAnnouncementInput {
  factId: string;
  entryCount: number;
  head: FindingEnvelope | RevocationEnvelope;
  checkpointRef?: HeadAnnouncementCheckpointRef;
  announcedAt?: number;
}

export function serializeProtocolPayload(payload: SwarmProtocolPayload | ProtocolJsonValue): string {
  const normalized = normalizeProtocolJson(payload);
  return canonicalizeNormalizedJson(normalized);
}

export async function hashProtocolPayload(
  payload: SwarmProtocolPayload | ProtocolJsonValue,
): Promise<ProtocolDigest> {
  const hashable = normalizeHashablePayload(payload);
  const canonical = canonicalizeNormalizedJson(hashable);
  const encoded = new TextEncoder().encode(canonical);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Bun/@types mismatch
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded as any);
  const digest = Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `0x${digest}`;
}

export function extractFindingEnvelopeSignableFields(
  envelope: FindingEnvelope,
): FindingEnvelopeSignableFields {
  const normalized = normalizeHashablePayload(envelope);
  if (!isFindingEnvelope(normalized)) {
    throw new TypeError("Invalid FindingEnvelope");
  }
  const validated = normalized as FindingEnvelope;
  const { attestation, ...rest } = validated;
  return rest;
}

export function extractRevocationEnvelopeSignableFields(
  envelope: RevocationEnvelope,
): RevocationEnvelopeSignableFields {
  const normalized = normalizeHashablePayload(envelope);
  if (!isRevocationEnvelope(normalized)) {
    throw new TypeError("Invalid RevocationEnvelope");
  }
  const validated = normalized as RevocationEnvelope;
  const { attestation, ...rest } = validated;
  return rest;
}

export async function createHeadAnnouncement(
  input: CreateHeadAnnouncementInput,
): Promise<HeadAnnouncement> {
  const head = assertHeadPayload(input.head);
  return {
    schema: HEAD_ANNOUNCEMENT_SCHEMA,
    factId: input.factId,
    feedId: head.feedId,
    issuerId: head.issuerId,
    headSeq: head.feedSeq,
    headEnvelopeHash: await hashProtocolPayload(head),
    entryCount: input.entryCount,
    checkpointRef: input.checkpointRef,
    announcedAt: input.announcedAt ?? Date.now(),
  };
}

export function isProtocolDigest(value: unknown): value is ProtocolDigest {
  return typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value);
}

export function isFindingEnvelope(value: unknown): value is FindingEnvelope {
  if (!isRecord(value) || value.schema !== FINDING_ENVELOPE_SCHEMA) {
    return false;
  }

  if (!hasOnlyKeys(value, FINDING_ENVELOPE_KEYS)) {
    return false;
  }

  const attestation = value.attestation;
  return (
    isNonEmptyString(value.findingId) &&
    isProtocolIssuerId(value.issuerId) &&
    isNonEmptyString(value.feedId) &&
    isSafeNonNegativeInteger(value.feedSeq) &&
    isSafeNonNegativeInteger(value.publishedAt) &&
    isNonEmptyString(value.title) &&
    isNonEmptyString(value.summary) &&
    isOneOf(value.severity, PROTOCOL_SEVERITIES) &&
    isUnitIntervalNumber(value.confidence) &&
    isOneOf(value.status, FINDING_ENVELOPE_STATUSES) &&
    isSafeNonNegativeInteger(value.signalCount) &&
    isStringArray(value.tags) &&
    (value.relatedFindingIds === undefined || isStringArray(value.relatedFindingIds)) &&
    Array.isArray(value.blobRefs) &&
    value.blobRefs.every((entry) => isFindingBlobRef(entry)) &&
    (attestation === undefined || isProtocolAttestation(attestation)) &&
    matchesIssuerAttestation(value.issuerId, attestation) &&
    (value.publish === undefined || isDurablePublishMetadata(value.publish))
  );
}

export function isFindingBlob(value: unknown): value is FindingBlob {
  if (!isRecord(value) || value.schema !== FINDING_BLOB_SCHEMA) {
    return false;
  }

  if (!hasOnlyKeys(value, FINDING_BLOB_KEYS)) {
    return false;
  }

  return (
    isNonEmptyString(value.blobId) &&
    isNonEmptyString(value.findingId) &&
    isProtocolIssuerId(value.issuerId) &&
    isSafeNonNegativeInteger(value.createdAt) &&
    isProtocolJsonObjectValue(value.manifest) &&
    Array.isArray(value.artifacts) &&
    value.artifacts.every((entry) => isFindingBlobArtifact(entry)) &&
    (value.proofRefs === undefined ||
      (Array.isArray(value.proofRefs) && value.proofRefs.every((entry) => isWitnessProofRef(entry)))) &&
    (value.publish === undefined || isDurablePublishMetadata(value.publish))
  );
}

export function isHeadAnnouncement(value: unknown): value is HeadAnnouncement {
  if (!isRecord(value) || value.schema !== HEAD_ANNOUNCEMENT_SCHEMA) {
    return false;
  }

  if (!hasOnlyKeys(value, HEAD_ANNOUNCEMENT_KEYS)) {
    return false;
  }

  return (
    isNonEmptyString(value.factId) &&
    isNonEmptyString(value.feedId) &&
    isProtocolIssuerId(value.issuerId) &&
    isSafeNonNegativeInteger(value.headSeq) &&
    isProtocolDigest(value.headEnvelopeHash) &&
    isSafeNonNegativeInteger(value.entryCount) &&
    isSafeNonNegativeInteger(value.announcedAt) &&
    (value.checkpointRef === undefined || isHeadAnnouncementCheckpointRef(value.checkpointRef))
  );
}

export function isRevocationEnvelope(value: unknown): value is RevocationEnvelope {
  if (!isRecord(value) || value.schema !== REVOCATION_ENVELOPE_SCHEMA) {
    return false;
  }

  if (!hasOnlyKeys(value, REVOCATION_ENVELOPE_KEYS)) {
    return false;
  }

  const attestation = value.attestation;
  const replacementValid =
    value.replacement === undefined || isProtocolTargetReference(value.replacement);

  return (
    isNonEmptyString(value.revocationId) &&
    isProtocolIssuerId(value.issuerId) &&
    isNonEmptyString(value.feedId) &&
    isSafeNonNegativeInteger(value.feedSeq) &&
    isSafeNonNegativeInteger(value.issuedAt) &&
    isOneOf(value.action, REVOCATION_ACTIONS) &&
    isProtocolTargetReference(value.target) &&
    replacementValid &&
    ((value.action === "supersede" && value.replacement !== undefined) ||
      (value.action === "revoke" && value.replacement === undefined)) &&
    isNonEmptyString(value.reason) &&
    (attestation === undefined || isProtocolAttestation(attestation)) &&
    matchesIssuerAttestation(value.issuerId, attestation) &&
    (value.publish === undefined || isDurablePublishMetadata(value.publish))
  );
}

export function isHubConfig(value: unknown): value is HubConfig {
  if (!isRecord(value) || value.schema !== HUB_CONFIG_SCHEMA) {
    return false;
  }

  if (!hasOnlyKeys(value, HUB_CONFIG_KEYS)) {
    return false;
  }

  return (
    isNonEmptyString(value.hubId) &&
    isNonEmptyString(value.displayName) &&
    isSafeNonNegativeInteger(value.updatedAt) &&
    Array.isArray(value.bootstrapPeers) &&
    value.bootstrapPeers.every((entry) => isHubEndpoint(entry)) &&
    Array.isArray(value.relayPeers) &&
    value.relayPeers.every((entry) => isHubEndpoint(entry)) &&
    isHubReplayConfig(value.replay) &&
    isHubBlobConfig(value.blobs) &&
    isHubTrustPolicy(value.trustPolicy)
  );
}

function normalizeProtocolJson(value: unknown, path = "$"): ProtocolJsonValue {
  if (value === null) {
    return null;
  }

  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${path} must be a finite number`);
    }
    return value;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      if (!(index in value)) {
        throw new TypeError(`${path}[${index}] cannot be undefined; sparse arrays are not supported`);
      }
    }
    return value.map((entry, index) => normalizeProtocolJson(entry, `${path}[${index}]`));
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be plain JSON`);
    }

    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError(`${path} must not contain symbol keys`);
    }

    const result: ProtocolJsonObject = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const entry = (value as Record<string, unknown>)[key];
      if (entry === undefined) {
        throw new TypeError(`${path}.${key} cannot be undefined; omit optional fields instead`);
      }
      result[key] = normalizeProtocolJson(entry, `${path}.${key}`);
    }
    return result;
  }

  throw new TypeError(`${path} must be plain JSON`);
}

function canonicalizeNormalizedJson(value: ProtocolJsonValue): string {
  if (value === null) {
    return "null";
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalizeNormalizedJson(entry)).join(",")}]`;
  }

  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeNormalizedJson(value[key])}`)
    .join(",")}}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isSafePositiveInteger(value: unknown): value is number {
  return isSafeNonNegativeInteger(value) && value > 0;
}

function isUnitIntervalNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value);
}

function isProtocolAttestation(value: unknown): value is ProtocolAttestation {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, PROTOCOL_ATTESTATION_KEYS) &&
    value.algorithm === "ed25519" &&
    isEd25519PublicKey(value.publicKey) &&
    typeof value.signature === "string" &&
    HEX_128_RE.test(value.signature)
  );
}

function isWitnessProofRef(value: unknown): value is WitnessProofRef {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, WITNESS_PROOF_REF_KEYS) &&
    isOneOf(value.provider, WITNESS_PROOF_PROVIDERS) &&
    isProtocolDigest(value.digest) &&
    (value.uri === undefined || typeof value.uri === "string")
  );
}

function isDurablePublishMetadata(value: unknown): value is DurablePublishMetadata {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, DURABLE_PUBLISH_METADATA_KEYS) &&
    (value.uri === undefined || typeof value.uri === "string") &&
    (value.publishedAt === undefined || isSafeNonNegativeInteger(value.publishedAt)) &&
    (value.notaryRecordId === undefined || typeof value.notaryRecordId === "string") &&
    (value.notaryEnvelopeHash === undefined || isProtocolDigest(value.notaryEnvelopeHash)) &&
    (value.witnessProofs === undefined ||
      (Array.isArray(value.witnessProofs) && value.witnessProofs.every((entry) => isWitnessProofRef(entry))))
  );
}

function isFindingBlobRef(value: unknown): value is FindingBlobRef {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, FINDING_BLOB_REF_KEYS) &&
    isNonEmptyString(value.blobId) &&
    isProtocolDigest(value.digest) &&
    isNonEmptyString(value.mediaType) &&
    isSafeNonNegativeInteger(value.byteLength) &&
    (value.publish === undefined || isDurablePublishMetadata(value.publish))
  );
}

function isFindingBlobArtifact(value: unknown): value is FindingBlobArtifact {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, FINDING_BLOB_ARTIFACT_KEYS) &&
    isNonEmptyString(value.artifactId) &&
    isOneOf(value.kind, FINDING_BLOB_ARTIFACT_KINDS) &&
    isNonEmptyString(value.mediaType) &&
    isProtocolDigest(value.digest) &&
    isSafeNonNegativeInteger(value.byteLength) &&
    (value.name === undefined || typeof value.name === "string") &&
    (value.publish === undefined || isDurablePublishMetadata(value.publish))
  );
}

function isHeadAnnouncementCheckpointRef(value: unknown): value is HeadAnnouncementCheckpointRef {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, HEAD_ANNOUNCEMENT_CHECKPOINT_REF_KEYS) &&
    isNonEmptyString(value.logId) &&
    isSafeNonNegativeInteger(value.checkpointSeq) &&
    isProtocolDigest(value.envelopeHash)
  );
}

function isSwarmProtocolSchema(value: unknown): value is SwarmProtocolSchema {
  return isOneOf(value, SWARM_PROTOCOL_SCHEMAS);
}

function isProtocolTargetReference(value: unknown): value is ProtocolTargetReference {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, PROTOCOL_TARGET_REFERENCE_KEYS) &&
    isOneOf(value.schema, TARGET_REFERENCE_SCHEMAS) &&
    isNonEmptyString(value.id) &&
    (value.digest === undefined || isProtocolDigest(value.digest))
  );
}

function isHubEndpoint(value: unknown): value is HubEndpoint {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, HUB_ENDPOINT_KEYS) &&
    isNonEmptyString(value.id) &&
    isNonEmptyString(value.url) &&
    isStringArray(value.protocols)
  );
}

function isHubReplayConfig(value: unknown): value is HubReplayConfig {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, HUB_REPLAY_CONFIG_KEYS) &&
    isSafePositiveInteger(value.maxEntriesPerSync) &&
    isSafePositiveInteger(value.checkpointInterval) &&
    isSafeNonNegativeInteger(value.retentionMs)
  );
}

function isHubBlobConfig(value: unknown): value is HubBlobConfig {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, HUB_BLOB_CONFIG_KEYS) &&
    isSafeNonNegativeInteger(value.maxInlineBytes) &&
    typeof value.requireDigest === "boolean" &&
    Array.isArray(value.providers) &&
    value.providers.every((entry) => isHubEndpoint(entry))
  );
}

export function isHubTrustPolicy(value: unknown): value is HubTrustPolicy {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, HUB_TRUST_POLICY_KEYS) &&
    isIssuerIdArray(value.trustedIssuers) &&
    isIssuerIdArray(value.blockedIssuers) &&
    typeof value.requireAttestation === "boolean" &&
    typeof value.requireWitnessProofs === "boolean" &&
    Array.isArray(value.allowedSchemas) &&
    value.allowedSchemas.every((entry) => isSwarmProtocolSchema(entry))
  );
}

function isProtocolJsonObjectValue(value: unknown): value is ProtocolJsonObject {
  if (!isRecord(value)) {
    return false;
  }

  try {
    const normalized = normalizeProtocolJson(value);
    return typeof normalized === "object" && normalized !== null && !Array.isArray(normalized);
  } catch {
    return false;
  }
}

function normalizeHashablePayload(payload: SwarmProtocolPayload | ProtocolJsonValue): ProtocolJsonValue {
  const normalized = normalizeProtocolJson(payload);
  if (!isRecord(normalized) || !("schema" in normalized)) {
    return normalized;
  }

  if (!isSwarmProtocolSchema(normalized.schema)) {
    return normalized;
  }

  switch (normalized.schema) {
    case FINDING_ENVELOPE_SCHEMA:
      if (!isFindingEnvelope(normalized)) {
        throw new TypeError("Invalid FindingEnvelope payload");
      }
      return {
        ...omitKey(normalized, "publish"),
        blobRefs: normalized.blobRefs.map((entry) => omitKey(entry, "publish")),
      };
    case FINDING_BLOB_SCHEMA:
      if (!isFindingBlob(normalized)) {
        throw new TypeError("Invalid FindingBlob payload");
      }
      return {
        ...omitKey(normalized, "publish"),
        artifacts: normalized.artifacts.map((entry) => omitKey(entry, "publish")),
      };
    case REVOCATION_ENVELOPE_SCHEMA:
      if (!isRevocationEnvelope(normalized)) {
        throw new TypeError("Invalid RevocationEnvelope payload");
      }
      return omitKey(normalized, "publish");
    case HEAD_ANNOUNCEMENT_SCHEMA:
      if (!isHeadAnnouncement(normalized)) {
        throw new TypeError("Invalid HeadAnnouncement payload");
      }
      return normalized;
    case HUB_CONFIG_SCHEMA:
      if (!isHubConfig(normalized)) {
        throw new TypeError("Invalid HubConfig payload");
      }
      return normalized;
  }
}

function omitKey<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const { [key]: _, ...rest } = value;
  return rest;
}

function hasOnlyKeys<T extends string>(value: Record<string, unknown>, allowedKeys: readonly T[]): boolean {
  return Object.keys(value).every((key) => (allowedKeys as readonly string[]).includes(key));
}

function isEd25519PublicKey(value: unknown): value is string {
  return typeof value === "string" && HEX_64_RE.test(value);
}

function isProtocolIssuerId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.startsWith(ISSUER_ID_PREFIX) &&
    isEd25519PublicKey(value.slice(ISSUER_ID_PREFIX.length))
  );
}

export function issuerIdFromPublicKey(publicKey: string): string {
  return `${ISSUER_ID_PREFIX}${publicKey}`;
}

export function matchesIssuerAttestation(
  issuerId: string,
  attestation: ProtocolAttestation | undefined,
): boolean {
  return attestation === undefined || issuerId === issuerIdFromPublicKey(attestation.publicKey);
}

function isIssuerIdArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => isProtocolIssuerId(entry));
}

function assertHeadPayload(value: unknown): FindingEnvelope | RevocationEnvelope {
  if (isFindingEnvelope(value) || isRevocationEnvelope(value)) {
    return value;
  }
  throw new TypeError("Head announcement requires a valid finding or revocation envelope");
}
