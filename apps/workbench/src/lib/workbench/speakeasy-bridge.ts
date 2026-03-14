/**
 * Speakeasy Bridge — Integration layer between @backbay/speakeasy and
 * Clawdstrike's domain types for the Sentinel Swarm.
 *
 * This is a pure-function + class module (no React). It bridges Speakeasy's
 * messaging primitives with Clawdstrike's domain model for intel sharing,
 * finding coordination, sentinel status, and trust management.
 *
 * @see docs/plans/sentinel-swarm/SPEAKEASY-INTEGRATION.md
 */

import type {
  SentinelIdentity,
  SentinelMode,
  SentinelStatus as SentinelLifecycleStatus,
  FindingStatus,
  Severity,
  SignalType,
  IntelType,
  IntelShareability,
  SpeakeasyPurpose,
  SpeakeasyClassification,
  ClawdstrikeSpeakeasy,
  SpeakeasyMember,
  Intel,
  Sentinel,
} from "./sentinel-types";
import { canonicalizeJson } from "./operator-crypto";
import { computeContentHash } from "./intel-forge";
import type { OperatorIdentity } from "./operator-types";
import {
  ED25519_PUBLIC_KEY_HEX,
  ED25519_SIGNATURE_HEX,
  signDetachedPayload,
  verifyDetachedPayload,
} from "./signature-adapter";

const TOPIC_PREFIX = "/baychat/v1";

export const CLAWDSTRIKE_MESSAGE_TYPES = [
  "intel_share",
  "intel_ack",
  "finding_update",
  "signal_alert",
  "sentinel_status",
  "sentinel_task",
  "reputation_vote",
  "room_metadata",
  "detection_sync",
] as const;

export type ClawdstrikeMessageType = (typeof CLAWDSTRIKE_MESSAGE_TYPES)[number];

const DEFAULT_TTL: Record<ClawdstrikeMessageType, number> = {
  intel_share: 10,
  intel_ack: 5,
  finding_update: 5,
  signal_alert: 3,
  sentinel_status: 5,
  sentinel_task: 5,
  reputation_vote: 5,
  room_metadata: 5,
  detection_sync: 10,
};

export const MESSAGE_TYPE_MAX_AGE: Record<ClawdstrikeMessageType, number> = {
  intel_share: 30 * 60_000,
  intel_ack: 15 * 60_000,
  finding_update: 15 * 60_000,
  signal_alert: 2 * 60_000,
  sentinel_status: 5 * 60_000,
  sentinel_task: 10 * 60_000,
  reputation_vote: 15 * 60_000,
  room_metadata: 15 * 60_000,
  detection_sync: 30 * 60_000,
};

const TIMESTAMP_TOLERANCE_MS = 5 * 60_000;
const NONCE_BYTES = 16;

export function operatorIdentityToBayChatIdentity(
  operator: OperatorIdentity,
  role: "moderator" | "participant" | "observer" = "participant",
): SpeakeasyMember {
  return {
    type: "operator",
    fingerprint: operator.fingerprint,
    displayName: operator.displayName,
    sigil: operator.sigil as SpeakeasyMember["sigil"],
    role,
    joinedAt: Date.now(),
  };
}

export interface ClawdstrikeBaseMessage {
  /** SHA-256 of the canonical JSON of the unsigned payload. */
  id: string;
  type: ClawdstrikeMessageType;
  sender: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

export interface IntelShareMessage extends ClawdstrikeBaseMessage {
  type: "intel_share";
  intelId: string;
  intelType: IntelType;
  title: string;
  /** Never raw evidence. */
  summary: string;
  contentHash: string;
  intelSignature: string;
  intelSignerPublicKey: string;
  confidence: number;
  mitreTechniques?: string[];
  tags: string[];
  shareability: "swarm" | "public";
  receiptJson?: string;
}

export interface IntelAckMessage extends ClawdstrikeBaseMessage {
  type: "intel_ack";
  intelId: string;
  action: "ingested" | "rejected" | "deferred";
  reason?: string;
}

export interface FindingUpdateMessage extends ClawdstrikeBaseMessage {
  type: "finding_update";
  findingId: string;
  status: FindingStatus;
  severity?: Severity;
  confidence?: number;
  annotation?: string;
  signalCount?: number;
}

export interface SignalAlertMessage extends ClawdstrikeBaseMessage {
  type: "signal_alert";
  signalId: string;
  signalType: SignalType;
  severity: "medium" | "high" | "critical";
  confidence: number;
  summary: string;
  sourceSentinelId?: string;
  sourceGuardId?: string;
  relatedFindingId?: string;
}

export interface SentinelStatusMessage extends ClawdstrikeBaseMessage {
  type: "sentinel_status";
  sentinelId: string;
  mode: SentinelMode;
  status: SentinelLifecycleStatus;
  activeGoals: number;
  recentSignalCount: number;
  recentFindingCount: number;
  policyHash?: string;
  version?: string;
}

export interface SentinelTaskMessage extends ClawdstrikeBaseMessage {
  type: "sentinel_task";
  /** '*' for any available sentinel. */
  targetSentinelId: string;
  taskType: "investigate" | "enrich" | "hunt" | "correlate" | "monitor";
  description: string;
  attachedTo?: string;
  priority: "low" | "normal" | "high" | "urgent";
  deadline?: number;
  delegationToken?: string;
}

export interface ReputationVoteMessage extends ClawdstrikeBaseMessage {
  type: "reputation_vote";
  targetFingerprint: string;
  vote: "positive" | "negative";
  category: "intel_quality" | "detection_efficacy" | "uptime" | "collaboration" | "general";
  reason: string;
  referenceId?: string;
}

export interface RoomMetadataMessage extends ClawdstrikeBaseMessage {
  type: "room_metadata";
  speakeasyId: string;
  purpose?: SpeakeasyPurpose;
  classification?: SpeakeasyClassification;
  attachedTo?: string | null;
  changeReason?: string;
}

export interface DetectionSyncMessage extends ClawdstrikeBaseMessage {
  type: "detection_sync";
  ruleId: string;
  action: "publish" | "update" | "deprecate";
  format: "sigma" | "yara" | "clawdstrike_pattern" | "policy_patch";
  content: string;
  contentHash: string;
  ruleVersion: number;
  authorFingerprint: string;
  confidence: number;
}

export type ClawdstrikeMessage =
  | IntelShareMessage
  | IntelAckMessage
  | FindingUpdateMessage
  | SignalAlertMessage
  | SentinelStatusMessage
  | SentinelTaskMessage
  | ReputationVoteMessage
  | RoomMetadataMessage
  | DetectionSyncMessage;

export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Bun vs @types/web ArrayBuffer mismatch
  const hashBuffer = await crypto.subtle.digest("SHA-256", data as any);
  return toHex(new Uint8Array(hashBuffer));
}

/** Hashes the full unsigned payload using canonical JSON. `id` and `signature` are excluded. */
export async function computeClawdstrikeMessageHash(
  message: Omit<ClawdstrikeBaseMessage, "signature" | "id"> & Record<string, unknown>,
): Promise<string> {
  return sha256Hex(canonicalizeJson(message));
}

export async function signClawdstrikeMessage<T>(
  content: T & { type: ClawdstrikeMessageType },
  senderPublicKey: string,
  secretKeyHex: string,
): Promise<T & ClawdstrikeBaseMessage> {
  const timestamp = Date.now();
  const nonce = generateNonce();

  const message = {
    ...content,
    sender: senderPublicKey,
    timestamp,
    nonce,
  };

  const hash = await computeClawdstrikeMessageHash(
    message as Omit<ClawdstrikeBaseMessage, "signature" | "id"> & Record<string, unknown>,
  );

  const hashBytes = new TextEncoder().encode(hash);
  const signature = await signDetachedPayload(hashBytes, secretKeyHex);

  return {
    ...message,
    id: hash,
    signature,
  } as T & ClawdstrikeBaseMessage;
}

export async function createIntelShareMessage(
  intel: Intel,
  senderPublicKey: string,
  secretKeyHex: string,
  opts?: { receiptJson?: string },
): Promise<IntelShareMessage> {
  return signClawdstrikeMessage(
    {
      type: "intel_share" as const,
      intelId: intel.id,
      intelType: intel.type,
      title: intel.title,
      summary: intel.description,
      contentHash: await computeContentHash(intel),
      intelSignature: intel.signature,
      intelSignerPublicKey: intel.signerPublicKey,
      confidence: intel.confidence,
      mitreTechniques: intel.mitre.map((m) => m.techniqueId),
      tags: intel.tags,
      shareability: intel.shareability === "private" ? "swarm" : intel.shareability,
      receiptJson: opts?.receiptJson,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createIntelAckMessage(
  intelId: string,
  action: IntelAckMessage["action"],
  senderPublicKey: string,
  secretKeyHex: string,
  reason?: string,
): Promise<IntelAckMessage> {
  return signClawdstrikeMessage(
    {
      type: "intel_ack" as const,
      intelId,
      action,
      reason,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createFindingUpdateMessage(
  findingId: string,
  status: FindingStatus,
  senderPublicKey: string,
  secretKeyHex: string,
  opts?: {
    severity?: Severity;
    confidence?: number;
    annotation?: string;
    signalCount?: number;
  },
): Promise<FindingUpdateMessage> {
  return signClawdstrikeMessage(
    {
      type: "finding_update" as const,
      findingId,
      status,
      severity: opts?.severity,
      confidence: opts?.confidence,
      annotation: opts?.annotation,
      signalCount: opts?.signalCount,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createSignalAlertMessage(
  signalId: string,
  signalType: SignalType,
  severity: SignalAlertMessage["severity"],
  confidence: number,
  summary: string,
  senderPublicKey: string,
  secretKeyHex: string,
  opts?: {
    sourceSentinelId?: string;
    sourceGuardId?: string;
    relatedFindingId?: string;
  },
): Promise<SignalAlertMessage> {
  return signClawdstrikeMessage(
    {
      type: "signal_alert" as const,
      signalId,
      signalType,
      severity,
      confidence,
      summary,
      sourceSentinelId: opts?.sourceSentinelId,
      sourceGuardId: opts?.sourceGuardId,
      relatedFindingId: opts?.relatedFindingId,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createSentinelStatusMessage(
  sentinel: Pick<Sentinel, "id" | "mode" | "status" | "goals" | "identity">,
  secretKeyHex: string,
  metrics?: {
    recentSignalCount?: number;
    recentFindingCount?: number;
    policyHash?: string;
    version?: string;
  },
): Promise<SentinelStatusMessage> {
  return signClawdstrikeMessage(
    {
      type: "sentinel_status" as const,
      sentinelId: sentinel.id,
      mode: sentinel.mode,
      status: sentinel.status,
      activeGoals: sentinel.goals.length,
      recentSignalCount: metrics?.recentSignalCount ?? 0,
      recentFindingCount: metrics?.recentFindingCount ?? 0,
      policyHash: metrics?.policyHash,
      version: metrics?.version,
    },
    sentinel.identity.publicKey,
    secretKeyHex,
  );
}

export async function createSentinelTaskMessage(
  targetSentinelId: string,
  taskType: SentinelTaskMessage["taskType"],
  description: string,
  priority: SentinelTaskMessage["priority"],
  senderPublicKey: string,
  secretKeyHex: string,
  opts?: {
    attachedTo?: string;
    deadline?: number;
    delegationToken?: string;
  },
): Promise<SentinelTaskMessage> {
  return signClawdstrikeMessage(
    {
      type: "sentinel_task" as const,
      targetSentinelId,
      taskType,
      description,
      priority,
      attachedTo: opts?.attachedTo,
      deadline: opts?.deadline,
      delegationToken: opts?.delegationToken,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createReputationVoteMessage(
  targetFingerprint: string,
  vote: ReputationVoteMessage["vote"],
  category: ReputationVoteMessage["category"],
  reason: string,
  senderPublicKey: string,
  secretKeyHex: string,
  referenceId?: string,
): Promise<ReputationVoteMessage> {
  return signClawdstrikeMessage(
    {
      type: "reputation_vote" as const,
      targetFingerprint,
      vote,
      category,
      reason,
      referenceId,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createRoomMetadataMessage(
  speakeasyId: string,
  senderPublicKey: string,
  secretKeyHex: string,
  changes: {
    purpose?: SpeakeasyPurpose;
    classification?: SpeakeasyClassification;
    attachedTo?: string | null;
    changeReason?: string;
  },
): Promise<RoomMetadataMessage> {
  return signClawdstrikeMessage(
    {
      type: "room_metadata" as const,
      speakeasyId,
      purpose: changes.purpose,
      classification: changes.classification,
      attachedTo: changes.attachedTo,
      changeReason: changes.changeReason,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export async function createDetectionSyncMessage(
  ruleId: string,
  action: DetectionSyncMessage["action"],
  format: DetectionSyncMessage["format"],
  content: string,
  ruleVersion: number,
  confidence: number,
  senderPublicKey: string,
  secretKeyHex: string,
  authorFingerprint: string,
): Promise<DetectionSyncMessage> {
  return signClawdstrikeMessage(
    {
      type: "detection_sync" as const,
      ruleId,
      action,
      format,
      content,
      contentHash: await sha256Hex(content),
      ruleVersion,
      authorFingerprint,
      confidence,
    },
    senderPublicKey,
    secretKeyHex,
  );
}

export interface ClawdstrikeVerificationResult {
  valid: boolean;
  reason?: string;
}

const seenNonces = new Set<string>();
const MAX_SEEN_NONCES = 10_000;

function trackNonce(nonce: string): boolean {
  if (seenNonces.has(nonce)) return false;
  if (seenNonces.size >= MAX_SEEN_NONCES) {
    // Evict oldest entries — Set iteration order is insertion order
    const it = seenNonces.values();
    for (let i = 0; i < MAX_SEEN_NONCES / 2; i++) {
      const val = it.next().value;
      if (val !== undefined) seenNonces.delete(val);
    }
  }
  seenNonces.add(nonce);
  return true;
}

/** Verifies timestamp freshness, hash integrity, Ed25519 signature, and nonce uniqueness. */
export async function verifyClawdstrikeMessage(
  message: ClawdstrikeMessage,
): Promise<ClawdstrikeVerificationResult> {
  // 1. Check timestamp freshness
  const age = Math.abs(Date.now() - message.timestamp);
  if (age > TIMESTAMP_TOLERANCE_MS) {
    return { valid: false, reason: "timestamp_stale" };
  }

  // 2. Check detached signature/public key format before verification
  if (!ED25519_SIGNATURE_HEX.test(message.signature)) {
    return { valid: false, reason: "invalid_signature_format" };
  }
  if (!ED25519_PUBLIC_KEY_HEX.test(message.sender)) {
    return { valid: false, reason: "invalid_sender_format" };
  }

  // 3. Recompute hash and verify id
  const { signature, id, ...content } = message;
  const expectedHash = await computeClawdstrikeMessageHash(
    content as Omit<ClawdstrikeBaseMessage, "signature" | "id"> & Record<string, unknown>,
  );
  if (id !== expectedHash) {
    return { valid: false, reason: "id_mismatch" };
  }

  // 4. Verify the detached signature over the hash bytes.
  const signatureValid = await verifyDetachedPayload(
    new TextEncoder().encode(expectedHash),
    signature,
    message.sender,
  );
  if (!signatureValid) {
    return { valid: false, reason: "invalid_signature" };
  }

  // 5. Check nonce uniqueness only after the signature succeeds.
  if (!trackNonce(message.nonce)) {
    return { valid: false, reason: "nonce_reused" };
  }

  return { valid: true };
}

export interface CreateSpeakeasyRoomConfig {
  swarmId: string;
  name: string;
  purpose: SpeakeasyPurpose;
  classification: SpeakeasyClassification;
  attachedTo?: string;
  members?: SpeakeasyMember[];
}

/** Deterministic: same inputs always produce the same room ID. */
export async function deriveSpeakeasyId(
  purpose: SpeakeasyPurpose,
  attachedToId: string,
  swarmId: string,
): Promise<string> {
  const input = `clawdstrike:${purpose}:${swarmId}:${attachedToId}`;
  const hash = await sha256Hex(input);
  return `spk_${hash.slice(0, 28)}`;
}

export async function createSpeakeasyRoom(
  config: CreateSpeakeasyRoomConfig,
): Promise<ClawdstrikeSpeakeasy> {
  const attachedTo = config.attachedTo ?? null;
  const idSuffix = attachedTo ?? config.swarmId;

  const speakeasyId = await deriveSpeakeasyId(
    config.purpose,
    idSuffix,
    config.swarmId,
  );

  const topics = getRoomTopics(speakeasyId);

  return {
    id: speakeasyId,
    swarmId: config.swarmId,
    name: config.name,
    purpose: config.purpose,
    classification: config.classification,
    attachedTo,
    members: config.members ?? [],
    topics,
    createdAt: Date.now(),
    lastMessageAt: null,
    archived: false,
  };
}

export function attachToFinding(
  room: ClawdstrikeSpeakeasy,
  findingId: string,
): ClawdstrikeSpeakeasy {
  return { ...room, attachedTo: findingId };
}

export function attachToCampaign(
  room: ClawdstrikeSpeakeasy,
  campaignId: string,
): ClawdstrikeSpeakeasy {
  return { ...room, attachedTo: campaignId };
}

export function archiveRoom(room: ClawdstrikeSpeakeasy): ClawdstrikeSpeakeasy {
  return { ...room, archived: true };
}

export function addRoomMember(
  room: ClawdstrikeSpeakeasy,
  member: SpeakeasyMember,
): ClawdstrikeSpeakeasy {
  const exists = room.members.some((m) => m.fingerprint === member.fingerprint);
  if (exists) return room;
  return { ...room, members: [...room.members, member] };
}

export function removeRoomMember(
  room: ClawdstrikeSpeakeasy,
  memberFingerprint: string,
): ClawdstrikeSpeakeasy {
  return {
    ...room,
    members: room.members.filter((m) => m.fingerprint !== memberFingerprint),
  };
}

export function updateClassification(
  room: ClawdstrikeSpeakeasy,
  classification: SpeakeasyClassification,
): ClawdstrikeSpeakeasy {
  return { ...room, classification };
}

export function getRoomTopics(speakeasyId: string): {
  messages: string;
  presence: string;
  typing: string;
} {
  // Strip spk_ prefix for topic compatibility if present
  const topicId = speakeasyId.startsWith("spk_")
    ? speakeasyId.slice(4)
    : speakeasyId;
  const base = `${TOPIC_PREFIX}/speakeasy/${topicId}`;
  return {
    messages: `${base}/messages`,
    presence: `${base}/presence`,
    typing: `${base}/typing`,
  };
}

export interface SwarmTopics {
  swarmId: string;
  intel: string;
  signals: string;
  detections: string;
  coordination: string;
  reputation: string;
}

export function createSwarmTopics(swarmId: string): SwarmTopics {
  const base = `${TOPIC_PREFIX}/swarm/${swarmId}`;
  return {
    swarmId,
    intel: `${base}/intel`,
    signals: `${base}/signals`,
    detections: `${base}/detections`,
    coordination: `${base}/coordination`,
    reputation: `${base}/reputation`,
  };
}

export function getAllSwarmTopics(swarmId: string): string[] {
  const topics = createSwarmTopics(swarmId);
  return [topics.intel, topics.signals, topics.detections, topics.coordination, topics.reputation];
}

export function createSentinelStatusTopic(sentinelId: string): string {
  return `${TOPIC_PREFIX}/sentinel/${sentinelId}/status`;
}

export interface ParsedSwarmTopic {
  swarmId: string;
  channel: "intel" | "signals" | "detections" | "coordination" | "reputation";
}

export function parseSwarmTopic(topic: string): ParsedSwarmTopic | null {
  const prefix = `${TOPIC_PREFIX}/swarm/`;
  if (!topic.startsWith(prefix)) return null;

  const remainder = topic.slice(prefix.length);
  const parts = remainder.split("/");
  if (parts.length !== 2) return null;

  const [swarmId, channel] = parts;
  const validChannels = ["intel", "signals", "detections", "coordination", "reputation"];
  if (!validChannels.includes(channel)) return null;

  return { swarmId, channel: channel as ParsedSwarmTopic["channel"] };
}

export interface ParsedSentinelTopic {
  sentinelId: string;
  channel: "status";
}

export function parseSentinelTopic(topic: string): ParsedSentinelTopic | null {
  const prefix = `${TOPIC_PREFIX}/sentinel/`;
  if (!topic.startsWith(prefix)) return null;

  const remainder = topic.slice(prefix.length);
  const parts = remainder.split("/");
  if (parts.length !== 2) return null;

  const [sentinelId, channel] = parts;
  if (channel !== "status") return null;

  return { sentinelId, channel };
}

/** Minimal interface matching @backbay/speakeasy's BayChatIdentity. */
export interface BayChatIdentityLike {
  publicKey: string;
  secretKey?: string;
  fingerprint: string;
  sigil: "diamond" | "eye" | "wave" | "crown" | "spiral" | "key" | "star" | "moon";
  nickname?: string;
  createdAt: number;
}

/** Public-only conversion; result has no signing capability. */
export function sentinelIdentityToBayChatIdentity(
  identity: SentinelIdentity,
): BayChatIdentityLike {
  return {
    publicKey: identity.publicKey,
    fingerprint: identity.fingerprint,
    sigil: identity.sigil,
    nickname: identity.nickname,
    createdAt: Date.now(),
  };
}

/** Strips secret key material. */
export function bayChatIdentityToSentinelIdentity(
  bayChatIdentity: BayChatIdentityLike,
): SentinelIdentity {
  return {
    publicKey: bayChatIdentity.publicKey,
    fingerprint: bayChatIdentity.fingerprint,
    sigil: bayChatIdentity.sigil,
    nickname: bayChatIdentity.nickname ?? bayChatIdentity.fingerprint.slice(0, 8),
  };
}

export function canSign(identity: BayChatIdentityLike): boolean {
  return identity.secretKey !== undefined && identity.secretKey.length > 0;
}

export function clawdstrikePublicKey(identity: BayChatIdentityLike): string {
  return identity.publicKey;
}

/** Produces "a1b2-c3d4-e5f6-g7h8" format. */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,4}/g)?.join("-") ?? fingerprint;
}

export function sentinelToMember(
  identity: SentinelIdentity,
  role: SpeakeasyMember["role"] = "participant",
): SpeakeasyMember {
  return {
    type: "sentinel",
    fingerprint: identity.fingerprint,
    displayName: identity.nickname,
    sigil: identity.sigil,
    role,
    joinedAt: Date.now(),
  };
}

export function operatorToMember(
  identity: BayChatIdentityLike,
  role: SpeakeasyMember["role"] = "moderator",
): SpeakeasyMember {
  return {
    type: "operator",
    fingerprint: identity.fingerprint,
    displayName: identity.nickname ?? identity.fingerprint.slice(0, 8),
    sigil: identity.sigil,
    role,
    joinedAt: Date.now(),
  };
}

/** Minimal interface matching @backbay/speakeasy MessageEnvelope. */
export interface MessageEnvelopeLike {
  version: 1;
  type: string;
  payload: Record<string, unknown>;
  ttl: number;
  created: number;
}

export function isClawdstrikeMessage(
  message: Record<string, unknown>,
): message is ClawdstrikeMessage & Record<string, unknown> {
  return (
    typeof message.type === "string" &&
    (CLAWDSTRIKE_MESSAGE_TYPES as readonly string[]).includes(message.type)
  );
}

export function isClawdstrikeMessageOfType<T extends ClawdstrikeMessageType>(
  message: Record<string, unknown>,
  type: T,
): message is Extract<ClawdstrikeMessage, { type: T }> & Record<string, unknown> {
  return message.type === type;
}

export interface RoutedMessage {
  source:
    | { kind: "speakeasy"; speakeasyId: string; channel: "messages" | "presence" | "typing" }
    | { kind: "swarm"; swarmId: string; channel: ParsedSwarmTopic["channel"] }
    | { kind: "sentinel"; sentinelId: string; channel: "status" }
    | { kind: "unknown"; topic: string };
  message: ClawdstrikeMessage | null;
  rawPayload: Record<string, unknown>;
  ttl: number;
  envelopeCreated: number;
}

export function routeMessage(topic: string, envelope: MessageEnvelopeLike): RoutedMessage {
  // Determine source from topic
  let source: RoutedMessage["source"];

  // Try speakeasy topic first
  const speakeasyParsed = parseSpeakeasyTopicLocal(topic);
  if (speakeasyParsed) {
    source = { kind: "speakeasy", ...speakeasyParsed };
  } else {
    const swarmParsed = parseSwarmTopic(topic);
    if (swarmParsed) {
      source = { kind: "swarm", ...swarmParsed };
    } else {
      const sentinelParsed = parseSentinelTopic(topic);
      if (sentinelParsed) {
        source = { kind: "sentinel", ...sentinelParsed };
      } else {
        source = { kind: "unknown", topic };
      }
    }
  }

  // Try to parse payload as Clawdstrike message
  const payload = envelope.payload;
  const message = isClawdstrikeMessage(payload) ? payload : null;

  return {
    source,
    message,
    rawPayload: payload,
    ttl: envelope.ttl,
    envelopeCreated: envelope.created,
  };
}

function parseSpeakeasyTopicLocal(
  topic: string,
): { speakeasyId: string; channel: "messages" | "presence" | "typing" } | null {
  const prefix = `${TOPIC_PREFIX}/speakeasy/`;
  if (!topic.startsWith(prefix)) return null;

  const remainder = topic.slice(prefix.length);
  const parts = remainder.split("/");
  if (parts.length !== 2) return null;

  const [speakeasyId, type] = parts;
  if (type !== "messages" && type !== "presence" && type !== "typing") return null;

  return { speakeasyId, channel: type };
}

export function createClawdstrikeEnvelope(message: ClawdstrikeMessage): MessageEnvelopeLike {
  // Map message type to envelope type
  let envelopeType: string;
  switch (message.type) {
    case "intel_share":
    case "intel_ack":
    case "detection_sync":
      envelopeType = "intel";
      break;
    case "finding_update":
    case "sentinel_task":
      envelopeType = "coordination";
      break;
    case "signal_alert":
      envelopeType = "signal";
      break;
    case "sentinel_status":
      envelopeType = "status";
      break;
    case "reputation_vote":
    case "room_metadata":
      envelopeType = "coordination";
      break;
    default:
      envelopeType = "message";
  }

  return {
    version: 1,
    type: envelopeType,
    payload: message as unknown as Record<string, unknown>,
    ttl: DEFAULT_TTL[message.type],
    created: Date.now(),
  };
}

export function isClawdstrikeEnvelopeValid(envelope: MessageEnvelopeLike): boolean {
  const payload = envelope.payload;
  if (!isClawdstrikeMessage(payload)) return false;

  const maxAge = MESSAGE_TYPE_MAX_AGE[payload.type] ?? 5 * 60_000;
  const age = Date.now() - envelope.created;
  return age <= maxAge && envelope.ttl > 0;
}

export function getPublishTopic(
  message: ClawdstrikeMessage,
  context: { swarmId?: string; speakeasyId?: string; sentinelId?: string },
): string {
  switch (message.type) {
    case "intel_share":
    case "intel_ack":
      if (context.speakeasyId) {
        return getRoomTopics(context.speakeasyId).messages;
      }
      if (context.swarmId) {
        return createSwarmTopics(context.swarmId).intel;
      }
      break;

    case "finding_update":
    case "sentinel_task":
      if (context.speakeasyId) {
        return getRoomTopics(context.speakeasyId).messages;
      }
      if (context.swarmId) {
        return createSwarmTopics(context.swarmId).coordination;
      }
      break;

    case "signal_alert":
      if (context.swarmId) {
        return createSwarmTopics(context.swarmId).signals;
      }
      break;

    case "sentinel_status":
      if (context.sentinelId) {
        return createSentinelStatusTopic(context.sentinelId);
      }
      break;

    case "reputation_vote":
      if (context.swarmId) {
        return createSwarmTopics(context.swarmId).reputation;
      }
      break;

    case "room_metadata":
      if (context.speakeasyId) {
        return getRoomTopics(context.speakeasyId).messages;
      }
      break;

    case "detection_sync":
      if (context.swarmId) {
        return createSwarmTopics(context.swarmId).detections;
      }
      break;
  }

    if (context.swarmId) {
    return createSwarmTopics(context.swarmId).coordination;
  }

  throw new Error(
    `Cannot determine publish topic for message type "${message.type}" with given context`,
  );
}
