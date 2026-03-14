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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Gossipsub topic prefix — matches @backbay/speakeasy TOPIC_PREFIX. */
const TOPIC_PREFIX = "/baychat/v1";

/**
 * Clawdstrike message type discriminators.
 * These extend Speakeasy's built-in MessageType union for domain-specific
 * security coordination messages.
 */
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

/**
 * Default TTL per message category (hops in Gossipsub mesh).
 * Higher-value messages get wider propagation.
 */
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

/**
 * Maximum age (ms) for each message type before receivers reject it.
 * Stale messages lose operational value.
 */
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

/** Timestamp freshness tolerance for verification (5 minutes). */
const TIMESTAMP_TOLERANCE_MS = 5 * 60_000;

/** Nonce byte length (128-bit). */
const NONCE_BYTES = 16;

// ---------------------------------------------------------------------------
// Identity Converters
// ---------------------------------------------------------------------------

/**
 * Convert an OperatorIdentity to a SpeakeasyMember for use in speakeasy rooms.
 */
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

// ---------------------------------------------------------------------------
// 1. Message Type Interfaces
// ---------------------------------------------------------------------------

/**
 * Base fields shared by all Clawdstrike Speakeasy messages.
 * Mirrors @backbay/speakeasy BaseMessage structure.
 */
export interface ClawdstrikeBaseMessage {
  /** SHA-256 of the canonical JSON serialization of the unsigned payload. */
  id: string;
  /** Message type discriminator. */
  type: ClawdstrikeMessageType;
  /** Sender's Ed25519 public key (hex). */
  sender: string;
  /** Unix timestamp in milliseconds. */
  timestamp: number;
  /** Random nonce (hex) for replay prevention. */
  nonce: string;
  /** Ed25519 signature over message hash (hex). */
  signature: string;
}

/** Intel artifact sharing. */
export interface IntelShareMessage extends ClawdstrikeBaseMessage {
  type: "intel_share";
  /** Intel artifact ID. */
  intelId: string;
  /** Intel type discriminator. */
  intelType: IntelType;
  /** Human-readable title. */
  title: string;
  /** Narrative summary (never raw evidence). */
  summary: string;
  /** SHA-256 of the full signable intel canonical JSON. */
  contentHash: string;
  /** Ed25519 signature over the signable intel hash by the intel author. */
  intelSignature: string;
  /** Public key needed to verify the intel signature path. */
  intelSignerPublicKey: string;
  /** Confidence score 0.0-1.0. */
  confidence: number;
  /** MITRE ATT&CK technique IDs if applicable. */
  mitreTechniques?: string[];
  /** Tags for categorization. */
  tags: string[];
  /** Shareability level at which this was published. */
  shareability: "swarm" | "public";
  /** Clawdstrike SignedReceipt as JSON (provenance chain). */
  receiptJson?: string;
}

/** Acknowledgement of intel receipt. */
export interface IntelAckMessage extends ClawdstrikeBaseMessage {
  type: "intel_ack";
  /** Intel artifact ID being acknowledged. */
  intelId: string;
  /** Digest action. */
  action: "ingested" | "rejected" | "deferred";
  /** Reason if rejected. */
  reason?: string;
}

/** Finding status change notification. */
export interface FindingUpdateMessage extends ClawdstrikeBaseMessage {
  type: "finding_update";
  /** Finding ID. */
  findingId: string;
  /** New status. */
  status: FindingStatus;
  /** New severity if changed. */
  severity?: Severity;
  /** Updated confidence. */
  confidence?: number;
  /** Annotation text (analyst note). */
  annotation?: string;
  /** Number of contributing signals. */
  signalCount?: number;
}

/** Urgent signal broadcast. */
export interface SignalAlertMessage extends ClawdstrikeBaseMessage {
  type: "signal_alert";
  /** Signal ID. */
  signalId: string;
  /** Signal type. */
  signalType: SignalType;
  /** Severity. */
  severity: "medium" | "high" | "critical";
  /** Confidence 0.0-1.0. */
  confidence: number;
  /** Brief description. */
  summary: string;
  /** Sentinel that generated this signal. */
  sourceSentinelId?: string;
  /** Guard that triggered (if guard-originated). */
  sourceGuardId?: string;
  /** Related finding ID if already correlated. */
  relatedFindingId?: string;
}

/** Sentinel heartbeat/status update. */
export interface SentinelStatusMessage extends ClawdstrikeBaseMessage {
  type: "sentinel_status";
  /** Sentinel ID. */
  sentinelId: string;
  /** Current mode. */
  mode: SentinelMode;
  /** Operational status. */
  status: SentinelLifecycleStatus;
  /** Active goal count. */
  activeGoals: number;
  /** Signals generated in last hour. */
  recentSignalCount: number;
  /** Findings contributed to in last hour. */
  recentFindingCount: number;
  /** Policy hash currently enforced. */
  policyHash?: string;
  /** Software version. */
  version?: string;
}

/** Task assignment to sentinel. */
export interface SentinelTaskMessage extends ClawdstrikeBaseMessage {
  type: "sentinel_task";
  /** Target sentinel ID (or '*' for any available). */
  targetSentinelId: string;
  /** Task type. */
  taskType: "investigate" | "enrich" | "hunt" | "correlate" | "monitor";
  /** Task description. */
  description: string;
  /** Related finding or campaign ID. */
  attachedTo?: string;
  /** Priority. */
  priority: "low" | "normal" | "high" | "urgent";
  /** Deadline timestamp (ms). */
  deadline?: number;
  /** Delegation token if capability transfer is needed. */
  delegationToken?: string;
}

/** Reputation attestation. */
export interface ReputationVoteMessage extends ClawdstrikeBaseMessage {
  type: "reputation_vote";
  /** Public key fingerprint of the target member. */
  targetFingerprint: string;
  /** Vote direction. */
  vote: "positive" | "negative";
  /** Category of the vote. */
  category: "intel_quality" | "detection_efficacy" | "uptime" | "collaboration" | "general";
  /** Human-readable reason. */
  reason: string;
  /** Optional reference (intel ID, rule ID, etc.). */
  referenceId?: string;
}

/** Room purpose/classification update. */
export interface RoomMetadataMessage extends ClawdstrikeBaseMessage {
  type: "room_metadata";
  /** Speakeasy room ID being updated. */
  speakeasyId: string;
  /** Updated purpose (if changed). */
  purpose?: SpeakeasyPurpose;
  /** Updated classification (if changed). */
  classification?: SpeakeasyClassification;
  /** Updated attachment target (if changed). */
  attachedTo?: string | null;
  /** Reason for the change. */
  changeReason?: string;
}

/** Detection rule synchronization. */
export interface DetectionSyncMessage extends ClawdstrikeBaseMessage {
  type: "detection_sync";
  /** Detection rule ID. */
  ruleId: string;
  /** Action. */
  action: "publish" | "update" | "deprecate";
  /** Rule format. */
  format: "sigma" | "yara" | "clawdstrike_pattern" | "policy_patch";
  /** Rule content (canonical JSON or rule text). */
  content: string;
  /** SHA-256 of content. */
  contentHash: string;
  /** Version number (monotonically increasing). */
  ruleVersion: number;
  /** Author sentinel or operator fingerprint. */
  authorFingerprint: string;
  /** Confidence in the rule. */
  confidence: number;
}

/** Union of all Clawdstrike-specific message types. */
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

// ---------------------------------------------------------------------------
// 2. Signing / Hashing Primitives
// ---------------------------------------------------------------------------

/**
 * Generate a random nonce (16 bytes, hex-encoded).
 * Matches @backbay/speakeasy generateNonce() pattern.
 */
export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** Convert bytes to hex string. */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute SHA-256 hash of UTF-8 string, returning hex.
 * Uses Web Crypto API (available in browser + Tauri + Node 18+).
 */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Bun vs @types/web ArrayBuffer mismatch
  const hashBuffer = await crypto.subtle.digest("SHA-256", data as any);
  return toHex(new Uint8Array(hashBuffer));
}

/**
 * Compute message hash for signing.
 *
 * Hashes the full unsigned payload using canonical JSON so every mutable
 * message field is bound into the signature. Only `id` and `signature` stay
 * out of band.
 */
export async function computeClawdstrikeMessageHash(
  message: Omit<ClawdstrikeBaseMessage, "signature" | "id"> & Record<string, unknown>,
): Promise<string> {
  return sha256Hex(canonicalizeJson(message));
}

/**
 * Sign a Clawdstrike message using a sentinel's secret key.
 *
 * Steps:
 *   1. Generate nonce (16 random bytes, hex)
 *   2. Compute SHA-256 hash of canonical JSON over the unsigned payload
 *   3. Sign the hash bytes with Ed25519 via the workbench signature adapter
 *   4. Set id = hash
 */
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

// ---------------------------------------------------------------------------
// 3. Message Creation Helpers
// ---------------------------------------------------------------------------

/**
 * Create a signed IntelShareMessage for publishing an intel artifact.
 */
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

/**
 * Create a signed IntelAckMessage acknowledging receipt of intel.
 */
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

/**
 * Create a signed FindingUpdateMessage for a finding status change.
 */
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

/**
 * Create a signed SignalAlertMessage for an urgent signal broadcast.
 */
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

/**
 * Create a signed SentinelStatusMessage heartbeat from a sentinel.
 */
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

/**
 * Create a signed SentinelTaskMessage to assign work to a sentinel.
 */
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

/**
 * Create a signed ReputationVoteMessage for peer reputation attestation.
 */
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

/**
 * Create a signed RoomMetadataMessage for room configuration changes.
 */
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

/**
 * Create a signed DetectionSyncMessage for rule synchronization.
 */
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

// ---------------------------------------------------------------------------
// 4. Message Verification
// ---------------------------------------------------------------------------

/** Verification result returned by verifyClawdstrikeMessage. */
export interface ClawdstrikeVerificationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Nonce tracker for replay prevention within the current session.
 * Keeps a bounded set of recently-seen nonces.
 */
const seenNonces = new Set<string>();
const MAX_SEEN_NONCES = 10_000;

/** Evict oldest nonces when the set grows too large. */
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

/**
 * Verify a Clawdstrike message.
 *
 * Checks:
 * 1. Timestamp freshness (within 5-minute tolerance)
 * 2. Message hash integrity (id matches recomputed hash)
 * 3. Detached Ed25519 signature validity against the sender public key
 * 4. Nonce uniqueness (replay prevention)
 */
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

// ---------------------------------------------------------------------------
// 5. Room Management (pure functions)
// ---------------------------------------------------------------------------

/** Configuration for creating a new speakeasy room. */
export interface CreateSpeakeasyRoomConfig {
  /** Parent swarm ID. */
  swarmId: string;
  /** Display name. */
  name: string;
  /** Room purpose. */
  purpose: SpeakeasyPurpose;
  /** Initial classification. */
  classification: SpeakeasyClassification;
  /** What the room is attached to (finding ID, campaign ID, etc.). */
  attachedTo?: string;
  /** Initial members. */
  members?: SpeakeasyMember[];
}

/**
 * Derive a deterministic speakeasy ID from purpose + attachment + swarm.
 * Same inputs always produce the same room ID, preventing duplicate rooms.
 */
export async function deriveSpeakeasyId(
  purpose: SpeakeasyPurpose,
  attachedToId: string,
  swarmId: string,
): Promise<string> {
  const input = `clawdstrike:${purpose}:${swarmId}:${attachedToId}`;
  const hash = await sha256Hex(input);
  return `spk_${hash.slice(0, 28)}`;
}

/**
 * Create a ClawdstrikeSpeakeasy room object with deterministic ID.
 */
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

/**
 * Attach a room to a specific finding.
 * Returns a new room object (immutable update).
 */
export function attachToFinding(
  room: ClawdstrikeSpeakeasy,
  findingId: string,
): ClawdstrikeSpeakeasy {
  return { ...room, attachedTo: findingId };
}

/**
 * Attach a room to a campaign (intel artifact of type "campaign").
 * Returns a new room object (immutable update).
 */
export function attachToCampaign(
  room: ClawdstrikeSpeakeasy,
  campaignId: string,
): ClawdstrikeSpeakeasy {
  return { ...room, attachedTo: campaignId };
}

/**
 * Archive a room — marks it as read-only and unsubscribed from Gossipsub.
 * Returns a new room object.
 */
export function archiveRoom(room: ClawdstrikeSpeakeasy): ClawdstrikeSpeakeasy {
  return { ...room, archived: true };
}

/**
 * Add a member to a room. No-op if member with same fingerprint already exists.
 * Returns a new room object.
 */
export function addRoomMember(
  room: ClawdstrikeSpeakeasy,
  member: SpeakeasyMember,
): ClawdstrikeSpeakeasy {
  const exists = room.members.some((m) => m.fingerprint === member.fingerprint);
  if (exists) return room;
  return { ...room, members: [...room.members, member] };
}

/**
 * Remove a member from a room by fingerprint.
 * Returns a new room object.
 */
export function removeRoomMember(
  room: ClawdstrikeSpeakeasy,
  memberFingerprint: string,
): ClawdstrikeSpeakeasy {
  return {
    ...room,
    members: room.members.filter((m) => m.fingerprint !== memberFingerprint),
  };
}

/**
 * Update the classification level of a room.
 * Returns a new room object.
 */
export function updateClassification(
  room: ClawdstrikeSpeakeasy,
  classification: SpeakeasyClassification,
): ClawdstrikeSpeakeasy {
  return { ...room, classification };
}

/**
 * Get Gossipsub topic strings for a room.
 * Follows @backbay/speakeasy topic naming: /baychat/v1/speakeasy/{id}/...
 */
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

// ---------------------------------------------------------------------------
// 6. Topic Management (Swarm & Sentinel)
// ---------------------------------------------------------------------------

/** Swarm topic set. */
export interface SwarmTopics {
  swarmId: string;
  intel: string;
  signals: string;
  detections: string;
  coordination: string;
  reputation: string;
}

/**
 * Create all Gossipsub topic strings for a swarm.
 */
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

/**
 * Get all swarm topic strings as an array (for bulk subscription).
 */
export function getAllSwarmTopics(swarmId: string): string[] {
  const topics = createSwarmTopics(swarmId);
  return [topics.intel, topics.signals, topics.detections, topics.coordination, topics.reputation];
}

/**
 * Create the status topic for a specific sentinel.
 */
export function createSentinelStatusTopic(sentinelId: string): string {
  return `${TOPIC_PREFIX}/sentinel/${sentinelId}/status`;
}

/** Parsed swarm topic result. */
export interface ParsedSwarmTopic {
  swarmId: string;
  channel: "intel" | "signals" | "detections" | "coordination" | "reputation";
}

/**
 * Parse a topic string to extract swarm ID and channel.
 * Returns null if the topic is not a swarm topic.
 */
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

/** Parsed sentinel topic result. */
export interface ParsedSentinelTopic {
  sentinelId: string;
  channel: "status";
}

/**
 * Parse a topic string to extract sentinel ID and channel.
 * Returns null if the topic is not a sentinel topic.
 */
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

// ---------------------------------------------------------------------------
// 7. Identity Bridge
// ---------------------------------------------------------------------------

/**
 * BayChatIdentity shape — minimal interface matching @backbay/speakeasy's
 * BayChatIdentity without importing it directly (different repo).
 */
export interface BayChatIdentityLike {
  publicKey: string;
  secretKey?: string;
  fingerprint: string;
  sigil: "diamond" | "eye" | "wave" | "crown" | "spiral" | "key" | "star" | "moon";
  nickname?: string;
  createdAt: number;
}

/**
 * Convert a SentinelIdentity to BayChatIdentity-compatible shape.
 *
 * SentinelIdentity is a public-only type (no secret key). The resulting
 * BayChatIdentityLike will not have signing capability — use this for
 * display and verification, not for message creation.
 */
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

/**
 * Convert a BayChatIdentity-compatible object to SentinelIdentity.
 *
 * Strips secret key material — SentinelIdentity is always public-only.
 */
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

/**
 * Check if an identity has signing capability (has secret key material).
 * Works with both BayChatIdentityLike and SentinelIdentity (which never has secret key).
 */
export function canSign(identity: BayChatIdentityLike): boolean {
  return identity.secretKey !== undefined && identity.secretKey.length > 0;
}

/**
 * Extract the Clawdstrike-compatible public key from a Speakeasy identity.
 * Both systems use the same 32-byte hex format (no 0x prefix).
 */
export function clawdstrikePublicKey(identity: BayChatIdentityLike): string {
  return identity.publicKey;
}

/**
 * Format a 16-char hex fingerprint for human-readable display.
 * Produces "a1b2-c3d4-e5f6-g7h8" format used for out-of-band verification.
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,4}/g)?.join("-") ?? fingerprint;
}

/**
 * Create a SpeakeasyMember from a SentinelIdentity for room membership.
 */
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

/**
 * Create an operator SpeakeasyMember from a BayChatIdentity.
 */
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

// ---------------------------------------------------------------------------
// 8. Message Routing
// ---------------------------------------------------------------------------

/**
 * Envelope shape matching @backbay/speakeasy MessageEnvelope.
 * Minimal interface to avoid direct import.
 */
export interface MessageEnvelopeLike {
  version: 1;
  type: string;
  payload: Record<string, unknown>;
  ttl: number;
  created: number;
}

/**
 * Type guard: check if a message payload is a Clawdstrike message type
 * (vs. standard Speakeasy chat/presence/typing/bounty messages).
 */
export function isClawdstrikeMessage(
  message: Record<string, unknown>,
): message is ClawdstrikeMessage & Record<string, unknown> {
  return (
    typeof message.type === "string" &&
    (CLAWDSTRIKE_MESSAGE_TYPES as readonly string[]).includes(message.type)
  );
}

/**
 * Type guard for a specific Clawdstrike message type.
 */
export function isClawdstrikeMessageOfType<T extends ClawdstrikeMessageType>(
  message: Record<string, unknown>,
  type: T,
): message is Extract<ClawdstrikeMessage, { type: T }> & Record<string, unknown> {
  return message.type === type;
}

/**
 * Routed message result from topic + envelope parsing.
 */
export interface RoutedMessage {
  /** Source topic type. */
  source:
    | { kind: "speakeasy"; speakeasyId: string; channel: "messages" | "presence" | "typing" }
    | { kind: "swarm"; swarmId: string; channel: ParsedSwarmTopic["channel"] }
    | { kind: "sentinel"; sentinelId: string; channel: "status" }
    | { kind: "unknown"; topic: string };
  /** Parsed and typed message, or null if not a Clawdstrike message. */
  message: ClawdstrikeMessage | null;
  /** Raw payload for non-Clawdstrike messages. */
  rawPayload: Record<string, unknown>;
  /** Envelope TTL remaining. */
  ttl: number;
  /** Envelope creation timestamp. */
  envelopeCreated: number;
}

/**
 * Route an incoming envelope from a topic to a typed ClawdstrikeMessage.
 *
 * Parses the topic string to determine the source (speakeasy room, swarm
 * channel, or sentinel status), then attempts to deserialize the payload
 * as a Clawdstrike message type.
 */
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

/**
 * Local speakeasy topic parser (avoids importing from @backbay/speakeasy).
 * Mirrors parseSpeakeasyTopic from topics.ts.
 */
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

/**
 * Create a MessageEnvelope for a Clawdstrike message.
 * Uses type-appropriate TTL and envelope type mapping.
 */
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

/**
 * Check if a Clawdstrike message envelope is still valid (not expired).
 * Uses per-type max age from MESSAGE_TYPE_MAX_AGE.
 */
export function isClawdstrikeEnvelopeValid(envelope: MessageEnvelopeLike): boolean {
  const payload = envelope.payload;
  if (!isClawdstrikeMessage(payload)) return false;

  const maxAge = MESSAGE_TYPE_MAX_AGE[payload.type] ?? 5 * 60_000;
  const age = Date.now() - envelope.created;
  return age <= maxAge && envelope.ttl > 0;
}

// ---------------------------------------------------------------------------
// 9. Utility: Topic routing for publish
// ---------------------------------------------------------------------------

/**
 * Determine the correct topic for publishing a Clawdstrike message.
 *
 * @param message - The message to publish
 * @param context - Either a swarm ID, speakeasy ID, or sentinel ID
 * @returns The Gossipsub topic string to publish to
 */
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

  // Fallback: publish to swarm coordination if available
  if (context.swarmId) {
    return createSwarmTopics(context.swarmId).coordination;
  }

  throw new Error(
    `Cannot determine publish topic for message type "${message.type}" with given context`,
  );
}
