# Speakeasy Integration Design

> Detailed design for integrating `@backbay/speakeasy` into the Clawdstrike Workbench
> as the trust and coordination layer for the Sentinel Swarm.

**Status:** Design
**Date:** 2026-03-12
**Parent:** [INDEX.md](./INDEX.md) -- Section 5
**Branch:** `feat/sentinel-swarm`

---

## Table of Contents

1. [Identity Unification](#1-identity-unification)
2. [New Message Types](#2-new-message-types)
3. [Topic Architecture](#3-topic-architecture)
4. [React Integration](#4-react-integration)
5. [Room Lifecycle](#5-room-lifecycle)
6. [Trust Model](#6-trust-model)
7. [Offline / Degraded Mode](#7-offline--degraded-mode)
8. [Security Considerations](#8-security-considerations)

---

## 1. Identity Unification

### Problem Statement

A Sentinel needs a single cryptographic identity that works across two independent
signing systems:

| System | Library | Key Format | Signing Input |
|--------|---------|-----------|---------------|
| **Speakeasy** | `@noble/ed25519` via `@backbay/speakeasy` | 32-byte private key (hex), 32-byte public key (hex), 64-byte secret key = private \|\| public | SHA-256 hash of pipe-delimited canonical message fields |
| **Clawdstrike** | `ed25519-dalek` (Rust) / `@noble/ed25519` via `@clawdstrike/sdk` | 32-byte seed (private key), 32-byte public key | RFC 8785 canonical JSON bytes of Receipt |

### Compatibility Analysis

Both systems use the Ed25519 curve with the same underlying primitive. The critical
question is whether the same 32-byte seed produces the same keypair in both systems.

**Speakeasy key derivation** (from `identity.ts`):

```typescript
// BIP39 mnemonic -> seed (64 bytes) -> first 32 bytes as Ed25519 private key
const seed = mnemonicToSeedSync(mnemonic);
const privateKey = seed.slice(0, 32);
const publicKey = await ed.getPublicKeyAsync(privateKey);
```

**Clawdstrike key derivation** (from `signing.rs`):

```rust
// 32-byte seed -> Ed25519 keypair
pub fn from_seed(seed: &[u8; 32]) -> Self {
    let signing_key = SigningKey::from_bytes(seed);
    Self { signing_key }
}
```

**Clawdstrike TS SDK key derivation** (from `crypto/sign.ts`):

```typescript
// 32-byte private key -> sign via backend (noble or WASM)
export async function signMessage(
  message: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  return getBackend().signMessage(message, privateKey);
}
```

All three paths use the same Ed25519 seed-to-keypair derivation: `@noble/ed25519` on
the TS side and `ed25519-dalek` on the Rust side. Given the same 32-byte seed, both
produce identical public keys and compatible signatures.

### Decision: Shared Keypair (No Cross-Signing Required)

A Sentinel uses **one Ed25519 keypair** for all operations. The 32-byte seed is the
single source of truth; the public key and fingerprint are derived deterministically.

```
Sentinel Ed25519 Seed (32 bytes)
  |
  +---> Speakeasy: BayChatIdentity
  |       publicKey, fingerprint, sigil, signMessage(), verifyMessage()
  |
  +---> Clawdstrike TS SDK: SignedReceipt.sign(receipt, privateKey)
  |       Uses same 32-byte seed via @noble/ed25519
  |
  +---> Clawdstrike Rust: Keypair::from_seed(&seed)
  |       Uses same 32-byte seed via ed25519-dalek
  |
  +---> Delegation Tokens: hush-multi-agent signs with same keypair
  |
  +---> Intel Artifacts: signData() from @backbay/speakeasy signing.ts
```

### SentinelIdentity Adapter

A thin adapter bridges the `BayChatIdentity` type to the Clawdstrike signing
interface. This adapter lives in the workbench `SpeakeasyBridge` library.

```typescript
import type { BayChatIdentity } from '@backbay/speakeasy';
import { getSecretKeyBytes } from '@backbay/speakeasy';
import { SignedReceipt, Receipt } from '@clawdstrike/sdk';

/**
 * Bridge a Speakeasy identity to Clawdstrike receipt signing.
 *
 * Both systems use the same Ed25519 seed, so we extract the 32-byte
 * private key from the BayChatIdentity and pass it directly to the
 * SDK's SignedReceipt.sign().
 */
export async function signReceiptWithIdentity(
  receipt: Receipt,
  identity: BayChatIdentity,
): Promise<SignedReceipt> {
  const privateKey = getSecretKeyBytes(identity); // first 32 bytes
  return SignedReceipt.sign(receipt, privateKey);
}

/**
 * Extract the Clawdstrike-compatible public key from a Speakeasy identity.
 * Speakeasy stores publicKey as hex without 0x prefix, which matches
 * the Clawdstrike TS SDK PublicKey type (32-byte hex, no 0x).
 */
export function clawdstrikePublicKey(identity: BayChatIdentity): string {
  return identity.publicKey; // already 32-byte hex, no prefix
}
```

### Key Storage

| Context | Storage Mechanism | Notes |
|---------|------------------|-------|
| Workbench (browser) | IndexedDB via Speakeasy's `saveIdentity()` / `loadIdentity()` | Single primary identity per browser profile |
| Workbench (Tauri desktop) | Stronghold vault for seed, IndexedDB for derived public fields | Seed never leaves Stronghold |
| Sentinel (autonomous agent) | Provisioned at creation time; seed stored in `SentinelManager` encrypted store | One keypair per sentinel instance |
| Recovery | BIP39 24-word seed phrase via `recoverIdentity()` | Deterministic re-derivation of all fields |

### Fingerprint and Sigil Derivation

Speakeasy computes a 16-char hex fingerprint from `SHA-256(publicKey)` truncated
(see `computeFingerprint` in `identity.ts`). The sigil is then derived from the
first byte of that fingerprint modulo 8, selecting from the set: diamond, eye,
wave, crown, spiral, key, star, moon (see `deriveSigil` in `sigil.ts`). The color
is derived from fingerprint bytes 4-7 mapped to HSL hue (`deriveColor` in
`sigil.ts`).

Clawdstrike will reuse these derivations directly:

- Sentinels display their sigil + color in all workbench UIs (findings, intel, swarm graphs).
- The fingerprint serves as the short-form identifier in trust graphs and audit logs.
- The `formatFingerprint()` function produces the human-verifiable `a1b2-c3d4-e5f6-g7h8` format used for out-of-band verification.

---

## 2. New Message Types

### Extending the Speakeasy Type System

Speakeasy defines `MessageType` as a string union in `types.ts`:

```typescript
export type MessageType =
  | 'chat'
  | 'sentinel_request'
  | 'sentinel_response'
  | 'bounty_created'
  | 'bounty_claimed'
  | 'bounty_submitted'
  | 'bounty_verified'
  | 'bounty_settled'
  | 'presence'
  | 'typing';
```

The existing `SentinelRequest` and `SentinelResponse` types serve general-purpose
sentinel interaction. The Clawdstrike integration needs domain-specific message
types for security coordination. These extend `BaseMessage` (which provides `id`,
`type`, `sender`, `timestamp`, `nonce`, `signature`) and are routed through the
same `computeMessageHash` / `signMessage` / `verifyMessage` pipeline.

### New MessageType Values

```typescript
export type ClawdstrikeMessageType =
  | 'intel_share'          // Publishing an intel artifact to the room
  | 'intel_ack'            // Acknowledging receipt of intel
  | 'finding_update'       // Status change on an attached finding
  | 'signal_alert'         // High-priority signal forwarded to room
  | 'sentinel_status'      // Sentinel heartbeat and mode update
  | 'sentinel_task'        // Operator assigns task to sentinel
  | 'sentinel_report'      // Sentinel reports task completion
  | 'reputation_vote'      // Peer reputation attestation
  | 'room_metadata'        // Room configuration change (classification, purpose)
  | 'detection_sync';      // Shared detection rule update
```

### Message Definitions

#### IntelShareMessage

Published when a sentinel or operator shares an intel artifact with a room. The
full intel content travels inside the message; receivers validate the signature
before ingesting.

```typescript
interface IntelShareMessage extends BaseMessage {
  type: 'intel_share';
  /** Intel artifact ID */
  intelId: string;
  /** Intel type discriminator */
  intelType: 'detection_rule' | 'pattern' | 'ioc' | 'campaign' | 'advisory' | 'policy_patch';
  /** Human-readable title */
  title: string;
  /** Narrative summary (never raw evidence) */
  summary: string;
  /** SHA-256 of the full intel canonical JSON */
  contentHash: string;
  /** Ed25519 signature over contentHash by the intel author */
  intelSignature: string;
  /** Confidence score 0.0-1.0 */
  confidence: number;
  /** MITRE ATT&CK technique IDs if applicable */
  mitreTechniques?: string[];
  /** Tags for categorization */
  tags: string[];
  /** Shareability level at which this was published */
  shareability: 'swarm' | 'public';
  /** Clawdstrike SignedReceipt as JSON (provenance chain) */
  receiptJson?: string;
}
```

#### IntelAckMessage

Sent by a receiver to confirm they have ingested intel. Enables delivery tracking
and reputation scoring.

```typescript
interface IntelAckMessage extends BaseMessage {
  type: 'intel_ack';
  /** Intel artifact ID being acknowledged */
  intelId: string;
  /** Digest action */
  action: 'ingested' | 'rejected' | 'deferred';
  /** Reason if rejected */
  reason?: string;
}
```

#### FindingUpdateMessage

Broadcast when the status of a finding attached to a room changes. This keeps
all room participants synchronized on triage state.

```typescript
interface FindingUpdateMessage extends BaseMessage {
  type: 'finding_update';
  /** Finding ID */
  findingId: string;
  /** New status */
  status: 'emerging' | 'confirmed' | 'promoted' | 'dismissed' | 'false_positive';
  /** New severity if changed */
  severity?: 'low' | 'medium' | 'high' | 'critical';
  /** Updated confidence */
  confidence?: number;
  /** Annotation text (analyst note) */
  annotation?: string;
  /** Number of contributing signals */
  signalCount?: number;
}
```

#### SignalAlertMessage

Forwarded into a room when a signal exceeds a severity threshold relevant to the
room's attached finding or campaign. Not all signals are forwarded -- only those
that cross the room's configured alert threshold.

```typescript
interface SignalAlertMessage extends BaseMessage {
  type: 'signal_alert';
  /** Signal ID */
  signalId: string;
  /** Signal type */
  signalType: 'anomaly' | 'detection' | 'indicator' | 'policy_violation' | 'behavioral';
  /** Severity */
  severity: 'medium' | 'high' | 'critical';
  /** Confidence 0.0-1.0 */
  confidence: number;
  /** Brief description */
  summary: string;
  /** Sentinel that generated this signal */
  sourceSentinelId?: string;
  /** Guard that triggered (if guard-originated) */
  sourceGuardId?: string;
  /** Related finding ID if already correlated */
  relatedFindingId?: string;
}
```

#### SentinelStatusMessage

Heartbeat and mode updates for sentinels participating in a swarm. Published to
swarm-level topics (not per-room) for global visibility.

```typescript
interface SentinelStatusMessage extends BaseMessage {
  type: 'sentinel_status';
  /** Sentinel ID */
  sentinelId: string;
  /** Current mode */
  mode: 'watcher' | 'hunter' | 'curator' | 'liaison';
  /** Operational status */
  status: 'active' | 'paused' | 'retired';
  /** Active goal count */
  activeGoals: number;
  /** Signals generated in last hour */
  recentSignalCount: number;
  /** Findings contributed to in last hour */
  recentFindingCount: number;
  /** Policy hash currently enforced */
  policyHash?: string;
  /** Software version */
  version?: string;
}
```

#### SentinelTaskMessage

An operator or curator sentinel assigns work to another sentinel through a room.

```typescript
interface SentinelTaskMessage extends BaseMessage {
  type: 'sentinel_task';
  /** Target sentinel ID (or '*' for any available) */
  targetSentinelId: string;
  /** Task type */
  taskType: 'investigate' | 'enrich' | 'hunt' | 'correlate' | 'monitor';
  /** Task description */
  description: string;
  /** Related finding or campaign ID */
  attachedTo?: string;
  /** Priority */
  priority: 'low' | 'normal' | 'high' | 'urgent';
  /** Deadline timestamp (ms) */
  deadline?: number;
  /** Delegation token if capability transfer is needed */
  delegationToken?: string;
}
```

#### SentinelReportMessage

A sentinel reports the result of a completed or failed task.

```typescript
interface SentinelReportMessage extends BaseMessage {
  type: 'sentinel_report';
  /** Original task message ID */
  taskId: string;
  /** Sentinel reporting */
  sentinelId: string;
  /** Outcome */
  outcome: 'completed' | 'failed' | 'partial' | 'deferred';
  /** Summary of findings */
  summary: string;
  /** New signal IDs generated during task */
  generatedSignals?: string[];
  /** New finding IDs created or updated */
  affectedFindings?: string[];
  /** Intel ID if task produced shareable intel */
  producedIntelId?: string;
  /** Signed receipt attesting to task execution */
  receiptJson?: string;
}
```

#### DetectionSyncMessage

Synchronizes detection rules across swarm members. Published when a detection
rule is created, updated, or deprecated.

```typescript
interface DetectionSyncMessage extends BaseMessage {
  type: 'detection_sync';
  /** Detection rule ID */
  ruleId: string;
  /** Action */
  action: 'publish' | 'update' | 'deprecate';
  /** Rule format */
  format: 'sigma' | 'yara' | 'clawdstrike_pattern' | 'policy_patch';
  /** Rule content (canonical JSON or rule text) */
  content: string;
  /** SHA-256 of content */
  contentHash: string;
  /** Version number (monotonically increasing) */
  ruleVersion: number;
  /** Author sentinel or operator fingerprint */
  authorFingerprint: string;
  /** Confidence in the rule */
  confidence: number;
}
```

### Hash Coverage for New Types

The `computeMessageHash` function in `signing.ts` builds a canonical string from
pipe-delimited fields. Each new message type needs a case in that switch statement.
The signing input for each type must include all semantically significant fields
(everything except `id` and `signature`, which are derived).

Example addition to `computeMessageHash`:

```typescript
case 'intel_share':
  parts.push(
    msg.intelId,
    msg.intelType,
    msg.title,
    msg.contentHash,
    msg.intelSignature,
    msg.confidence.toString(),
    msg.shareability,
  );
  break;
```

The full set of hash cases for all ten new message types will be specified in the
implementation PR.

### AnyMessage Union Extension

```typescript
export type ClawdstrikeAnyMessage =
  | AnyMessage              // existing Speakeasy types
  | IntelShareMessage
  | IntelAckMessage
  | FindingUpdateMessage
  | SignalAlertMessage
  | SentinelStatusMessage
  | SentinelTaskMessage
  | SentinelReportMessage
  | DetectionSyncMessage;
```

The `MessageEnvelope.type` field (currently `'message' | 'presence' | 'typing' |
'sync_request' | 'sync_response'`) will be extended with:

```typescript
type EnvelopeType =
  | 'message'
  | 'presence'
  | 'typing'
  | 'sync_request'
  | 'sync_response'
  | 'intel'           // for IntelShareMessage, IntelAckMessage, DetectionSyncMessage
  | 'coordination'    // for FindingUpdateMessage, SentinelTaskMessage, SentinelReportMessage
  | 'signal'          // for SignalAlertMessage
  | 'status';         // for SentinelStatusMessage
```

---

## 3. Topic Architecture

### Existing Topic Structure

Speakeasy defines topics in `topics.ts` with prefix `/baychat/v1`:

```
/baychat/v1/discovery                              (global peer discovery)
/baychat/v1/sentinels                              (global sentinel announcements)
/baychat/v1/speakeasy/{speakeasyId}/messages       (per-room messages)
/baychat/v1/speakeasy/{speakeasyId}/presence        (per-room presence)
/baychat/v1/speakeasy/{speakeasyId}/typing          (per-room typing indicators)
```

### New Topic Families

All new topics use the same `/baychat/v1/` prefix for protocol consistency and
share the same Gossipsub mesh.

#### Swarm Topics

Per-swarm topics for intel distribution and coordination:

```
/baychat/v1/swarm/{swarmId}/intel               Published intel artifacts (IntelShareMessage, IntelAckMessage)
/baychat/v1/swarm/{swarmId}/signals             Shared signal stream (SignalAlertMessage, opt-in)
/baychat/v1/swarm/{swarmId}/detections          Detection rule sync (DetectionSyncMessage)
/baychat/v1/swarm/{swarmId}/coordination        Findings, tasks, reports (FindingUpdateMessage, SentinelTaskMessage, SentinelReportMessage)
/baychat/v1/swarm/{swarmId}/reputation          Reputation attestations (ReputationVoteMessage)
```

#### Sentinel Topics

Per-sentinel status broadcast:

```
/baychat/v1/sentinel/{sentinelId}/status        Heartbeat + mode (SentinelStatusMessage)
```

#### Topic Builder Functions

New functions in the `SpeakeasyBridge` library, following the pattern of
`createSpeakeasyTopics()` in `topics.ts`:

```typescript
import { TOPIC_PREFIX } from '@backbay/speakeasy';

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

export function parseSwarmTopic(
  topic: string,
): { swarmId: string; channel: keyof Omit<SwarmTopics, 'swarmId'> } | null {
  const prefix = `${TOPIC_PREFIX}/swarm/`;
  if (!topic.startsWith(prefix)) return null;

  const remainder = topic.slice(prefix.length);
  const parts = remainder.split('/');
  if (parts.length !== 2) return null;

  const [swarmId, channel] = parts;
  const validChannels = ['intel', 'signals', 'detections', 'coordination', 'reputation'];
  if (!validChannels.includes(channel)) return null;

  return { swarmId, channel: channel as keyof Omit<SwarmTopics, 'swarmId'> };
}
```

### Subscription Strategy

Not every workbench instance subscribes to all topics. Subscription is selective
based on what the user has configured:

| Topic | When Subscribed |
|-------|----------------|
| `/baychat/v1/discovery` | Always (global, auto-subscribed by `Transport.start()`) |
| `/baychat/v1/sentinels` | Always (global, auto-subscribed by `Transport.start()`) |
| `/baychat/v1/swarm/{id}/intel` | When user joins a swarm |
| `/baychat/v1/swarm/{id}/signals` | Opt-in per swarm (high volume, default off) |
| `/baychat/v1/swarm/{id}/detections` | When user joins a swarm |
| `/baychat/v1/swarm/{id}/coordination` | When user joins a swarm |
| `/baychat/v1/swarm/{id}/reputation` | When user joins a swarm |
| `/baychat/v1/sentinel/{id}/status` | When user's sentinel is active, or when tracking a peer sentinel |
| `/baychat/v1/speakeasy/{id}/*` | When user joins a speakeasy room (via `Transport.joinSpeakeasy()`) |

The signal topic is gated because the signal stream is high-volume. The swarm
policy's `autoShareDetections` flag controls whether a member's sentinels
automatically publish signals.

### TTL and Propagation

The `MessageEnvelope` carries a `ttl` field (default 10 hops, see `createEnvelope`
in `transport.ts`). For Clawdstrike messages:

| Message Category | Default TTL | Rationale |
|-----------------|-------------|-----------|
| `intel_share`, `detection_sync` | 10 | Full mesh propagation, high value |
| `finding_update`, `sentinel_task`, `sentinel_report` | 5 | Scoped to participants, lower fan-out needed |
| `signal_alert` | 3 | Time-sensitive, local relevance, prevent flooding |
| `sentinel_status` | 5 | Moderate propagation for swarm awareness |
| `intel_ack`, `reputation_vote` | 5 | Feedback loops, moderate propagation |

---

## 4. React Integration

### Existing Hooks

Speakeasy provides three hooks (`useIdentity`, `useTransport`, `useMessages`) that
manage identity lifecycle, transport connections, and message storage respectively.
The workbench uses React Context + `useReducer` for state management (the
`MultiPolicyState` / `multi-policy-store.tsx` pattern).

### Composition Strategy

The Clawdstrike workbench wraps the Speakeasy hooks inside a `SpeakeasyBridgeProvider`
context that mediates between Speakeasy's per-hook state and the workbench's
multi-policy-store pattern.

```
+-------------------------------------------------------+
|  MultiPolicyProvider  (existing workbench state root)  |
|                                                        |
|  +--------------------------------------------------+  |
|  |  SpeakeasyBridgeProvider  (new)                  |  |
|  |                                                  |  |
|  |  Wraps: useIdentity()  -> sentinelIdentityState  |  |
|  |  Wraps: useTransport() -> swarmConnectionState   |  |
|  |  Provides: useSpeakeasyBridge()                  |  |
|  |                                                  |  |
|  |  +----------------------------------------------+|  |
|  |  |  SwarmProvider  (new)                        ||  |
|  |  |                                              ||  |
|  |  |  Manages: swarm membership, intel store      ||  |
|  |  |  Uses: useMessages() per active room         ||  |
|  |  |  Provides: useSwarm(), useIntel()            ||  |
|  |  +----------------------------------------------+|  |
|  +--------------------------------------------------+  |
+-------------------------------------------------------+
```

### SpeakeasyBridgeProvider

```typescript
interface SpeakeasyBridgeContextValue {
  // Identity (from useIdentity)
  identity: BayChatIdentity | null;
  identityLoading: boolean;
  createIdentity: () => Promise<BayChatIdentity>;
  recoverIdentity: (seedPhrase: string[]) => Promise<BayChatIdentity>;

  // Transport (from useTransport)
  connectionState: ConnectionState;
  peers: KnownPeer[];
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;

  // Swarm operations (bridge layer)
  joinSwarm: (swarmId: string) => Promise<void>;
  leaveSwarm: (swarmId: string) => Promise<void>;
  activeSwarms: Map<string, SwarmTopics>;

  // Room operations (delegates to useTransport.joinSpeakeasy)
  openRoom: (speakeasyId: string) => Promise<SpeakeasyTopic>;
  closeRoom: (speakeasyId: string) => Promise<void>;
  activeRooms: Map<string, SpeakeasyTopic>;

  // Signing bridge
  signReceipt: (receipt: Receipt) => Promise<SignedReceipt>;
  signIntel: (content: Uint8Array) => Promise<string>;
}
```

The provider initializes transport with `autoConnect: false` and defers connection
until the user explicitly opts into swarm features. This preserves the local-first
design: a user who never touches swarm features incurs zero network overhead.

### Per-Room Message Stores

Each active speakeasy room gets its own `useMessages` instance. The `SwarmProvider`
maintains a `Map<string, UseMessagesReturn>` keyed by speakeasy ID. When a room
is opened, a new `useMessages({ identity, maxMessages: 1000 })` instance is created
and stored. When a room is closed, the instance is cleared and removed.

The `useMessages` hook's `addMessage` callback is wired to the `useTransport`'s
`onMessage` handler via topic routing:

```typescript
// Inside SpeakeasyBridgeProvider
const handleMessage = useCallback((topic: string, envelope: MessageEnvelope) => {
  // Route to the correct room's message store
  const parsed = parseSpeakeasyTopic(topic);
  if (parsed && parsed.type === 'messages') {
    const roomStore = roomStores.get(parsed.speakeasyId);
    if (roomStore) {
      roomStore.addMessage(envelope.payload);
    }
    return;
  }

  // Route swarm-level messages to the SwarmProvider
  const swarmParsed = parseSwarmTopic(topic);
  if (swarmParsed) {
    swarmDispatch({ type: 'swarm_message', swarmId: swarmParsed.swarmId,
                    channel: swarmParsed.channel, payload: envelope.payload });
  }
}, [roomStores, swarmDispatch]);
```

### Hook: useSpeakeasyRoom

A convenience hook for components that render a single room (the `SpeakeasyPanel`
component):

```typescript
function useSpeakeasyRoom(speakeasyId: string): {
  messages: AnyMessage[];
  sendChat: (content: string) => Promise<void>;
  sendIntelShare: (intel: Intel) => Promise<void>;
  sendFindingUpdate: (finding: Finding) => Promise<void>;
  pendingVerification: Set<string>;
  verificationFailed: Set<string>;
  members: SpeakeasyMember[];
  classification: 'routine' | 'sensitive' | 'restricted';
}
```

This hook composes `useContext(SpeakeasyBridgeContext)` to access the identity and
transport, and a room-specific `useMessages` instance from the room store map. It
also constructs domain-specific send helpers that call `createSignedMessage` with
the correct type discriminator and then `publish` to the room's message topic.

### Integration with Existing Workbench State

The workbench's `MultiPolicyState` reducer (in `multi-policy-store.tsx`) does not
need to absorb swarm state. Instead, swarm/speakeasy state lives in the parallel
`SpeakeasyBridgeProvider` and `SwarmProvider` contexts. Components that need both
(e.g., the Findings page promoting a finding to intel and sharing it to a swarm)
consume both contexts:

```typescript
function FindingPromoteButton({ finding }: { finding: Finding }) {
  const { state, dispatch } = useMultiPolicyStore();   // existing
  const { signReceipt, signIntel } = useSpeakeasyBridge();  // new
  const { publishIntel } = useSwarm();                  // new

  async function handlePromote() {
    const receipt = await signReceipt(buildFindingReceipt(finding));
    const intel = await buildIntelFromFinding(finding, receipt);
    const sig = await signIntel(canonicalize(intel));
    await publishIntel(intel, sig);
    dispatch({ type: 'FINDING_PROMOTED', findingId: finding.id, intelId: intel.id });
  }
  // ...
}
```

---

## 5. Room Lifecycle

### Room Creation

Speakeasy rooms (speakeasies) are created on-demand and attached to a Clawdstrike
object. The room ID is derived deterministically from the attachment point to ensure
idempotency (opening the same finding twice does not create two rooms).

```typescript
function deriveSpeakeasyId(
  purpose: ClawdstrikeSpeakeasy['purpose'],
  attachedToId: string,
  swarmId: string,
): string {
  // Deterministic: same inputs always produce same room ID
  const input = `clawdstrike:${purpose}:${swarmId}:${attachedToId}`;
  const hash = sha256(new TextEncoder().encode(input));
  return bytesToHex(hash).slice(0, 32); // 32 hex chars
}
```

### Room States

```
Created  -->  Active  -->  Archived
   |                          ^
   |                          |
   +--- (never opened) ------+
```

| State | Description | Transport Behavior |
|-------|-------------|-------------------|
| **Created** | Room ID derived, metadata stored locally, no transport subscription yet | No Gossipsub topics subscribed |
| **Active** | User or sentinel has opened the room; transport subscribed via `joinSpeakeasy(id)` | Subscribed to `messages`, `presence`, `typing` topics |
| **Archived** | Finding resolved, campaign closed, or manually archived; transport unsubscribed | `leaveSpeakeasy(id)` called; messages retained in local store for audit |

### Attachment Model

| Room Purpose | Attached To | Created When | Archived When |
|-------------|-------------|-------------|--------------|
| `finding` | Finding ID | Finding reaches `confirmed` status | Finding reaches `dismissed` or `false_positive` |
| `campaign` | Campaign ID (group of findings) | Operator creates campaign | Campaign closed |
| `incident` | Finding ID (critical severity) | Finding reaches `critical` + `confirmed` | Incident resolved |
| `coordination` | Swarm ID | Swarm created | Swarm dissolved |
| `mentoring` | Sentinel ID | Operator opens guidance session | Operator closes session |

### Room Metadata Storage

Room metadata is persisted locally (IndexedDB in browser, SQLite in Tauri):

```typescript
interface RoomRecord {
  speakeasyId: string;
  swarmId: string;
  purpose: ClawdstrikeSpeakeasy['purpose'];
  attachedTo: string;
  classification: 'routine' | 'sensitive' | 'restricted';
  createdAt: number;
  archivedAt?: number;
  memberFingerprints: string[];  // known participants
  lastActivity: number;
  messageCount: number;
}
```

### Message Retention

Active rooms keep the last 1000 messages in memory (via `useMessages`'s
`maxMessages` parameter). Archived rooms flush messages to local persistent
storage. The retention policy per classification:

| Classification | In-Memory | Persistent | Notes |
|---------------|-----------|------------|-------|
| `routine` | 1000 messages | 30 days | Auto-purge after TTL |
| `sensitive` | 500 messages | 90 days | Requires explicit delete |
| `restricted` | 200 messages | Until manual purge | Audit log of all access required |

---

## 6. Trust Model

### Layers of Trust

The trust model operates at three levels, each building on Speakeasy's
cryptographic primitives.

#### Layer 1: Cryptographic Identity Verification

Every message carries an Ed25519 signature verified by `verifyMessage()` in
`signing.ts`. The `useMessages` hook automatically rejects messages with invalid
signatures (they are added to `verificationFailed` and not included in the
`messages` array). This is the baseline: no message is displayed or acted upon
without a valid signature from a known public key.

Fingerprint verification follows the Speakeasy model: the 16-char hex fingerprint
formatted by `formatFingerprint()` (e.g., `a1b2-c3d4-e5f6-g7h8`) is verified
out-of-band by operators during the swarm onboarding ceremony. Once verified,
the fingerprint-to-public-key binding is stored in the local trust store.

#### Layer 2: Peer Reputation

Reputation is earned, not declared. The `ReputationTracker` scores swarm members
based on observed behavior:

| Signal | Weight | Direction |
|--------|--------|-----------|
| Intel shared that was subsequently ingested by peers | +3 | Positive |
| Intel shared that was rejected by peers | -1 | Negative |
| Detection rule that produced true-positive findings | +5 | Positive |
| Detection rule that produced only false positives | -2 | Negative |
| Consistent uptime and heartbeats | +1/day | Positive |
| Stale status (no heartbeat for >1 hour) | -1/hour | Negative |
| Finding confirmed by multiple independent sentinels | +2 per confirmer | Positive |
| Sybil-like behavior (many identities, same patterns) | -10 | Negative |

Reputation scores are local to each member's view. `ReputationVoteMessage` messages
allow peers to share attestations, but each member computes their own weighted
score independently. There is no global reputation oracle.

The swarm policy's `minReputation` threshold gates who can publish intel to the
swarm. Members below the threshold can still participate in rooms but cannot
push intel or detection rules to the shared feeds.

#### Layer 3: Compartmentalization

Rooms have a `classification` level that controls information flow:

| Classification | Who Can Join | Intel Flow | Message Retention |
|---------------|-------------|-----------|------------------|
| `routine` | Any swarm member | Unrestricted | Standard |
| `sensitive` | Invited members only (explicit `memberFingerprints` list) | Summary only, no raw evidence | Extended |
| `restricted` | Admin-approved, verified fingerprints | No outbound sharing | Permanent until manual purge |

Promotion of intel from a `restricted` room to a broader audience requires explicit
operator approval and automatic redaction of raw evidence. The `IntelShareMessage`
for such promotions carries only the `summary` field; `receiptJson` is stripped
of `metadata` contents.

### Swarm Membership Verification

Joining a swarm requires:

1. **Personal swarm:** Automatic. All of a user's own sentinels are members.
2. **Trusted swarm:** Invitation from an admin member. The invite is a signed
   `SentinelTaskMessage` with `taskType: 'join_invitation'` (special case).
   The invitee accepts by publishing a `SentinelStatusMessage` to the swarm's
   sentinel status topic.
3. **Federated swarm:** Discovery via `/baychat/v1/discovery` topic, followed by
   mutual fingerprint verification. The trust graph starts at minimum reputation;
   members must earn their way up.

### Sybil Resistance

Federated swarms are vulnerable to Sybil attacks. Mitigations:

- **Invitation chains:** Each member can only invite N new members (configurable
  per swarm policy). The inviter's reputation is partially staked on the invitee's
  behavior.
- **Proof of useful work:** Reputation accrues only from validated contributions
  (true-positive detections, confirmed findings). Creating many identities does not
  bypass this.
- **Anomaly detection:** The `ReputationTracker` flags patterns consistent with
  Sybil behavior (many new identities with correlated activity, suspiciously fast
  reputation accumulation).

---

## 7. Offline / Degraded Mode

### Design Principle: Local-First

The workbench must be fully functional with zero network connectivity. Swarm
features degrade gracefully; they never block the core sentinel workflow.

### Mode Detection

The `SpeakeasyBridgeProvider` tracks connection state via `useTransport`'s
`connectionState` field (values: `'disconnected' | 'connecting' | 'connected' |
'error'`). Components use this to adapt their UI:

```typescript
function useNetworkMode(): 'online' | 'degraded' | 'offline' {
  const { connectionState, peers } = useSpeakeasyBridge();

  if (connectionState !== 'connected') return 'offline';
  if (peers.length === 0) return 'degraded';  // connected but no peers
  return 'online';
}
```

### Offline Capabilities

| Capability | Offline Behavior |
|-----------|-----------------|
| Sentinel creation and configuration | Fully functional; identity generated locally |
| Signal ingestion and scoring | Fully functional; local sentinel loop operates normally |
| Finding triage and enrichment | Fully functional; all state is local |
| Intel creation and signing | Fully functional; signing is local Ed25519 |
| Room messages (read) | Locally cached messages available; no new messages received |
| Room messages (send) | **Queued** in outbox; delivered when transport reconnects |
| Intel sharing | **Queued** in outbox; published when transport reconnects |
| Detection sync | **Queued**; synced on reconnect |
| Reputation scoring | Frozen; no new votes received or sent |

### Message Outbox

When the transport is unavailable, all publish operations are queued in a local
outbox (IndexedDB). The outbox is a FIFO queue with per-message expiry.

```typescript
interface OutboxEntry {
  id: string;
  topic: string;
  envelope: MessageEnvelope;
  createdAt: number;
  expiresAt: number;       // messages expire if not sent within this window
  retryCount: number;
  maxRetries: number;
}
```

On reconnect, the `SpeakeasyBridgeProvider` drains the outbox in order, checking
`isEnvelopeValid()` (from `transport.ts`) before publishing. Expired entries are
discarded and logged. The outbox is capped at 500 entries to prevent unbounded
local storage growth.

### Reconnection Strategy

When the transport transitions from `'connected'` to `'disconnected'` or `'error'`:

1. Immediately: set `networkMode` to `'offline'`, enable outbox queuing.
2. After 5 seconds: attempt reconnect via `transport.start()`.
3. Exponential backoff: 5s, 10s, 20s, 40s, 60s max interval.
4. On success: drain outbox, re-subscribe to all previously active swarm and
   room topics (stored in `activeSwarms` and `activeRooms` maps).
5. On each failed attempt: increment a `reconnectAttempts` counter; after 10
   failures, stop auto-retry and surface a manual "Reconnect" button in the UI.

### Personal Swarm in Offline Mode

The personal swarm (a user's own sentinels coordinating) does not require the
Gossipsub network. When offline, personal swarm coordination falls back to
direct function calls within the same process:

```typescript
// Offline: sentinels communicate via in-process event bus
const localBus = new EventTarget();

function publishLocal(channel: string, message: ClawdstrikeAnyMessage): void {
  localBus.dispatchEvent(new CustomEvent(channel, { detail: message }));
}

function subscribeLocal(channel: string, handler: (msg: ClawdstrikeAnyMessage) => void): void {
  localBus.addEventListener(channel, (e) => handler((e as CustomEvent).detail));
}
```

This in-process bus uses the same message types and signing as the network path.
The `SwarmCoordinator` abstracts over both transports; callers do not know whether
messages are routed locally or over Gossipsub.

---

## 8. Security Considerations

### Replay Prevention

Speakeasy already implements replay prevention via three mechanisms:

1. **Nonce:** Every message includes a random 128-bit nonce (`generateNonce()` in
   `signing.ts`). The nonce is included in the signed hash, so replaying a message
   with a different nonce invalidates the signature.

2. **Timestamp tolerance:** `isTimestampRecent()` rejects messages older than 5
   minutes (configurable `toleranceMs`). This limits the replay window.

3. **Deduplication by ID:** The `useMessages` hook tracks seen message IDs via a
   `Set<string>` and silently drops duplicates (see the `seenIds` check in
   `addMessage`).

For Clawdstrike's higher-security context, additional measures:

| Threat | Mitigation |
|--------|-----------|
| Replay of `intel_share` from a revoked member | Receiver checks sender fingerprint against current swarm membership before ingesting. Revoked members' public keys are in a local deny-list. |
| Replay of `detection_sync` with outdated rule | `ruleVersion` field is monotonically increasing; receivers reject versions <= their stored version for the same `ruleId`. |
| Replay of `sentinel_task` to re-trigger work | Tasks are deduplicated by `taskId` (which is the message ID). The sentinel tracks completed task IDs and rejects duplicates. |
| Delayed delivery of queued outbox messages | Each `OutboxEntry` has an `expiresAt` field. `isEnvelopeValid()` is checked before publish. Recipients also apply timestamp tolerance. |

### Message Expiry

The `MessageEnvelope.created` timestamp combined with `isEnvelopeValid(envelope, maxAgeMs)`
(from `transport.ts`) provides envelope-level expiry. Default max age is 5 minutes.

For Clawdstrike messages, the max age varies by type:

| Message Type | Max Age | Rationale |
|-------------|---------|-----------|
| `signal_alert` | 2 minutes | Stale alerts lose operational value |
| `sentinel_status` | 5 minutes | Status should be recent |
| `intel_share`, `detection_sync` | 30 minutes | Higher value, may traverse slow paths |
| `finding_update` | 15 minutes | State changes remain relevant longer |
| `sentinel_task` | 10 minutes | Tasks should be timely |
| `intel_ack`, `reputation_vote` | 15 minutes | Feedback loops tolerate some delay |

The receiving end checks expiry via:

```typescript
function isClawdstrikeEnvelopeValid(envelope: MessageEnvelope): boolean {
  const maxAge = MESSAGE_TYPE_MAX_AGE[envelope.payload.type] ?? 5 * 60 * 1000;
  return isEnvelopeValid(envelope, maxAge);
}
```

### Compartmentalization Levels

Three classification levels map to data handling policies:

**Routine:**
- Messages are not encrypted beyond transport-layer Noise encryption (provided by
  libp2p's `noise()` connection encrypter in `transport.ts`).
- Intel can be shared freely to other swarms.
- No special audit requirements.

**Sensitive:**
- Room membership is restricted to an explicit allowlist of fingerprints.
- Raw signal data and evidence are stripped from `IntelShareMessage` before
  cross-room sharing; only `summary` and `contentHash` travel.
- All membership changes are logged locally with timestamps.

**Restricted:**
- Same as sensitive, plus:
- Messages include an additional application-layer encryption envelope
  (NaCl secretbox, key derived from room-specific shared secret distributed
  out-of-band).
- No intel can be shared out of the room without operator approval and automatic
  redaction review.
- Full audit trail of who read what message (presence + message receipt tracking).

### Integrity of Intel Artifacts

Intel artifacts carry a dual-signature provenance chain:

1. **Content signature:** Ed25519 signature over the SHA-256 hash of the intel's
   canonical JSON content. This is the `intelSignature` field in `IntelShareMessage`.
   Produced by `signData()` from `signing.ts`.

2. **Receipt:** A Clawdstrike `SignedReceipt` (from `receipt.rs` / `receipt.ts`)
   attesting to the finding-to-intel promotion decision. The receipt's
   `content_hash` covers the source finding's evidence, and the receipt's `verdict`
   records the promotion decision. Signed by the same sentinel identity via
   `signReceiptWithIdentity()`.

Receivers validate both signatures before ingesting intel:

```typescript
async function validateIntel(msg: IntelShareMessage): Promise<boolean> {
  // 1. Verify the Speakeasy message signature (sender authenticity)
  const msgValid = await verifyMessage(msg);
  if (!msgValid.valid) return false;

  // 2. Verify the intel content signature (content integrity)
  const contentBytes = new TextEncoder().encode(msg.contentHash);
  const contentValid = await verifyData(
    contentBytes,
    msg.intelSignature,
    msg.sender,
  );
  if (!contentValid) return false;

  // 3. If receipt is present, verify its signature chain
  if (msg.receiptJson) {
    const signedReceipt = SignedReceipt.fromJSON(msg.receiptJson);
    const result = await signedReceipt.verify({
      signer: msg.sender, // same identity
    });
    if (!result.valid) return false;
  }

  return true;
}
```

### Transport Security

The libp2p stack in `transport.ts` uses Noise encryption (`noise()` from
`@chainsafe/libp2p-noise`) for all peer connections. This provides:

- Authenticated key exchange (peers verify each other's libp2p PeerId).
- Forward secrecy for the transport session.
- Encryption of all Gossipsub messages in transit.

Note: Noise authenticates libp2p PeerIds, not Speakeasy public keys. The binding
between a libp2p PeerId and a Speakeasy identity is established at the application
layer via signed presence messages. A malicious relay can see encrypted traffic but
cannot forge message signatures (Ed25519 signing is end-to-end, not transport-dependent).

### Threat Summary

| Threat | Impact | Mitigation |
|--------|--------|-----------|
| Forged message | High | Ed25519 signature verification on every message; invalid messages dropped |
| Replay attack | Medium | Nonce + timestamp tolerance + dedup by message ID |
| Sybil attack (federated swarm) | High | Invitation chains, proof-of-useful-work reputation, anomaly detection |
| Compromised sentinel key | High | Revocation via swarm membership deny-list; key rotation via new BIP39 seed |
| Intel poisoning (bad detection rules) | High | Reputation gating on `detection_sync`; rules must be signed; receivers track rule efficacy |
| Traffic analysis | Low | Noise-encrypted transport; message padding not implemented (future work) |
| Denial of service (topic flooding) | Medium | TTL limits propagation; per-peer rate limiting in Gossipsub configuration |
| Compromised relay server | Low | End-to-end signatures prevent forgery; relay sees encrypted bytes only |
| Stale outbox messages after long offline | Low | Per-message expiry in outbox; `isEnvelopeValid()` check before publish |

---

## Appendix: File Reference

### Speakeasy Source Files

| File | Relevant Exports |
|------|-----------------|
| `backbay-sdk/packages/speakeasy/src/core/types.ts` | `BayChatIdentity`, `BaseMessage`, `MessageType`, `ChatMessage`, `SentinelRequest`, `SentinelResponse`, `PresenceMessage`, `AnyMessage`, `MessageEnvelope` (via transport types) |
| `backbay-sdk/packages/speakeasy/src/core/identity.ts` | `generateIdentity()`, `recoverIdentity()`, `computeFingerprint()`, `formatFingerprint()`, `saveIdentity()`, `loadIdentity()`, `getSecretKeyBytes()`, `canSign()` |
| `backbay-sdk/packages/speakeasy/src/core/signing.ts` | `computeMessageHash()`, `signMessage()`, `createSignedMessage()`, `verifyMessage()`, `signData()`, `verifyData()`, `generateNonce()`, `isTimestampRecent()` |
| `backbay-sdk/packages/speakeasy/src/core/sigil.ts` | `deriveSigil()`, `deriveColor()`, `deriveAccentColor()`, `SIGILS`, `SIGIL_METADATA` |
| `backbay-sdk/packages/speakeasy/src/transport/transport.ts` | `createTransport()`, `createEnvelope()`, `isEnvelopeValid()`, `decrementTtl()` |
| `backbay-sdk/packages/speakeasy/src/transport/topics.ts` | `TOPIC_PREFIX`, `GLOBAL_TOPICS`, `createSpeakeasyTopics()`, `getAllSpeakeasyTopics()`, `parseSpeakeasyTopic()` |
| `backbay-sdk/packages/speakeasy/src/transport/types.ts` | `Transport` interface, `NodeConfig`, `ConnectionState`, `SpeakeasyTopic`, `GlobalTopics`, `MessageEnvelope`, `KnownPeer`, `NetworkEvents` |
| `backbay-sdk/packages/speakeasy/src/react/useIdentity.ts` | `useIdentity()` hook |
| `backbay-sdk/packages/speakeasy/src/react/useTransport.ts` | `useTransport()` hook |
| `backbay-sdk/packages/speakeasy/src/react/useMessages.ts` | `useMessages()` hook |

### Clawdstrike Source Files

| File | Relevant Exports |
|------|-----------------|
| `crates/libs/hush-core/src/signing.rs` | `Keypair`, `PublicKey`, `Signature`, `Signer` trait, `verify_signature()` |
| `crates/libs/hush-core/src/receipt.rs` | `Receipt`, `SignedReceipt`, `Verdict`, `Provenance`, `PublicKeySet`, `VerificationResult` |
| `packages/sdk/hush-ts/src/receipt.ts` | `Receipt` class, `SignedReceipt` class, `Verdict`, `Provenance`, `PublicKeySet` |
| `packages/sdk/hush-ts/src/crypto/sign.ts` | `Keypair`, `generateKeypair()`, `signMessage()`, `verifySignature()` |

### Workbench Files (Existing, to Be Extended)

| File | Integration Point |
|------|------------------|
| `apps/workbench/src/lib/workbench/multi-policy-store.tsx` | Add swarm-related actions to reducer or compose with new provider |
| `apps/workbench/src/lib/workbench/hunt-types.ts` | Signal and Finding type evolution |
| `apps/workbench/src/App.tsx` | Add `SpeakeasyBridgeProvider` to provider stack |
| `apps/workbench/src/components/workbench/workbench-sidebar.tsx` | Add Swarms navigation item |
