/**
 * Swarm Coordinator -- networking layer for swarm intel distribution.
 *
 * Wraps a TransportAdapter (which may be backed by @backbay/speakeasy's
 * Gossipsub transport or the in-process event bus) to provide typed
 * publish/subscribe for Intel, Signal, and Detection messages across swarms.
 *
 * This is a pure-function + class module (no React).
 *
 * @see docs/plans/sentinel-swarm/INDEX.md -- section 5 (Speakeasy integration)
 * @see docs/plans/sentinel-swarm/SPEAKEASY-INTEGRATION.md -- section 3 (topics), section 7 (offline)
 * @see docs/plans/sentinel-swarm/SIGNAL-PIPELINE.md -- section 7 (feedback loop)
 */

import type {
  Swarm,
  SwarmType,
  SwarmMember,
  SwarmPolicy,
  SwarmStats,
  IntelRef,
  DetectionRef,
  SpeakeasyRef,
  Intel,
  Signal,
} from "@/lib/workbench/sentinel-types";

import { generateId } from "@/lib/workbench/sentinel-types";


/** Protocol prefix, matching @backbay/speakeasy TOPIC_PREFIX. */
const TOPIC_PREFIX = "/baychat/v1";

/** Default TTL for intel/detection envelopes (full mesh propagation). */
const DEFAULT_INTEL_TTL = 10;

/** Default TTL for signal envelopes (scoped, prevent flooding). */
const DEFAULT_SIGNAL_TTL = 3;

/** Default TTL for coordination envelopes. */
const DEFAULT_COORDINATION_TTL = 5;

/** Maximum outbox entries before oldest are evicted. */
const DEFAULT_OUTBOX_MAX_SIZE = 500;

/** Default message expiry in milliseconds (5 minutes). */
const DEFAULT_MESSAGE_EXPIRY_MS = 5 * 60 * 1000;

/** Initial reconnect delay (ms). */
const RECONNECT_INITIAL_DELAY_MS = 5_000;

/** Maximum reconnect delay (ms). */
const RECONNECT_MAX_DELAY_MS = 60_000;

/** Maximum reconnect attempts before giving up auto-retry. */
const RECONNECT_MAX_ATTEMPTS = 10;

/** Envelope protocol version. */
const ENVELOPE_VERSION = 1 as const;


/**
 * Envelope type for swarm messages. Matches the Speakeasy MessageEnvelope
 * pattern but is independent of the libp2p types so that the coordinator
 * can work with any transport backend (Gossipsub, in-process, mock).
 */
export interface SwarmEnvelope {
  /** Protocol version. Always 1. */
  version: typeof ENVELOPE_VERSION;
  /**
   * Envelope type for routing.
   * Extends the Speakeasy MessageEnvelope.type with swarm-specific categories.
   */
  type: "intel" | "signal" | "detection" | "coordination" | "status";
  /** Signed message payload. Opaque to the transport layer. */
  payload: unknown;
  /** TTL in Gossipsub hops. */
  ttl: number;
  /** Timestamp when envelope was created (Unix ms). */
  created: number;
}

/**
 * Detection rule message payload for swarm distribution.
 * Mirrors DetectionSyncMessage from SPEAKEASY-INTEGRATION.md section 2.
 */
export interface DetectionMessage {
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


/**
 * Build the intel topic for a swarm.
 * Published intel artifacts (IntelShareMessage, IntelAckMessage).
 */
export function swarmIntelTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/intel`;
}

/**
 * Build the shared signal stream topic for a swarm (opt-in, high volume).
 */
export function swarmSignalTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/signals`;
}

/**
 * Build the detection rule sync topic for a swarm.
 */
export function swarmDetectionTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/detections`;
}

/**
 * Build the coordination topic for a swarm.
 * Findings, tasks, reports (FindingUpdateMessage, SentinelTaskMessage, SentinelReportMessage).
 */
export function swarmCoordinationTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/coordination`;
}

/**
 * Build the per-sentinel heartbeat/status topic.
 */
export function sentinelStatusTopic(sentinelId: string): string {
  return `${TOPIC_PREFIX}/sentinel/${sentinelId}/status`;
}

/** Valid swarm topic channel names. */
export type SwarmChannel = "intel" | "signals" | "detections" | "coordination";

/** Parsed swarm topic information. */
export interface ParsedSwarmTopic {
  swarmId: string;
  channel: SwarmChannel;
}

/**
 * Parse a swarm topic string and extract the swarmId and channel.
 * Returns null if the topic does not match the swarm topic pattern.
 */
export function parseSwarmTopic(topic: string): ParsedSwarmTopic | null {
  const prefix = `${TOPIC_PREFIX}/swarm/`;
  if (!topic.startsWith(prefix)) return null;

  const remainder = topic.slice(prefix.length);
  const slashIdx = remainder.indexOf("/");
  if (slashIdx === -1) return null;

  const swarmId = remainder.slice(0, slashIdx);
  const channel = remainder.slice(slashIdx + 1);

  if (
    channel !== "intel" &&
    channel !== "signals" &&
    channel !== "detections" &&
    channel !== "coordination"
  ) {
    return null;
  }

  return { swarmId, channel };
}

/**
 * Get all subscribable topics for a swarm.
 * The signals topic is NOT included by default (opt-in per spec).
 */
export function getSwarmTopics(
  swarmId: string,
  includeSignals = false,
): string[] {
  const topics = [
    swarmIntelTopic(swarmId),
    swarmDetectionTopic(swarmId),
    swarmCoordinationTopic(swarmId),
  ];
  if (includeSignals) {
    topics.push(swarmSignalTopic(swarmId));
  }
  return topics;
}


/**
 * Abstract transport interface for swarm networking.
 *
 * This is deliberately NOT the real Speakeasy Transport interface -- it is a
 * thin contract so that:
 *   - The coordinator can be tested with a mock
 *   - The InProcessEventBus can implement the same interface for personal swarms
 *   - The real Speakeasy transport can be adapted with a thin wrapper
 *
 * @see /backbay-sdk/packages/speakeasy/src/transport/types.ts -- Transport
 */
export interface TransportAdapter {
  /** Subscribe to a Gossipsub topic. Idempotent. */
  subscribe(topic: string): void;
  /** Unsubscribe from a Gossipsub topic. Idempotent. */
  unsubscribe(topic: string): void;
  /** Publish a SwarmEnvelope to a topic. Rejects if transport is disconnected. */
  publish(topic: string, envelope: SwarmEnvelope): Promise<void>;
  /** Register a handler for incoming messages on any subscribed topic. */
  onMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void;
  /** Remove a previously registered message handler. */
  offMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void;
  /** Whether the transport layer is connected to the network. */
  isConnected(): boolean;
}


/** Create a SwarmEnvelope with the given type, payload, and TTL. */
export function createSwarmEnvelope(
  type: SwarmEnvelope["type"],
  payload: unknown,
  ttl?: number,
): SwarmEnvelope {
  const defaultTtl =
    type === "intel" || type === "detection"
      ? DEFAULT_INTEL_TTL
      : type === "signal"
        ? DEFAULT_SIGNAL_TTL
        : DEFAULT_COORDINATION_TTL;

  return {
    version: ENVELOPE_VERSION,
    type,
    payload,
    ttl: ttl ?? defaultTtl,
    created: Date.now(),
  };
}


/** A single queued message waiting for transport reconnection. */
export interface OutboxEntry {
  /** Unique entry ID. */
  id: string;
  /** Destination topic. */
  topic: string;
  /** The envelope to publish. */
  envelope: SwarmEnvelope;
  /** When the entry was queued (Unix ms). */
  createdAt: number;
  /** Deadline after which the message is stale and should be discarded (Unix ms). */
  expiresAt: number;
  /** Number of publish attempts so far. */
  retryCount: number;
}

/**
 * FIFO message outbox for offline/degraded mode.
 *
 * When the transport is disconnected, the SwarmCoordinator queues publish
 * operations here. On reconnection, `flush()` drains the queue in order.
 *
 * @see docs/plans/sentinel-swarm/SPEAKEASY-INTEGRATION.md -- section 7 (offline)
 */
export class MessageOutbox {
  private readonly queue: OutboxEntry[] = [];
  private readonly maxSize: number;
  private readonly messageExpiryMs: number;

  constructor(
    maxSize: number = DEFAULT_OUTBOX_MAX_SIZE,
    messageExpiryMs: number = DEFAULT_MESSAGE_EXPIRY_MS,
  ) {
    this.maxSize = maxSize;
    this.messageExpiryMs = messageExpiryMs;
  }

  /** Enqueue a message for later delivery. Evicts oldest if at capacity. */
  enqueue(topic: string, envelope: SwarmEnvelope): void {
    const now = Date.now();

    // Evict expired entries first
    this.evictExpired(now);

    // If still at capacity, drop the oldest entry
    if (this.queue.length >= this.maxSize) {
      this.queue.shift();
    }

    this.queue.push({
      id: crypto.randomUUID(),
      topic,
      envelope,
      createdAt: now,
      expiresAt: now + this.messageExpiryMs,
      retryCount: 0,
    });
  }

  /**
   * Flush all valid queued messages through the provided transport.
   * Expired entries are discarded. Returns the count of successfully sent messages.
   */
  async flush(transport: TransportAdapter): Promise<number> {
    const now = Date.now();
    let sent = 0;

    while (this.queue.length > 0) {
      const entry = this.queue[0]!;

      // Discard expired
      if (entry.expiresAt <= now) {
        this.queue.shift();
        continue;
      }

      // Attempt publish
      try {
        await transport.publish(entry.topic, entry.envelope);
        this.queue.shift();
        sent++;
      } catch {
        // Transport failed mid-flush; stop draining and leave remaining for next attempt
        entry.retryCount++;
        break;
      }
    }

    return sent;
  }

  /** Number of entries currently queued. */
  get size(): number {
    return this.queue.length;
  }

  /** Remove all entries (e.g., on user logout). */
  clear(): void {
    this.queue.length = 0;
  }

  /** Peek at queued entries (read-only snapshot). */
  peek(): readonly OutboxEntry[] {
    return [...this.queue];
  }

  /** Evict all entries whose expiresAt is in the past. */
  private evictExpired(now: number): void {
    while (this.queue.length > 0 && this.queue[0]!.expiresAt <= now) {
      this.queue.shift();
    }
  }
}


/**
 * In-process transport adapter for personal swarm coordination.
 *
 * Uses EventTarget internally for immediate, same-process delivery. No
 * network traffic. This ensures sentinel code has a single coordination
 * path regardless of swarm type (personal vs. networked).
 *
 * @see docs/plans/sentinel-swarm/SPEAKEASY-INTEGRATION.md -- section 7 (personal swarm offline)
 * @see docs/plans/sentinel-swarm/SIGNAL-PIPELINE.md -- section 9.5 (offline/local-only mode)
 */
export class InProcessEventBus implements TransportAdapter {
  private readonly target = new EventTarget();
  private readonly subscriptions = new Set<string>();
  private readonly handlers = new Map<
    (topic: string, envelope: SwarmEnvelope) => void,
    (event: Event) => void
  >();

  /** Personal swarm bus is always "connected". */
  isConnected(): boolean {
    return true;
  }

  subscribe(topic: string): void {
    if (this.subscriptions.has(topic)) return;
    this.subscriptions.add(topic);
  }

  unsubscribe(topic: string): void {
    this.subscriptions.delete(topic);
  }

  async publish(topic: string, envelope: SwarmEnvelope): Promise<void> {
    // Only deliver to topics we are subscribed to (mimics Gossipsub behavior)
    if (!this.subscriptions.has(topic)) return;

    // Dispatch asynchronously to avoid stack overflow in tight loops,
    // but still within the same tick for test predictability.
    const event = new CustomEvent(topic, { detail: envelope });
    this.target.dispatchEvent(event);
  }

  onMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void {
    // Create a listener that fires for any subscribed topic
    const listener = (event: Event): void => {
      const ce = event as CustomEvent<SwarmEnvelope>;
      handler(ce.type, ce.detail);
    };
    this.handlers.set(handler, listener);

    // Subscribe the listener to all currently subscribed topics
    for (const topic of this.subscriptions) {
      this.target.addEventListener(topic, listener);
    }
  }

  offMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void {
    const listener = this.handlers.get(handler);
    if (!listener) return;

    for (const topic of this.subscriptions) {
      this.target.removeEventListener(topic, listener);
    }
    this.handlers.delete(handler);
  }

  /**
   * Must be called after subscribe() when handlers are already registered,
   * to ensure existing handlers receive events on the newly subscribed topic.
   * Called internally by SwarmCoordinator.joinSwarm().
   */
  refreshHandlers(): void {
    for (const [handler, listener] of this.handlers) {
      for (const topic of this.subscriptions) {
        // Remove first to avoid double-registration
        this.target.removeEventListener(topic, listener);
        this.target.addEventListener(topic, listener);
      }
    }
  }
}


export type IntelHandler = (swarmId: string, intel: Intel) => void;
export type SignalHandler = (swarmId: string, signal: Signal) => void;
export type DetectionHandler = (swarmId: string, detection: DetectionMessage) => void;

/**
 * Event emitted when a policy evaluation occurs on an agent within a swarm.
 * Used to drive the "evaluating" glow state on agent session board nodes.
 */
export interface PolicyEvaluatedEvent {
  /** The agent session ID that evaluated the policy. */
  agentId: string;
  /** Hash of the policy that was evaluated. */
  policyHash: string;
  /** Verdict of the evaluation, if available. */
  verdict?: "allow" | "deny" | "warn";
  /** Timestamp when the evaluation occurred (Unix ms). */
  timestamp: number;
}

export type PolicyEvaluatedHandler = (swarmId: string, event: PolicyEvaluatedEvent) => void;

/**
 * Event emitted when a new member joins a swarm.
 * Used to drive live trust graph updates (add agent node to board).
 */
export interface MemberJoinedEvent {
  /** Unique member identifier (fingerprint or session ID). */
  memberId: string;
  /** Agent model name (e.g., "claude-3", "gpt-4"). */
  agentModel?: string;
  /** Policy mode the agent is running under. */
  policyMode?: string;
  /** Timestamp when the member joined (Unix ms). */
  timestamp: number;
}

/**
 * Event emitted when a member leaves a swarm.
 * Used to drive live trust graph updates (fade + remove agent node from board).
 */
export interface MemberLeftEvent {
  /** Unique member identifier (fingerprint or session ID). */
  memberId: string;
  /** Reason for leaving. */
  reason?: "disconnect" | "retire" | "timeout";
  /** Timestamp when the member left (Unix ms). */
  timestamp: number;
}

export type MemberJoinedHandler = (swarmId: string, event: MemberJoinedEvent) => void;
export type MemberLeftHandler = (swarmId: string, event: MemberLeftEvent) => void;


/**
 * Core networking layer for swarm intel distribution.
 *
 * Wraps a TransportAdapter (Gossipsub or in-process) and provides:
 * - Swarm lifecycle (create, join, leave)
 * - Typed publish for Intel, Signal, and Detection messages
 * - Typed subscribe for incoming messages
 * - Automatic offline queuing via MessageOutbox
 * - Exponential backoff reconnection
 *
 * This class is framework-agnostic (no React). React integration is handled
 * by the SwarmProvider context that wraps this coordinator.
 *
 * @see docs/plans/sentinel-swarm/INDEX.md -- section 5, section 7
 */
export class SwarmCoordinator {
  private readonly transport: TransportAdapter;
  private readonly outbox: MessageOutbox;

  /** Swarms we are currently joined to (swarmId -> topic set). */
  private readonly activeSwarms = new Map<string, string[]>();

  /** Whether the signal topic is subscribed per-swarm. */
  private readonly signalSubscriptions = new Set<string>();

  /** Registered handlers. */
  private readonly intelHandlers = new Set<IntelHandler>();
  private readonly signalHandlers = new Set<SignalHandler>();
  private readonly detectionHandlers = new Set<DetectionHandler>();
  private readonly policyEvaluatedHandlers = new Set<PolicyEvaluatedHandler>();
  private readonly memberJoinedHandlers = new Set<MemberJoinedHandler>();
  private readonly memberLeftHandlers = new Set<MemberLeftHandler>();

  /** Bound message router (stored so it can be unregistered on destroy). */
  private readonly boundRouter: (topic: string, envelope: SwarmEnvelope) => void;

  /** Reconnection state. */
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private destroyed = false;

  constructor(
    transport: TransportAdapter,
    outbox?: MessageOutbox,
  ) {
    this.transport = transport;
    this.outbox = outbox ?? new MessageOutbox();
    this.boundRouter = this.routeMessage.bind(this);
    this.transport.onMessage(this.boundRouter);
  }


  /**
   * Create a new Swarm object (in-memory).
   * Does NOT subscribe to any topics -- call joinSwarm() for that.
   */
  createSwarm(config: CreateSwarmConfig): Swarm {
    return createSwarm(config);
  }

  /**
   * Join a swarm: add the member and subscribe to the swarm's topics.
   *
   * @param swarm - The swarm to join (mutated in place).
   * @param member - The new member to add.
   * @param subscribeSignals - Whether to subscribe to the high-volume signal topic (default false).
   * @returns The updated swarm.
   */
  joinSwarm(
    swarm: Swarm,
    member: SwarmMember,
    subscribeSignals = false,
  ): Swarm {
    // Add member to swarm data
    const updated = addMember(swarm, member);

    // Subscribe to swarm topics
    const topics = getSwarmTopics(swarm.id, subscribeSignals);
    for (const topic of topics) {
      this.transport.subscribe(topic);
    }

    this.activeSwarms.set(swarm.id, topics);

    if (subscribeSignals) {
      this.signalSubscriptions.add(swarm.id);
    }

    // If using InProcessEventBus, refresh handler registrations for new topics
    if (this.transport instanceof InProcessEventBus) {
      this.transport.refreshHandlers();
    }

    return updated;
  }

  /**
   * Leave a swarm: remove the member and unsubscribe from all topics.
   *
   * @param swarm - The swarm to leave (mutated in place).
   * @param memberId - Fingerprint of the member to remove.
   * @returns The updated swarm.
   */
  leaveSwarm(swarm: Swarm, memberId: string): Swarm {
    const updated = removeMember(swarm, memberId);

    // Unsubscribe from all swarm topics
    const topics = this.activeSwarms.get(swarm.id);
    if (topics) {
      for (const topic of topics) {
        this.transport.unsubscribe(topic);
      }
    }

    this.activeSwarms.delete(swarm.id);
    this.signalSubscriptions.delete(swarm.id);

    return updated;
  }

  /**
   * Toggle signal topic subscription for an already-joined swarm.
   */
  setSignalSubscription(swarmId: string, enabled: boolean): void {
    const topics = this.activeSwarms.get(swarmId);
    if (!topics) return;

    const signalTopic = swarmSignalTopic(swarmId);

    if (enabled && !this.signalSubscriptions.has(swarmId)) {
      this.transport.subscribe(signalTopic);
      topics.push(signalTopic);
      this.signalSubscriptions.add(swarmId);
    } else if (!enabled && this.signalSubscriptions.has(swarmId)) {
      this.transport.unsubscribe(signalTopic);
      const idx = topics.indexOf(signalTopic);
      if (idx !== -1) topics.splice(idx, 1);
      this.signalSubscriptions.delete(swarmId);
    }
  }


  /**
   * Publish an Intel artifact to a swarm's intel topic.
   * Queues in outbox if transport is disconnected.
   */
  async publishIntel(swarm: Swarm, intel: Intel): Promise<void> {
    const topic = swarmIntelTopic(swarm.id);
    const envelope = createSwarmEnvelope("intel", intel, DEFAULT_INTEL_TTL);
    await this.safePublish(topic, envelope);
  }

  /**
   * Publish a Signal to a swarm's signal topic (opt-in).
   * Queues in outbox if transport is disconnected.
   */
  async publishSignal(swarm: Swarm, signal: Signal): Promise<void> {
    const topic = swarmSignalTopic(swarm.id);
    const envelope = createSwarmEnvelope("signal", signal, DEFAULT_SIGNAL_TTL);
    await this.safePublish(topic, envelope);
  }

  /**
   * Publish a detection rule to a swarm's detection topic.
   * Queues in outbox if transport is disconnected.
   */
  async publishDetection(
    swarm: Swarm,
    detection: DetectionMessage,
  ): Promise<void> {
    const topic = swarmDetectionTopic(swarm.id);
    const envelope = createSwarmEnvelope("detection", detection, DEFAULT_INTEL_TTL);
    await this.safePublish(topic, envelope);
  }


  /** Register a handler for incoming Intel artifacts. */
  onIntelReceived(handler: IntelHandler): void {
    this.intelHandlers.add(handler);
  }

  /** Unregister an Intel handler. */
  offIntelReceived(handler: IntelHandler): void {
    this.intelHandlers.delete(handler);
  }

  /** Register a handler for incoming Signals. */
  onSignalReceived(handler: SignalHandler): void {
    this.signalHandlers.add(handler);
  }

  /** Unregister a Signal handler. */
  offSignalReceived(handler: SignalHandler): void {
    this.signalHandlers.delete(handler);
  }

  /** Register a handler for incoming Detection rules. */
  onDetectionReceived(handler: DetectionHandler): void {
    this.detectionHandlers.add(handler);
  }

  /** Unregister a Detection handler. */
  offDetectionReceived(handler: DetectionHandler): void {
    this.detectionHandlers.delete(handler);
  }

  /** Register a handler for policy evaluation events. */
  onPolicyEvaluated(handler: PolicyEvaluatedHandler): void {
    this.policyEvaluatedHandlers.add(handler);
  }

  /** Unregister a policy evaluation handler. */
  offPolicyEvaluated(handler: PolicyEvaluatedHandler): void {
    this.policyEvaluatedHandlers.delete(handler);
  }

  /**
   * Emit a policy evaluation event directly (for in-process swarms that
   * bypass transport). Dispatches to all registered handlers.
   */
  emitPolicyEvaluated(swarmId: string, event: PolicyEvaluatedEvent): void {
    for (const handler of this.policyEvaluatedHandlers) {
      try {
        handler(swarmId, event);
      } catch {
        // Handler errors should not break the emitter
      }
    }
  }

  /** Register a handler for member joined events. */
  onMemberJoined(handler: MemberJoinedHandler): void {
    this.memberJoinedHandlers.add(handler);
  }

  /** Unregister a member joined handler. */
  offMemberJoined(handler: MemberJoinedHandler): void {
    this.memberJoinedHandlers.delete(handler);
  }

  /** Register a handler for member left events. */
  onMemberLeft(handler: MemberLeftHandler): void {
    this.memberLeftHandlers.add(handler);
  }

  /** Unregister a member left handler. */
  offMemberLeft(handler: MemberLeftHandler): void {
    this.memberLeftHandlers.delete(handler);
  }

  /**
   * Emit a member joined event directly (for in-process swarms that
   * bypass transport). Dispatches to all registered handlers.
   */
  emitMemberJoined(swarmId: string, event: MemberJoinedEvent): void {
    for (const handler of this.memberJoinedHandlers) {
      try {
        handler(swarmId, event);
      } catch {
        // Handler errors should not break the emitter
      }
    }
  }

  /**
   * Emit a member left event directly (for in-process swarms that
   * bypass transport). Dispatches to all registered handlers.
   */
  emitMemberLeft(swarmId: string, event: MemberLeftEvent): void {
    for (const handler of this.memberLeftHandlers) {
      try {
        handler(swarmId, event);
      } catch {
        // Handler errors should not break the emitter
      }
    }
  }


  /**
   * Attempt to flush the outbox. Call this when the transport reconnects.
   * Returns the number of messages successfully sent.
   */
  async flushOutbox(): Promise<number> {
    if (!this.transport.isConnected()) return 0;
    return this.outbox.flush(this.transport);
  }

  /**
   * Start exponential-backoff reconnection polling.
   * Call this when the transport transitions to disconnected/error.
   *
   * @param reconnectFn - Async function that attempts to restart the transport.
   *   Return true if reconnection succeeded.
   * @param onGiveUp - Called after RECONNECT_MAX_ATTEMPTS failures.
   */
  startReconnect(
    reconnectFn: () => Promise<boolean>,
    onGiveUp?: () => void,
  ): void {
    if (this.destroyed) return;
    if (this.reconnectTimer !== null) return; // already reconnecting

    this.reconnectAttempts = 0;
    this.scheduleReconnect(reconnectFn, onGiveUp);
  }

  /** Stop reconnection polling. */
  stopReconnect(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = 0;
  }

  /** Current reconnect attempt count. */
  get currentReconnectAttempts(): number {
    return this.reconnectAttempts;
  }


  /** IDs of swarms we are currently joined to. */
  get joinedSwarmIds(): string[] {
    return Array.from(this.activeSwarms.keys());
  }

  /** Whether transport is currently connected. */
  get isConnected(): boolean {
    return this.transport.isConnected();
  }

  /** Number of messages waiting in the outbox. */
  get outboxSize(): number {
    return this.outbox.size;
  }

  /**
   * Tear down the coordinator. Unregisters the message router,
   * stops reconnection, and clears the outbox.
   */
  destroy(): void {
    this.destroyed = true;
    this.stopReconnect();
    this.transport.offMessage(this.boundRouter);
    this.intelHandlers.clear();
    this.signalHandlers.clear();
    this.detectionHandlers.clear();
    this.policyEvaluatedHandlers.clear();
    this.memberJoinedHandlers.clear();
    this.memberLeftHandlers.clear();
    this.activeSwarms.clear();
    this.signalSubscriptions.clear();
    this.outbox.clear();
  }


  /**
   * Publish via transport if connected, otherwise queue in outbox.
   */
  private async safePublish(
    topic: string,
    envelope: SwarmEnvelope,
  ): Promise<void> {
    if (this.transport.isConnected()) {
      try {
        await this.transport.publish(topic, envelope);
        return;
      } catch {
        // Transport claims connected but publish failed; fall through to outbox
      }
    }
    this.outbox.enqueue(topic, envelope);
  }

  /**
   * Route an incoming transport message to the appropriate typed handlers.
   */
  private routeMessage(topic: string, envelope: SwarmEnvelope): void {
    const parsed = parseSwarmTopic(topic);
    if (!parsed) return;

    // Only route messages for swarms we have joined
    if (!this.activeSwarms.has(parsed.swarmId)) return;

    switch (parsed.channel) {
      case "intel":
        if (envelope.type === "intel") {
          for (const handler of this.intelHandlers) {
            try {
              handler(parsed.swarmId, envelope.payload as Intel);
            } catch {
              // Handler errors should not break the router
            }
          }
        }
        break;

      case "signals":
        if (envelope.type === "signal") {
          for (const handler of this.signalHandlers) {
            try {
              handler(parsed.swarmId, envelope.payload as Signal);
            } catch {
              // Handler errors should not break the router
            }
          }
        }
        break;

      case "detections":
        if (envelope.type === "detection") {
          for (const handler of this.detectionHandlers) {
            try {
              handler(parsed.swarmId, envelope.payload as DetectionMessage);
            } catch {
              // Handler errors should not break the router
            }
          }
        }
        break;

      case "coordination": {
        // Route coordination messages to registered handlers by action type
        const payload = envelope.payload as Record<string, unknown> | null;
        if (!payload || typeof payload !== "object") break;

        if (payload.action === "policy_evaluated") {
          const event = payload as unknown as PolicyEvaluatedEvent;
          for (const handler of this.policyEvaluatedHandlers) {
            try {
              handler(parsed.swarmId, event);
            } catch {
              // Handler errors should not break the router
            }
          }
        } else if (payload.action === "member_joined") {
          const event = payload as unknown as MemberJoinedEvent;
          for (const handler of this.memberJoinedHandlers) {
            try {
              handler(parsed.swarmId, event);
            } catch {
              // Handler errors should not break the router
            }
          }
        } else if (payload.action === "member_left") {
          const event = payload as unknown as MemberLeftEvent;
          for (const handler of this.memberLeftHandlers) {
            try {
              handler(parsed.swarmId, event);
            } catch {
              // Handler errors should not break the router
            }
          }
        }
        break;
      }
    }
  }

  /**
   * Schedule a single reconnection attempt with exponential backoff.
   */
  private scheduleReconnect(
    reconnectFn: () => Promise<boolean>,
    onGiveUp?: () => void,
  ): void {
    if (this.destroyed) return;

    if (this.reconnectAttempts >= RECONNECT_MAX_ATTEMPTS) {
      this.reconnectTimer = null;
      onGiveUp?.();
      return;
    }

    const delay = Math.min(
      RECONNECT_INITIAL_DELAY_MS * Math.pow(2, this.reconnectAttempts),
      RECONNECT_MAX_DELAY_MS,
    );

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;

      if (this.destroyed) return;

      this.reconnectAttempts++;
      let success = false;

      try {
        success = await reconnectFn();
      } catch {
        success = false;
      }

      if (success) {
        this.reconnectAttempts = 0;
        // Re-subscribe to all previously active swarm topics
        for (const [swarmId, topics] of this.activeSwarms) {
          for (const topic of topics) {
            this.transport.subscribe(topic);
          }
        }
        // Drain the outbox
        await this.flushOutbox();
      } else {
        this.scheduleReconnect(reconnectFn, onGiveUp);
      }
    }, delay);
  }
}


/** Configuration for creating a new swarm. */
export interface CreateSwarmConfig {
  /** Display name for the swarm. */
  name: string;
  /** Swarm layer type. */
  type: SwarmType;
  /** Description. Defaults to empty string. */
  description?: string;
  /** Initial governance policies. Defaults are applied if omitted. */
  policies?: Partial<SwarmPolicy>;
}

/**
 * Create a new Swarm object with sensible defaults.
 * Pure function -- returns a new Swarm, does not subscribe to any topics.
 */
export function createSwarm(config: CreateSwarmConfig): Swarm {
  const id = generateId("swm");
  const now = Date.now();

  const defaultPolicy: SwarmPolicy = {
    minReputationToPublish: config.type === "federated" ? 0.3 : null,
    requireSignatures: true,
    autoShareDetections: config.type !== "federated",
    compartmentalized: config.type === "federated",
    requiredCapabilities: [],
    maxMembers: null,
  };

  return {
    id,
    name: config.name,
    type: config.type,
    description: config.description ?? "",
    members: [],
    sharedIntel: [],
    sharedDetections: [],
    trustGraph: [],
    policies: { ...defaultPolicy, ...config.policies },
    speakeasies: [],
    stats: {
      memberCount: 0,
      sentinelCount: 0,
      operatorCount: 0,
      intelShared: 0,
      activeDetections: 0,
      speakeasyCount: 0,
      avgReputation: 0,
    },
    topicPrefix: `${TOPIC_PREFIX}/swarm/${id}/`,
    createdAt: now,
    lastActivityAt: now,
  };
}

/**
 * Add a member to a swarm. Returns a new Swarm object (immutable update).
 * If a member with the same fingerprint already exists, returns the swarm unchanged.
 */
export function addMember(swarm: Swarm, member: SwarmMember): Swarm {
  if (swarm.members.some((m) => m.fingerprint === member.fingerprint)) {
    return swarm;
  }

  const members = [...swarm.members, member];
  const stats = recomputeStats(members, swarm.sharedIntel, swarm.sharedDetections, swarm.speakeasies);

  return {
    ...swarm,
    members,
    stats,
    lastActivityAt: Date.now(),
  };
}

/**
 * Remove a member from a swarm by fingerprint. Returns a new Swarm object.
 * If the member is not found, returns the swarm unchanged.
 */
export function removeMember(swarm: Swarm, fingerprint: string): Swarm {
  const filtered = swarm.members.filter((m) => m.fingerprint !== fingerprint);
  if (filtered.length === swarm.members.length) {
    return swarm;
  }

  const stats = recomputeStats(filtered, swarm.sharedIntel, swarm.sharedDetections, swarm.speakeasies);

  return {
    ...swarm,
    members: filtered,
    trustGraph: swarm.trustGraph.filter(
      (e) => e.from !== fingerprint && e.to !== fingerprint,
    ),
    stats,
    lastActivityAt: Date.now(),
  };
}

/**
 * Update swarm governance policies. Returns a new Swarm object.
 */
export function updateSwarmPolicy(
  swarm: Swarm,
  patch: Partial<SwarmPolicy>,
): Swarm {
  return {
    ...swarm,
    policies: { ...swarm.policies, ...patch },
    lastActivityAt: Date.now(),
  };
}

/**
 * Partial stat deltas for updating swarm statistics incrementally.
 */
export interface SwarmStatsDelta {
  intelShared?: number;
  activeDetections?: number;
  speakeasyCount?: number;
}

/**
 * Apply incremental stat deltas to a swarm. Returns a new Swarm object.
 */
export function updateSwarmStats(
  swarm: Swarm,
  delta: SwarmStatsDelta,
): Swarm {
  return {
    ...swarm,
    stats: {
      ...swarm.stats,
      intelShared: swarm.stats.intelShared + (delta.intelShared ?? 0),
      activeDetections: swarm.stats.activeDetections + (delta.activeDetections ?? 0),
      speakeasyCount: swarm.stats.speakeasyCount + (delta.speakeasyCount ?? 0),
    },
    lastActivityAt: Date.now(),
  };
}


/**
 * Recompute derived stats from current members and references.
 */
function recomputeStats(
  members: SwarmMember[],
  sharedIntel: IntelRef[],
  sharedDetections: DetectionRef[],
  speakeasies: SpeakeasyRef[],
): SwarmStats {
  const sentinelCount = members.filter((m) => m.type === "sentinel").length;
  const operatorCount = members.filter((m) => m.type === "operator").length;

  const totalReputation = members.reduce(
    (sum, m) => sum + m.reputation.overall,
    0,
  );
  const avgReputation = members.length > 0 ? totalReputation / members.length : 0;

  return {
    memberCount: members.length,
    sentinelCount,
    operatorCount,
    intelShared: sharedIntel.length,
    activeDetections: sharedDetections.length,
    speakeasyCount: speakeasies.length,
    avgReputation: Math.round(avgReputation * 1000) / 1000,
  };
}
