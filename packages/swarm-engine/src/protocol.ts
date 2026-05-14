/**
 * Protocol bridge, topic builders, and routing utilities for the swarm engine.
 *
 * @module
 */

import type {
  SwarmEngineEventMap,
  SwarmEngineEvent,
  SwarmEngineEnvelope,
} from "./events.js";
import { TypedEventEmitter } from "./events.js";

export const TOPIC_PREFIX = "/baychat/v1";

export function swarmIntelTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/intel`;
}

export function swarmSignalTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/signals`;
}

export function swarmDetectionTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/detections`;
}

export function swarmCoordinationTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/coordination`;
}

export function swarmAgentsTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/agents`;
}

export function swarmTasksTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/tasks`;
}

export function swarmTopologyTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/topology`;
}

export function swarmConsensusTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/consensus`;
}

export function swarmMemoryTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/memory`;
}

export function swarmHooksTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/hooks`;
}

/** Maps event kind to envelope channel type. */
export const EVENT_TO_CHANNEL: Record<string, SwarmEngineEnvelope["type"]> = {
  "agent.spawned": "agent_lifecycle",
  "agent.terminated": "agent_lifecycle",
  "agent.status_changed": "agent_lifecycle",
  "agent.heartbeat": "agent_lifecycle",
  "task.created": "task_orchestration",
  "task.assigned": "task_orchestration",
  "task.status_changed": "task_orchestration",
  "task.completed": "task_orchestration",
  "task.failed": "task_orchestration",
  "task.progress": "task_orchestration",
  "topology.updated": "topology",
  "topology.rebalanced": "topology",
  "topology.leader_elected": "topology",
  "consensus.proposed": "consensus",
  "consensus.vote_cast": "consensus",
  "consensus.resolved": "consensus",
  "memory.store": "memory",
  "memory.search": "memory",
  "hooks.triggered": "hooks",
  "hooks.completed": "hooks",
  "guard.evaluated": "coordination",
  "action.denied": "coordination",
  "action.completed": "coordination",
};

/** Maps envelope type to topic suffix. */
export const CHANNEL_TO_TOPIC_SUFFIX: Record<SwarmEngineEnvelope["type"], string> = {
  intel: "intel",
  signal: "signals",
  detection: "detections",
  coordination: "coordination",
  status: "status", // upstream SwarmEnvelope v1 compat; no engine event maps here
  agent_lifecycle: "agents",
  task_orchestration: "tasks",
  topology: "topology",
  consensus: "consensus",
  memory: "memory",
  hooks: "hooks",
};

export interface ProtocolBridgeConfig {
  swarmId: string;
  publish: (topic: string, envelope: SwarmEngineEnvelope) => Promise<void>;
  defaultTtl?: number;
}

const REPLAY_WINDOW_MS = 5 * 60 * 1000;

/**
 * Bridges internal events to the transport layer as SwarmEngineEnvelopes.
 * Transport errors are swallowed; the host handles retry.
 */
export class ProtocolBridge {
  private readonly unsubscribers: Array<() => void> = [];
  private readonly defaultTtl: number;
  /** Replay protection: most recent `created` timestamp per sender. */
  private readonly lastSeen: Map<string, number> = new Map();

  constructor(
    private readonly events: TypedEventEmitter<SwarmEngineEventMap>,
    private readonly config: ProtocolBridgeConfig,
  ) {
    this.defaultTtl = config.defaultTtl ?? 5;
  }

  connect(): void {
    if (this.unsubscribers.length > 0) {
      return;
    }

    for (const [eventKind, channel] of Object.entries(EVENT_TO_CHANNEL)) {
      const unsub = this.events.on(
        eventKind as keyof SwarmEngineEventMap,
        (data: unknown) => {
          const envelope: SwarmEngineEnvelope = {
            version: 1,
            type: channel,
            payload: data as SwarmEngineEvent,
            ttl: this.defaultTtl,
            created: Date.now(),
          };

          const sender =
            (data as Record<string, unknown>)?.sourceAgentId as
              | string
              | null
              | undefined;
          if (sender) {
            const prev = this.lastSeen.get(sender);
            if (
              prev !== undefined &&
              envelope.created < prev - REPLAY_WINDOW_MS
            ) {
              return;
            }
            this.lastSeen.set(sender, envelope.created);
          }

          const topicSuffix = CHANNEL_TO_TOPIC_SUFFIX[channel];
          const topic = `${TOPIC_PREFIX}/swarm/${this.config.swarmId}/${topicSuffix}`;
          this.config.publish(topic, envelope).catch(() => {});
        },
      );
      this.unsubscribers.push(unsub);
    }
  }

  disconnect(): void {
    for (const unsub of this.unsubscribers) unsub();
    this.unsubscribers.length = 0;
    this.lastSeen.clear();
  }

  dispose(): void {
    this.disconnect();
  }
}

export type ExtendedSwarmChannel =
  | "intel" | "signals" | "detections" | "coordination"
  | "agents" | "tasks" | "topology" | "consensus"
  | "memory" | "hooks";

export interface ParsedSwarmTopic {
  swarmId: string;
  channel: ExtendedSwarmChannel;
}

const VALID_CHANNELS = new Set<ExtendedSwarmChannel>([
  "intel", "signals", "detections", "coordination",
  "agents", "tasks", "topology", "consensus", "memory", "hooks",
]);

/** Returns null for invalid topics or unrecognized channels. */
export function parseSwarmTopic(topic: string): ParsedSwarmTopic | null {
  const prefix = `${TOPIC_PREFIX}/swarm/`;
  if (!topic.startsWith(prefix)) return null;
  const remainder = topic.slice(prefix.length);
  const slashIdx = remainder.indexOf("/");
  if (slashIdx === -1) return null;
  const swarmId = remainder.slice(0, slashIdx);
  const channel = remainder.slice(slashIdx + 1);
  if (!swarmId || !channel) return null;
  if (!VALID_CHANNELS.has(channel as ExtendedSwarmChannel)) return null;
  return { swarmId, channel: channel as ExtendedSwarmChannel };
}

export interface GetSwarmTopicsOptions {
  includeSignals?: boolean;
  includeConsensus?: boolean;
  includeMemory?: boolean;
  includeHooks?: boolean;
}

/**
 * Build topic strings for subscribing to a swarm's channels.
 * Accepts a deprecated boolean second arg for backward compat.
 */
export function getSwarmTopics(
  swarmId: string,
  optionsOrLegacyBoolean?: boolean | GetSwarmTopicsOptions,
): string[] {
  let options: GetSwarmTopicsOptions | undefined;
  if (typeof optionsOrLegacyBoolean === "boolean") {
    console.warn("[getSwarmTopics] boolean arg is deprecated, use options object");
    options = { includeSignals: optionsOrLegacyBoolean };
  } else {
    options = optionsOrLegacyBoolean;
  }
  const topics = [
    swarmIntelTopic(swarmId),
    swarmDetectionTopic(swarmId),
    swarmCoordinationTopic(swarmId),
    swarmAgentsTopic(swarmId),
    swarmTasksTopic(swarmId),
    swarmTopologyTopic(swarmId),
  ];
  if (options?.includeSignals) topics.push(swarmSignalTopic(swarmId));
  if (options?.includeConsensus) topics.push(swarmConsensusTopic(swarmId));
  if (options?.includeMemory) topics.push(swarmMemoryTopic(swarmId));
  if (options?.includeHooks) topics.push(swarmHooksTopic(swarmId));
  return topics;
}
