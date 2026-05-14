/** @clawdstrike/swarm-engine */

export * from "./types.js";
export * from "./events.js";
export { Deque, PriorityQueue } from "./collections.js";
export { TopologyManager } from "./topology.js";
export type { AdaptiveThresholds } from "./topology.js";
export { AgentRegistry } from "./agent-registry.js";
export type { AgentRegistryConfig } from "./agent-registry.js";
export { TaskGraph } from "./task-graph.js";
export type { TaskGraphConfig } from "./task-graph.js";
export { generateSwarmId } from "./ids.js";
export type { SwarmEngineIdPrefix } from "./ids.js";

export { AgentPool } from "./agent-pool.js";
export { SwarmOrchestrator } from "./orchestrator.js";
export type { SwarmOrchestratorConfig } from "./orchestrator.js";
export {
  ProtocolBridge,
  TOPIC_PREFIX,
  EVENT_TO_CHANNEL,
  swarmIntelTopic,
  swarmSignalTopic,
  swarmDetectionTopic,
  swarmCoordinationTopic,
  swarmAgentsTopic,
  swarmTasksTopic,
  swarmTopologyTopic,
  swarmConsensusTopic,
  swarmMemoryTopic,
  swarmHooksTopic,
  parseSwarmTopic,
  getSwarmTopics,
} from "./protocol.js";
export type {
  ProtocolBridgeConfig,
  ExtendedSwarmChannel,
  ParsedSwarmTopic,
  GetSwarmTopicsOptions,
} from "./protocol.js";
