/**
 * Workbench swarm engine — internal port of the former `@clawdstrike/swarm-engine`
 * package. Only the guard-gated spawn + bookkeeping surface is kept; the
 * consensus, HNSW memory, and protocol-bridge subsystems were dropped during
 * the fold per a prior viability audit.
 */

export * from "./types";
export * from "./events";
export { TopologyManager } from "./topology";
export type { AdaptiveThresholds } from "./topology";
export { AgentRegistry } from "./agent-registry";
export type { AgentRegistryConfig } from "./agent-registry";
export { TaskGraph } from "./task-graph";
export type { TaskGraphConfig } from "./task-graph";
export { generateSwarmId } from "./ids";
export type { SwarmEngineIdPrefix } from "./ids";
export { AgentPool } from "./agent-pool";
export { SwarmOrchestrator } from "./orchestrator";
export type { SwarmOrchestratorConfig } from "./orchestrator";
