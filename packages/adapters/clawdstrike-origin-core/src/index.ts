/**
 * @clawdstrike/origin-core
 *
 * Trust adapter framework for origin-aware security enforcement.
 * Provides the core types and interfaces that provider-specific
 * adapters (Slack, GitHub, Teams, etc.) implement.
 */

export type {
  ActorType,
  ApprovalDecision,
  ApprovalRequest,
  ApprovalScope,
  OriginContext,
  OriginProvider,
  ProviderMetadata,
  ProvenanceConfidence,
  ProvenanceResult,
  Space,
  SpaceType,
  Visibility,
} from "./types.js";

export type {
  OriginContextInput,
  OriginContextWire,
} from "./origin-context-wire.js";

export {
  normalizeOriginContext,
  toWireOriginContext,
} from "./origin-context-wire.js";

export type {
  ProviderEvent,
  ProviderPayload,
  ProviderResponse,
  TrustAdapter,
} from "./adapter.js";
