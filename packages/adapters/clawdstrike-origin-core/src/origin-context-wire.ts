import type {
  ActorType,
  OriginContext,
  OriginProvider,
  ProvenanceConfidence,
  SpaceType,
  Visibility,
} from "./types.js";

/**
 * Canonical JSON shape used by the Rust runtime.
 * Client-facing TypeScript code should prefer `OriginContext`.
 */
export interface OriginContextWire {
  provider: OriginProvider;
  tenant_id?: string;
  space_id?: string;
  space_type?: SpaceType;
  thread_id?: string;
  actor_id?: string;
  actor_type?: ActorType;
  actor_role?: string;
  visibility?: Visibility;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  provenance_confidence?: ProvenanceConfidence;
  metadata?: Record<string, unknown>;
}

/**
 * Accepts either the camelCase client shape, the canonical snake_case wire
 * shape, or a mixed payload while normalizing to `OriginContext`.
 *
 * When both aliases are present, camelCase wins.
 */
export interface OriginContextInput {
  provider: OriginProvider;
  tenantId?: string;
  tenant_id?: string;
  spaceId?: string;
  space_id?: string;
  spaceType?: SpaceType;
  space_type?: SpaceType;
  threadId?: string;
  thread_id?: string;
  actorId?: string;
  actor_id?: string;
  actorType?: ActorType;
  actor_type?: ActorType;
  actorRole?: string;
  actor_role?: string;
  visibility?: Visibility;
  externalParticipants?: boolean;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  provenanceConfidence?: ProvenanceConfidence;
  provenance_confidence?: ProvenanceConfidence;
  metadata?: Record<string, unknown>;
}

function firstDefined<T>(...values: Array<T | undefined>): T | undefined {
  return values.find((value) => value !== undefined);
}

/**
 * Normalizes camelCase and snake_case origin payloads into the client-facing
 * `OriginContext` shape used throughout the adapter API.
 */
export function normalizeOriginContext(input: OriginContextInput): OriginContext {
  return {
    provider: input.provider,
    tenantId: firstDefined(input.tenantId, input.tenant_id),
    spaceId: firstDefined(input.spaceId, input.space_id),
    spaceType: firstDefined(input.spaceType, input.space_type),
    threadId: firstDefined(input.threadId, input.thread_id),
    actorId: firstDefined(input.actorId, input.actor_id),
    actorType: firstDefined(input.actorType, input.actor_type),
    actorRole: firstDefined(input.actorRole, input.actor_role),
    visibility: input.visibility,
    externalParticipants: firstDefined(
      input.externalParticipants,
      input.external_participants,
    ),
    tags: [...(input.tags ?? [])],
    sensitivity: input.sensitivity,
    provenanceConfidence: firstDefined(
      input.provenanceConfidence,
      input.provenance_confidence,
    ),
    metadata: input.metadata ? { ...input.metadata } : undefined,
  };
}

/**
 * Serializes an origin context into the canonical snake_case payload expected
 * by the Rust runtime.
 */
export function toWireOriginContext(input: OriginContextInput): OriginContextWire {
  const normalized = normalizeOriginContext(input);
  const wire: OriginContextWire = {
    provider: normalized.provider,
    tags: [...normalized.tags],
  };

  if (normalized.tenantId !== undefined) {
    wire.tenant_id = normalized.tenantId;
  }
  if (normalized.spaceId !== undefined) {
    wire.space_id = normalized.spaceId;
  }
  if (normalized.spaceType !== undefined) {
    wire.space_type = normalized.spaceType;
  }
  if (normalized.threadId !== undefined) {
    wire.thread_id = normalized.threadId;
  }
  if (normalized.actorId !== undefined) {
    wire.actor_id = normalized.actorId;
  }
  if (normalized.actorType !== undefined) {
    wire.actor_type = normalized.actorType;
  }
  if (normalized.actorRole !== undefined) {
    wire.actor_role = normalized.actorRole;
  }
  if (normalized.visibility !== undefined) {
    wire.visibility = normalized.visibility;
  }
  if (normalized.externalParticipants !== undefined) {
    wire.external_participants = normalized.externalParticipants;
  }
  if (normalized.sensitivity !== undefined) {
    wire.sensitivity = normalized.sensitivity;
  }
  if (normalized.provenanceConfidence !== undefined) {
    wire.provenance_confidence = normalized.provenanceConfidence;
  }
  if (normalized.metadata !== undefined) {
    wire.metadata = { ...normalized.metadata };
  }

  return wire;
}
