/**
 * Origin Enclaves - Core Types
 *
 * TypeScript mirror of the Rust OriginContext type and related structures
 * for origin-aware policy enforcement.
 */

// ---------------------------------------------------------------------------
// Provider & Enum Types
// ---------------------------------------------------------------------------

/** Origin provider identifier. Well-known providers are strongly typed; custom strings allowed. */
export type OriginProvider =
  | "slack"
  | "teams"
  | "github"
  | "jira"
  | "email"
  | "discord"
  | "webhook"
  | (string & {});

/** Type of space/channel where the originating event occurred. */
export type SpaceType =
  | "channel"
  | "group"
  | "dm"
  | "thread"
  | "issue"
  | "ticket"
  | "pull_request"
  | "email_thread"
  | (string & {});

/** Visibility of the originating space. */
export type Visibility =
  | "private"
  | "internal"
  | "public"
  | "external_shared"
  | "unknown";

/** Confidence level of provenance verification. */
export type ProvenanceConfidence = "strong" | "medium" | "weak" | "unknown";

/** Type of actor that initiated the action. */
export type ActorType = "human" | "bot" | "service" | "unknown";

// ---------------------------------------------------------------------------
// OriginContext
// ---------------------------------------------------------------------------

/**
 * Describes the origin of an agent invocation: where it came from,
 * who triggered it, and the security-relevant properties of the source.
 */
export interface OriginContext {
  /** Provider that originated the event (e.g. "slack", "github"). */
  provider: OriginProvider;

  /** Tenant/workspace ID within the provider. */
  tenantId?: string;

  /** Space (channel, repo, issue) ID within the tenant. */
  spaceId?: string;

  /** Type of the originating space. */
  spaceType?: SpaceType;

  /** Thread or sub-conversation ID within the space. */
  threadId?: string;

  /** Identity of the actor who triggered the event. */
  actorId?: string;

  /** Classification of the actor. */
  actorType?: ActorType;

  /** Role of the actor within the originating system. */
  actorRole?: string;

  /** Visibility of the originating space. */
  visibility?: Visibility;

  /** Whether external (non-org) participants are present. */
  externalParticipants?: boolean;

  /** Policy-relevant tags derived from the origin (defaults to []). */
  tags: string[];

  /** Sensitivity label (e.g. "public", "confidential", "restricted"). */
  sensitivity?: string;

  /** Confidence in the provenance of this origin context. */
  provenanceConfidence?: ProvenanceConfidence;

  /** Provider-specific metadata not covered by the common fields. */
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// ProvenanceResult
// ---------------------------------------------------------------------------

/** Result of validating the provenance (authenticity) of a provider event. */
export interface ProvenanceResult {
  /** Whether the event passed provenance validation. */
  valid: boolean;

  /** Confidence level of the validation. */
  confidence: ProvenanceConfidence;

  /** Provider that was validated. */
  provider: OriginProvider;

  /** Additional validation details. */
  details?: Record<string, unknown>;

  /** Error message if validation failed. */
  error?: string;
}

// ---------------------------------------------------------------------------
// Approval Flow
// ---------------------------------------------------------------------------

/** A request for human-in-the-loop approval, bound to an origin context. */
export interface ApprovalRequest {
  /** Unique identifier for this approval request. */
  id: string;

  /** Origin context that triggered the tool invocation. */
  originContext: OriginContext;

  /** Enclave profile that governs this action. */
  enclaveId: string;

  /** Name of the tool requiring approval. */
  toolName: string;

  /** Arguments to the tool (for display/audit). */
  toolArgs?: Record<string, unknown>;

  /** Human-readable reason the tool requires approval. */
  reason: string;

  /** Identity of the requester. */
  requestedBy: string;

  /** ISO 8601 timestamp when the request was created. */
  requestedAt: string;

  /** ISO 8601 timestamp when the request expires. */
  expiresAt?: string;
}

/** Decision on an approval request. */
export type ApprovalDecision =
  | { status: "approved"; approvedBy: string; scope?: ApprovalScope }
  | { status: "denied"; deniedBy: string; reason?: string }
  | { status: "expired" };

/** Scope constraints on an approved action. */
export interface ApprovalScope {
  /** Time-to-live in seconds for the approval. */
  ttlSeconds?: number;

  /** Restrict approval to the originating thread only. */
  threadOnly?: boolean;

  /** Restrict approval to the specific tool only. */
  toolOnly?: boolean;

  /** Hash of the arguments; approval is void if args change. */
  argumentHash?: string;
}

// ---------------------------------------------------------------------------
// Provider Discovery
// ---------------------------------------------------------------------------

/** Describes a space (channel, repo, issue) within a provider. */
export interface Space {
  /** Space identifier within the provider. */
  id: string;

  /** Human-readable name of the space. */
  name: string;

  /** Type of the space. */
  type: SpaceType;

  /** Visibility of the space. */
  visibility: Visibility;

  /** Provider-specific metadata. */
  metadata?: Record<string, unknown>;
}

/** Metadata about a provider's capabilities and sync state. */
export interface ProviderMetadata {
  /** Provider identifier. */
  provider: OriginProvider;

  /** List of supported capabilities (e.g. "approval", "identity-enrichment"). */
  capabilities: string[];

  /** Space types the provider supports. */
  supportedSpaceTypes: SpaceType[];

  /** ISO 8601 timestamp of the last metadata sync. */
  lastSynced?: string;
}
