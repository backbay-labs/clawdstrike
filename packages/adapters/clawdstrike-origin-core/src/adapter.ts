/**
 * Trust Adapter Interface
 *
 * Defines the contract that provider-specific adapters (Slack, GitHub, etc.)
 * must implement to participate in origin-aware security enforcement.
 */

import type {
  ApprovalDecision,
  ApprovalRequest,
  OriginContext,
  OriginProvider,
  ProviderMetadata,
  ProvenanceResult,
  Space,
} from "./types.js";

// ---------------------------------------------------------------------------
// Provider I/O types (opaque to the framework)
// ---------------------------------------------------------------------------

/** Raw event from a provider (e.g. Slack webhook, GitHub event). */
export interface ProviderEvent {
  /** Raw headers from the webhook/event. */
  headers: Record<string, string>;

  /** Raw body (string or parsed object). */
  body: unknown;

  /** Timestamp of receipt. */
  receivedAt: Date;

  /** Provider hint (for routing when multiple adapters are registered). */
  provider?: OriginProvider;
}

/**
 * Provider-specific payload for rendering (e.g. Slack Block Kit JSON,
 * Teams Adaptive Card, GitHub comment markdown).
 */
export interface ProviderPayload {
  /** Format identifier (e.g. "slack-blocks", "teams-adaptive-card"). */
  format: string;

  /** The rendered content. */
  content: unknown;
}

/** Raw response from a provider (e.g. interactive button callback). */
export interface ProviderResponse {
  /** Raw headers from the callback. */
  headers: Record<string, string>;

  /** Raw body (string or parsed object). */
  body: unknown;

  /** Timestamp of receipt. */
  receivedAt: Date;
}

// ---------------------------------------------------------------------------
// TrustAdapter interface
// ---------------------------------------------------------------------------

/**
 * A TrustAdapter bridges a specific messaging/collaboration provider
 * into the Clawdstrike origin-aware security framework.
 *
 * Implementations MUST be safe to call concurrently.
 */
export interface TrustAdapter {
  /** Provider identifier (e.g. "slack", "github"). */
  readonly provider: OriginProvider;

  /**
   * Validate the provenance (authenticity) of an incoming event.
   *
   * For example, verify the Slack signing secret or GitHub webhook HMAC.
   * Implementations MUST return `{ valid: false }` rather than throwing
   * when validation fails (fail-closed on errors is the caller's job).
   */
  validate(event: ProviderEvent): Promise<ProvenanceResult>;

  /**
   * Normalize a provider-specific event into a canonical OriginContext.
   *
   * This extracts the provider, tenant, space, actor, visibility, and
   * other security-relevant fields from the raw event payload.
   */
  normalize(event: ProviderEvent): Promise<OriginContext>;

  /**
   * Render an approval request in the provider's native format.
   *
   * For Slack this would produce Block Kit JSON; for GitHub, a PR comment
   * with reaction-based approval buttons, etc.
   */
  renderApprovalRequest(request: ApprovalRequest): Promise<ProviderPayload>;

  /**
   * Consume an approval response from the provider and parse it into
   * a canonical ApprovalDecision.
   */
  consumeApprovalResponse(response: ProviderResponse): Promise<ApprovalDecision>;

  /**
   * Derive policy-relevant tags from the origin context.
   *
   * Tags are used by the policy engine for enclave profile matching.
   * Examples: "visibility:public", "external-participants", "provider:slack".
   */
  deriveTags(context: OriginContext): string[];

  // -----------------------------------------------------------------------
  // Optional advanced methods
  // -----------------------------------------------------------------------

  /**
   * Enrich an origin context with additional identity information
   * from the provider (e.g. resolve Slack user ID to email, org membership).
   */
  enrichIdentity?(context: OriginContext): Promise<OriginContext>;

  /**
   * List spaces (channels, repos, etc.) accessible to the adapter
   * within the given tenant.
   */
  listSpaces?(tenantId: string): Promise<Space[]>;

  /**
   * Sync and return metadata about the provider's current capabilities
   * and configuration.
   */
  syncMetadata?(): Promise<ProviderMetadata>;
}
