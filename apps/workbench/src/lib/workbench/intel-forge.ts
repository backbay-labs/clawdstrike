/**
 * Intel Forge -- promotion engine for creating, signing, and packaging Intel artifacts.
 *
 * All functions are pure (no React, no side effects) and operate on the types
 * defined in sentinel-types.ts.  The signing flow follows the spec in
 * docs/plans/sentinel-swarm/SIGNAL-PIPELINE.md section 6:
 *
 *   1. Extract signable fields from Intel
 *   2. Canonicalize using RFC 8785 (sorted keys, no whitespace)
 *   3. SHA-256 hash of the canonical JSON
 *   4. Ed25519 sign the hash
 *   5. Build receipt chain linking back to source findings
 *
 * @see docs/plans/sentinel-swarm/SIGNAL-PIPELINE.md#6-intel-promotion
 */

import type {
  Intel,
  IntelType,
  IntelContent,
  IntelContentPattern,
  IntelContentIoc,
  IntelContentDetectionRule,
  IntelContentCampaign,
  IntelContentAdvisory,
  IntelContentPolicyPatch,
  IntelShareability,
  MitreMapping,
  SentinelIdentity,
} from "./sentinel-types";

import type { Finding, Enrichment, MitreTechnique } from "./finding-engine";
import type { Signal } from "./signal-pipeline";
import type { Receipt } from "./types";
import {
  ED25519_PUBLIC_KEY_HEX,
  ED25519_SIGNATURE_HEX,
  signDetachedPayload,
  verifyDetachedPayload,
} from "./signature-adapter";
// ---------------------------------------------------------------------------
// Canonical JSON — single implementation lives in operator-crypto.ts.
// Imported for local use and re-exported for backward compatibility
// with existing imports (e.g. speakeasy-bridge.ts).
// ---------------------------------------------------------------------------
import { canonicalizeJson } from "./operator-crypto";
export { canonicalizeJson };

// ---------------------------------------------------------------------------
// ID Generation
// ---------------------------------------------------------------------------

let intelCounter = 0;

/**
 * Generate an intel ID with the `int_` prefix.
 *
 * Format: `int_<timestamp_b36><counter_b36><random_hex>`
 * The timestamp + counter prefix preserves sortability, while the 4
 * random hex chars (from crypto.getRandomValues) prevent collisions
 * when the module-level counter resets on page reload.
 */
export function generateIntelId(): string {
  const ts = Date.now().toString(36);
  const seq = (++intelCounter).toString(36).padStart(4, "0");
  const rnd = new Uint8Array(2);
  crypto.getRandomValues(rnd);
  const rndHex = Array.from(rnd)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `int_${ts}${seq}${rndHex}`;
}

// ---------------------------------------------------------------------------
// Promotion Config
// ---------------------------------------------------------------------------

/** Configuration for Intel promotion. */
export interface PromotionConfig {
  /** Title override. Falls back to finding title. */
  title?: string;
  /** Description. Falls back to auto-generated summary. */
  description?: string;
  /** Intel type override. Falls back to auto-detected type. */
  type?: IntelType;
  /** Shareability scope. Defaults to "private". */
  shareability?: IntelShareability;
  /** Additional tags. */
  tags?: string[];
  /** Author fingerprint (16 hex chars). */
  authorFingerprint: string;
  /** Content override. Falls back to auto-extracted content. */
  content?: IntelContent;
}

async function hashCanonicalValue(value: unknown): Promise<{
  bytes: Uint8Array;
  hex: string;
}> {
  const canonical = canonicalizeJson(value);
  const encoded = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    encoded.buffer as ArrayBuffer,
  );
  const hashBytes = new Uint8Array(hashBuffer);
  return {
    bytes: hashBytes,
    hex: Array.from(hashBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  };
}

// ---------------------------------------------------------------------------
// Content Hash
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 hash of the canonical JSON representation of Intel content.
 * Returns hex-encoded hash string. Used for deduplication across the swarm.
 */
export async function computeContentHash(intel: Intel): Promise<string> {
  const { hex } = await hashCanonicalValue(extractSignableFields(intel));
  return hex;
}

// ---------------------------------------------------------------------------
// Promote Finding -> Intel
// ---------------------------------------------------------------------------

/**
 * Auto-detect the best IntelType from a finding's enrichments and signals.
 */
function detectIntelType(finding: Finding, signals: Signal[]): IntelType {
  // Check for behavioral patterns
  const hasBehavioral = signals.some(
    (s) => s.type === "behavioral" || s.type === "anomaly",
  );
  // Check for IOC enrichments
  const hasIocs = finding.enrichments.some((e) => e.type === "ioc_extraction");
  // Check for detection rules
  const hasDetectionSignals = signals.some((s) => s.type === "detection");
  // Check for policy violations
  const hasPolicyViolations = signals.some(
    (s) => s.type === "policy_violation",
  );

  if (hasPolicyViolations) return "policy_patch";
  if (hasBehavioral) return "pattern";
  if (hasIocs) return "ioc";
  if (hasDetectionSignals) return "detection_rule";

  return "advisory";
}

/**
 * Extract IntelContent from a finding based on its enrichments and type.
 */
function extractContent(
  finding: Finding,
  signals: Signal[],
  intelType: IntelType,
): IntelContent {
  switch (intelType) {
    case "pattern":
      return extractPatternContent(finding, signals);
    case "ioc":
      return extractIocContent(finding);
    case "detection_rule":
      return extractDetectionRuleContent(finding);
    case "campaign":
      return extractCampaignContent(finding);
    case "advisory":
      return extractAdvisoryContent(finding);
    case "policy_patch":
      return extractPolicyPatchContent(finding);
  }
}

function extractPatternContent(
  finding: Finding,
  signals: Signal[],
): IntelContentPattern {
  // Extract pattern steps from behavioral signals
  const behavioralSignals = signals.filter(
    (s) =>
      finding.signalIds.includes(s.id) &&
      (s.type === "behavioral" || s.type === "anomaly"),
  );

  const sequence = behavioralSignals.map((s, idx) => ({
    step: idx + 1,
    actionType: s.data.actionType ?? ("file_access" as const),
    targetPattern:
      s.data.kind === "behavioral"
        ? (s.data.patternName ?? s.context.agentName)
        : s.context.agentName,
    timeWindow: undefined,
  }));

  return {
    kind: "pattern",
    sequence,
    matchCount: behavioralSignals.length,
    narrative: `Behavioral pattern detected from ${finding.signalCount} signals across ${finding.scope.agentIds.length} agent(s). ${finding.title}.`,
  };
}

function extractIocContent(finding: Finding): IntelContentIoc {
  const iocEnrichments = finding.enrichments.filter(
    (e) => e.type === "ioc_extraction",
  );

  const indicators: Array<{
    type: "hash" | "domain" | "ip" | "url" | "email" | "other";
    value: string;
    context?: string;
  }> = [];

  for (const enrichment of iocEnrichments) {
    const data = enrichment.data as Record<string, unknown>;
    const rawIndicators = data.indicators;
    if (Array.isArray(rawIndicators)) {
      for (const ind of rawIndicators) {
        const indObj = ind as Record<string, unknown>;
        indicators.push({
          type: normalizeIocType(String(indObj.iocType ?? "other")),
          value: String(indObj.indicator ?? ""),
          context: indObj.source ? String(indObj.source) : undefined,
        });
      }
    }
  }

  return {
    kind: "ioc",
    indicators,
    narrative: `${indicators.length} indicator(s) of compromise extracted from finding "${finding.title}".`,
  };
}

function normalizeIocType(
  raw: string,
): "hash" | "domain" | "ip" | "url" | "email" | "other" {
  const normalized = raw.toLowerCase();
  if (
    normalized === "hash" ||
    normalized === "sha256" ||
    normalized === "md5" ||
    normalized === "sha1"
  )
    return "hash";
  if (normalized === "domain") return "domain";
  if (normalized === "ip" || normalized === "ipv4" || normalized === "ipv6")
    return "ip";
  if (normalized === "url") return "url";
  if (normalized === "email") return "email";
  return "other";
}

function extractDetectionRuleContent(
  finding: Finding,
): IntelContentDetectionRule {
  return {
    kind: "detection_rule",
    sourceFormat: "clawdstrike_policy",
    sourceText: JSON.stringify(
      {
        finding_id: finding.id,
        signal_ids: finding.signalIds,
        severity: finding.severity,
        confidence: finding.confidence,
      },
      null,
      2,
    ),
    narrative: `Detection rule derived from finding "${finding.title}" with ${finding.signalCount} contributing signal(s).`,
  };
}

function extractCampaignContent(finding: Finding): IntelContentCampaign {
  return {
    kind: "campaign",
    campaignName: finding.title,
    findingIds: [finding.id],
    narrative: `Campaign narrative for "${finding.title}". ${finding.signalCount} signal(s) over time range ${finding.scope.timeRange.start} to ${finding.scope.timeRange.end}.`,
  };
}

function extractAdvisoryContent(finding: Finding): IntelContentAdvisory {
  const recommendations: string[] = [];
  for (const action of finding.actions) {
    switch (action) {
      case "policy_updated":
        recommendations.push("Review and apply updated policy configuration.");
        break;
      case "pattern_added":
        recommendations.push(
          "Monitor for recurrence of the identified pattern.",
        );
        break;
      case "agent_revoked":
        recommendations.push(
          "Verify agent revocation and audit related sessions.",
        );
        break;
      case "escalated":
        recommendations.push(
          "Escalate to security operations for further investigation.",
        );
        break;
      default:
        break;
    }
  }

  if (recommendations.length === 0) {
    recommendations.push(
      "Review finding details and assess impact.",
      "Consider updating policy guards to prevent recurrence.",
    );
  }

  return {
    kind: "advisory",
    narrative: `Advisory: "${finding.title}". Severity: ${finding.severity}, Confidence: ${(finding.confidence * 100).toFixed(0)}%. ${finding.signalCount} contributing signal(s) involving ${finding.scope.agentIds.length} agent(s).`,
    recommendations,
  };
}

function extractPolicyPatchContent(
  finding: Finding,
): IntelContentPolicyPatch {
  return {
    kind: "policy_patch",
    guardsPatch: {},
    narrative: `Policy patch recommended based on finding "${finding.title}" (${finding.severity} severity). Review guard configurations for the involved action types.`,
    targetRuleset: undefined,
  };
}

/**
 * Extract MITRE ATT&CK mappings from finding enrichments.
 */
function extractMitreMappings(finding: Finding): MitreMapping[] {
  const mappings: MitreMapping[] = [];
  const seen = new Set<string>();

  for (const enrichment of finding.enrichments) {
    if (enrichment.type !== "mitre_attack") continue;

    const data = enrichment.data as Record<string, unknown>;
    const techniques = data.techniques;
    if (Array.isArray(techniques)) {
      for (const tech of techniques) {
        const t = tech as MitreTechnique;
        if (t.id && !seen.has(t.id)) {
          seen.add(t.id);
          mappings.push({
            techniqueId: t.id,
            techniqueName: t.name,
            tactic: t.tactic,
          });
        }
      }
    }
  }

  return mappings;
}

/**
 * Create an Intel artifact from a promoted Finding.
 *
 * This is the primary entry point for the intel promotion flow. It:
 * 1. Auto-detects the intel type from finding content (or uses override)
 * 2. Extracts content based on enrichments and signal types
 * 3. Carries forward MITRE mappings from finding enrichments
 * 4. Sets derivedFrom to the finding's signal IDs for provenance
 * 5. Inherits confidence from the finding
 *
 * The returned Intel has placeholder signature/receipt fields that must be
 * filled by signIntel() before distribution.
 */
export function promoteToIntel(
  finding: Finding,
  signals: Signal[],
  config: PromotionConfig,
): Intel {
  const intelType = config.type ?? detectIntelType(finding, signals);
  const content = config.content ?? extractContent(finding, signals, intelType);
  const mitre = extractMitreMappings(finding);
  const now = Date.now();

  // Build a placeholder receipt -- the real receipt is created during signing
  const placeholderReceipt: Receipt = {
    id: crypto.randomUUID(),
    timestamp: new Date(now).toISOString(),
    verdict: "allow",
    guard: "intel_forge",
    policyName: "intel_promotion",
    action: { type: "file_access", target: `intel:${finding.id}` },
    evidence: {
      finding_id: finding.id,
      signal_count: finding.signalCount,
      enrichment_count: finding.enrichments.length,
      promotion_type: intelType,
    },
    signature: "",
    publicKey: "",
    valid: false,
  };

  const tags = [
    ...(config.tags ?? []),
    finding.severity,
    intelType,
  ];

  const intel: Intel = {
    id: generateIntelId(),
    type: intelType,
    title: config.title ?? finding.title,
    description:
      config.description ??
      `Intel derived from finding "${finding.title}" (${finding.severity} severity, ${(finding.confidence * 100).toFixed(0)}% confidence).`,
    content,
    derivedFrom: [finding.id],
    confidence: finding.confidence,
    tags: Array.from(new Set(tags)),
    mitre,
    shareability: config.shareability ?? "private",
    signature: "",
    signerPublicKey: "",
    receipt: placeholderReceipt,
    author: config.authorFingerprint,
    createdAt: now,
    version: 1,
  };

  return intel;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Extract the fields of an Intel artifact that are included in the signature.
 *
 * Per SIGNAL-PIPELINE.md section 6.1, the signed fields are:
 * id, type, title, description, content, derivedFrom, confidence,
 * tags, mitre, shareability, createdAt, author.
 *
 * Excluded from signing: signature, signerPublicKey, receipt (per section 6.1).
 */
function extractSignableFields(
  intel: Intel,
): Record<string, unknown> {
  return {
    id: intel.id,
    type: intel.type,
    title: intel.title,
    description: intel.description,
    content: intel.content,
    derivedFrom: intel.derivedFrom,
    confidence: intel.confidence,
    tags: intel.tags,
    mitre: intel.mitre,
    shareability: intel.shareability,
    createdAt: intel.createdAt,
    author: intel.author,
  };
}

function extractReceiptSignableFields(
  receipt: Receipt,
): Record<string, unknown> {
  return {
    id: receipt.id,
    timestamp: receipt.timestamp,
    verdict: receipt.verdict,
    guard: receipt.guard,
    policyName: receipt.policyName,
    action: receipt.action,
    evidence: receipt.evidence,
    publicKey: receipt.publicKey,
    keyType: receipt.keyType,
    imported: receipt.imported,
  };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function sameStringArray(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

/**
 * Sign an Intel artifact with Ed25519.
 *
 * Flow (per SIGNAL-PIPELINE.md section 6.3):
 * 1. Extract signable fields (exclude receipt, signature, signerPublicKey)
 * 2. Canonicalize using RFC 8785 (sorted keys, no whitespace)
 * 3. SHA-256 hash of canonical JSON
 * 4. Sign hash with the provided private key
 * 5. Return intel with signature and signerPublicKey filled
 *
 * The workbench does not currently depend on `@backbay/witness`, so callers
 * must supply the signer public key explicitly. Detached Ed25519 signing is
 * routed through the local signature adapter, which can be swapped for a
 * witness-backed verifier later without changing the calling contract.
 */
export async function signIntel(
  intel: Intel,
  privateKeyHex: string,
  publicKeyHex = intel.signerPublicKey,
): Promise<Intel> {
  if (!ED25519_PUBLIC_KEY_HEX.test(publicKeyHex)) {
    throw new Error(
      "signIntel requires the caller to provide a 32-byte Ed25519 public key",
    );
  }

  const { bytes: contentHashBytes, hex: contentHash } = await hashCanonicalValue(
    extractSignableFields(intel),
  );
  const signatureHex = await signDetachedPayload(contentHashBytes, privateKeyHex);

  const unsignedReceipt: Receipt = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    verdict: "allow",
    guard: "intel_forge",
    policyName: "intel_promotion",
    action: { type: "file_access", target: `intel:${intel.id}` },
    evidence: {
      content_hash: contentHash,
      finding_ids: intel.derivedFrom,
      signal_count: intel.derivedFrom.length,
      enrichment_summary: `${intel.mitre.length} MITRE mapping(s), ${intel.tags.length} tag(s)`,
      intel_type: intel.type,
      parent_receipt: intel.receipt.id,
    },
    signature: "",
    publicKey: publicKeyHex,
    valid: false,
  };
  const { bytes: receiptHashBytes } = await hashCanonicalValue(
    extractReceiptSignableFields(unsignedReceipt),
  );
  const receiptSignature = await signDetachedPayload(
    receiptHashBytes,
    privateKeyHex,
  );
  const signedReceipt: Receipt = {
    ...unsignedReceipt,
    signature: receiptSignature,
    valid: true,
  };

  return {
    ...intel,
    signature: signatureHex,
    signerPublicKey: publicKeyHex,
    receipt: signedReceipt,
  };
}

/**
 * Verify an Intel artifact's signature.
 *
 */
export async function verifyIntel(intel: Intel): Promise<{
  valid: boolean;
  reason: string;
}> {
  if (!intel.signature || intel.signature.length === 0) {
    return { valid: false, reason: "Missing signature" };
  }
  if (!intel.signerPublicKey || intel.signerPublicKey.length === 0) {
    return { valid: false, reason: "Missing signer public key" };
  }
  if (!ED25519_SIGNATURE_HEX.test(intel.signature)) {
    return {
      valid: false,
      reason: "invalid_signature_format",
    };
  }
  if (!ED25519_PUBLIC_KEY_HEX.test(intel.signerPublicKey)) {
    return {
      valid: false,
      reason: "invalid_public_key_format",
    };
  }

  const { bytes: intelHashBytes, hex: intelHashHex } = await hashCanonicalValue(
    extractSignableFields(intel),
  );
  const intelValid = await verifyDetachedPayload(
    intelHashBytes,
    intel.signature,
    intel.signerPublicKey,
  );
  if (!intelValid) {
    return { valid: false, reason: "invalid_signature" };
  }

  if (!intel.receipt.signature || intel.receipt.signature.length === 0) {
    return { valid: false, reason: "missing_receipt_signature" };
  }
  if (!intel.receipt.publicKey || intel.receipt.publicKey.length === 0) {
    return { valid: false, reason: "missing_receipt_public_key" };
  }
  if (!ED25519_SIGNATURE_HEX.test(intel.receipt.signature)) {
    return { valid: false, reason: "invalid_receipt_signature_format" };
  }
  if (!ED25519_PUBLIC_KEY_HEX.test(intel.receipt.publicKey)) {
    return { valid: false, reason: "invalid_receipt_public_key_format" };
  }
  if (intel.receipt.publicKey !== intel.signerPublicKey) {
    return { valid: false, reason: "receipt_signer_mismatch" };
  }
  if (intel.receipt.action.target !== `intel:${intel.id}`) {
    return { valid: false, reason: "receipt_target_mismatch" };
  }

  const receiptContentHash = intel.receipt.evidence.content_hash;
  if (typeof receiptContentHash !== "string" || receiptContentHash !== intelHashHex) {
    return { valid: false, reason: "receipt_content_hash_mismatch" };
  }

  const receiptFindingIds = intel.receipt.evidence.finding_ids;
  if (!isStringArray(receiptFindingIds) || !sameStringArray(receiptFindingIds, intel.derivedFrom)) {
    return { valid: false, reason: "receipt_finding_ids_mismatch" };
  }

  const { bytes: receiptHashBytes } = await hashCanonicalValue(
    extractReceiptSignableFields(intel.receipt),
  );
  const receiptValid = await verifyDetachedPayload(
    receiptHashBytes,
    intel.receipt.signature,
    intel.receipt.publicKey,
  );
  if (!receiptValid) {
    return { valid: false, reason: "invalid_receipt_signature" };
  }

  return { valid: true, reason: "Intel signature verified" };
}

// ---------------------------------------------------------------------------
// Swarm Packaging
// ---------------------------------------------------------------------------

/**
 * Wrap an Intel artifact for Gossipsub distribution via the swarm.
 *
 * Creates a message matching the IntelShareMessage / SpeakeasyIntelMessage
 * shape from SPEAKEASY-INTEGRATION.md, wrapped in a MessageEnvelope.
 *
 * Per SIGNAL-PIPELINE.md section 6.4:
 * - private intel is NOT published (local only)
 * - swarm intel goes to /baychat/v1/swarm/{swarmId}/intel
 * - public intel goes to /baychat/v1/discovery
 */
export function packageForSwarm(
  intel: Intel,
  sentinelIdentity: SentinelIdentity,
): IntelSwarmPackage | null {
  if (intel.shareability === "private") {
    return null; // Private intel is not distributed
  }

  const message: IntelSwarmMessage = {
    type: "intel_share",
    intel,
    summary: intel.description,
    shareability: intel.shareability,
    authorFingerprint: sentinelIdentity.fingerprint,
    authorPublicKey: sentinelIdentity.publicKey,
    authorSigil: sentinelIdentity.sigil,
  };

  const envelope: IntelSwarmEnvelope = {
    envelopeType: "message",
    payload: message,
    ttl: 10, // Max 10 hops in Gossipsub
    createdAt: Date.now(),
    senderId: sentinelIdentity.fingerprint,
  };

  return {
    envelope,
    topic:
      intel.shareability === "public"
        ? "/baychat/v1/discovery"
        : undefined, // Swarm-scoped topic is set by the caller with the swarmId
  };
}

// ---------------------------------------------------------------------------
// Swarm Package Types (local to forge, not exported from sentinel-types)
// ---------------------------------------------------------------------------

/** Message payload for sharing intel via Gossipsub. */
export interface IntelSwarmMessage {
  type: "intel_share";
  intel: Intel;
  summary: string;
  shareability: IntelShareability;
  authorFingerprint: string;
  authorPublicKey: string;
  authorSigil: string;
}

/** Envelope wrapping an intel share message for Gossipsub transport. */
export interface IntelSwarmEnvelope {
  envelopeType: "message";
  payload: IntelSwarmMessage;
  ttl: number;
  createdAt: number;
  senderId: string;
}

/** Complete package ready for swarm distribution. */
export interface IntelSwarmPackage {
  envelope: IntelSwarmEnvelope;
  /** Gossipsub topic. Undefined means the caller must provide the swarm-scoped topic. */
  topic: string | undefined;
}

// ---------------------------------------------------------------------------
// Utility Exports
// ---------------------------------------------------------------------------

/** Supported IntelType values for UI rendering. */
export const INTEL_TYPES: readonly IntelType[] = [
  "detection_rule",
  "pattern",
  "ioc",
  "campaign",
  "advisory",
  "policy_patch",
] as const;

/** Human-readable labels for IntelType. */
export const INTEL_TYPE_LABELS: Record<IntelType, string> = {
  detection_rule: "Detection Rule",
  pattern: "Pattern",
  ioc: "IOC Bundle",
  campaign: "Campaign",
  advisory: "Advisory",
  policy_patch: "Policy Patch",
};

/** Human-readable labels for IntelShareability. */
export const SHAREABILITY_LABELS: Record<IntelShareability, string> = {
  private: "Private",
  swarm: "Swarm",
  public: "Public",
};
