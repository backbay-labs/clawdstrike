/**
 * ProofTab - Receipt chain viewer for the ContextInspector proof tab.
 *
 * Displays Ed25519-signed receipt details for the selected entity,
 * including guard results, policy snapshot info, and Merkle proof status.
 *
 * When nothing is selected, shows an empty-state prompt.
 * When a receipt entity is selected, shows full receipt detail.
 * When any other entity is selected, shows associated receipts list.
 */
import { useCallback } from "react";
import { useSelection, useWorkbenchDispatch } from "@/shell/workbench/WorkbenchStateProvider";
import type { SelectionEntityType } from "@/shell/workbench/workbenchState";

// ── Style Constants ──────────────────────────────────────────────

const COLOR_TEXT_MUTED = "var(--color-text-muted, #6b7280)";
const COLOR_TEXT_PRIMARY = "var(--color-text-primary, #e0e0e6)";
const COLOR_GOLD = "var(--color-origin-gold, #c8a84e)";
const COLOR_BORDER = "var(--color-border-subtle, #1a1d2e)";
const COLOR_ALLOW = "#4ade80";
const COLOR_DENY = "#f87171";

const FONT_MONO = "monospace";
const FONT_SIZE_BODY = 11;
const FONT_SIZE_LABEL = 10;
const SECTION_PADDING = 12;

// ── Types ────────────────────────────────────────────────────────

interface GuardResult {
  guardName: string;
  verdict: "allow" | "deny";
  durationMs: number;
}

interface MerkleProof {
  root: string;
  index: number;
  total: number;
}

interface ReceiptData {
  receiptId?: string;
  verdict?: "allow" | "deny";
  timestamp?: string;
  policyName?: string;
  policyVersion?: string;
  guardResults?: GuardResult[];
  signature?: string;
  publicKey?: string;
  merkleProof?: MerkleProof | null;
  verificationStatus?: "Verified" | "Unverified" | "Invalid";
}

interface ReceiptSummary extends ReceiptData {
  [key: string]: unknown;
}

// ── Utilities ────────────────────────────────────────────────────

function truncateHash(hash: string | undefined, prefixLen = 8, suffixLen = 4): string {
  if (!hash) return "---";
  if (hash.length <= prefixLen + suffixLen + 3) return hash;
  return `${hash.slice(0, prefixLen)}...${hash.slice(-suffixLen)}`;
}

function formatTimestamp(iso: string | undefined): string {
  if (!iso) return "---";
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function entityLabel(entityType: SelectionEntityType): string {
  if (!entityType) return "entity";
  return entityType;
}

// ── Sub-components ───────────────────────────────────────────────

function EmptyState() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: 8,
        color: COLOR_TEXT_MUTED,
        fontFamily: FONT_MONO,
        fontSize: FONT_SIZE_BODY,
        padding: 16,
        textAlign: "center",
      }}
    >
      <span style={{ fontSize: 20, opacity: 0.35 }}>{"\u{1F50F}"}</span>
      Select an entity to view its proof chain
    </div>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div
      style={{
        fontSize: FONT_SIZE_LABEL,
        fontFamily: FONT_MONO,
        fontWeight: 600,
        color: COLOR_GOLD,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        marginBottom: 8,
      }}
    >
      {title}
    </div>
  );
}

function SectionCard({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        padding: SECTION_PADDING,
        borderBottom: `1px solid ${COLOR_BORDER}`,
      }}
    >
      {children}
    </div>
  );
}

function LabelValue({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 4 }}>
      <span
        style={{
          fontSize: FONT_SIZE_LABEL,
          fontFamily: FONT_MONO,
          color: COLOR_TEXT_MUTED,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {label}
      </span>
      <div
        style={{
          fontSize: FONT_SIZE_BODY,
          fontFamily: FONT_MONO,
          color: COLOR_TEXT_PRIMARY,
          marginTop: 1,
        }}
      >
        {children}
      </div>
    </div>
  );
}

function VerdictPill({ verdict }: { verdict: "allow" | "deny" }) {
  const isAllow = verdict === "allow";
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 6px",
        borderRadius: 3,
        fontSize: 9,
        fontFamily: FONT_MONO,
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        background: isAllow ? "rgba(74, 222, 128, 0.15)" : "rgba(248, 113, 113, 0.15)",
        color: isAllow ? COLOR_ALLOW : COLOR_DENY,
      }}
    >
      {verdict}
    </span>
  );
}

function VerificationBadge({ status }: { status: "Verified" | "Unverified" | "Invalid" }) {
  const colorMap: Record<string, string> = {
    Verified: COLOR_ALLOW,
    Unverified: "#facc15",
    Invalid: COLOR_DENY,
  };
  const bgMap: Record<string, string> = {
    Verified: "rgba(74, 222, 128, 0.12)",
    Unverified: "rgba(250, 204, 21, 0.12)",
    Invalid: "rgba(248, 113, 113, 0.12)",
  };

  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 6px",
        borderRadius: 3,
        fontSize: 9,
        fontFamily: FONT_MONO,
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        background: bgMap[status],
        color: colorMap[status],
      }}
    >
      {status}
    </span>
  );
}

// ── Verdict Banner ───────────────────────────────────────────────

function VerdictBanner({ receipt }: { receipt: ReceiptData }) {
  const verdict = receipt.verdict ?? "deny";
  const isAllow = verdict === "allow";

  return (
    <div
      style={{
        padding: SECTION_PADDING,
        background: isAllow ? "rgba(74, 222, 128, 0.1)" : "rgba(248, 113, 113, 0.1)",
        borderBottom: `1px solid ${COLOR_BORDER}`,
        display: "flex",
        flexDirection: "column",
        gap: 4,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          fontSize: 13,
          fontFamily: FONT_MONO,
          fontWeight: 700,
          color: isAllow ? COLOR_ALLOW : COLOR_DENY,
        }}
      >
        <span>{isAllow ? "\u2713" : "\u2717"}</span>
        <span style={{ textTransform: "uppercase" }}>{verdict}</span>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          fontSize: FONT_SIZE_LABEL,
          fontFamily: FONT_MONO,
          color: COLOR_TEXT_MUTED,
        }}
      >
        <span>{formatTimestamp(receipt.timestamp)}</span>
        <span style={{ color: COLOR_TEXT_PRIMARY }}>{truncateHash(receipt.receiptId)}</span>
      </div>
    </div>
  );
}

// ── Policy Section ───────────────────────────────────────────────

function PolicySection({ receipt }: { receipt: ReceiptData }) {
  return (
    <SectionCard>
      <SectionHeader title="Policy" />
      <LabelValue label="Name">{receipt.policyName ?? "---"}</LabelValue>
      <LabelValue label="Version">{receipt.policyVersion ?? "---"}</LabelValue>
    </SectionCard>
  );
}

// ── Guard Results ────────────────────────────────────────────────

function GuardResultsSection({ results }: { results: GuardResult[] }) {
  // Sort: deny results first
  const sorted = [...results].sort((a, b) => {
    if (a.verdict === "deny" && b.verdict !== "deny") return -1;
    if (a.verdict !== "deny" && b.verdict === "deny") return 1;
    return 0;
  });

  return (
    <SectionCard>
      <SectionHeader title="Guard Results" />
      {sorted.length === 0 ? (
        <div style={{ fontSize: FONT_SIZE_BODY, fontFamily: FONT_MONO, color: COLOR_TEXT_MUTED }}>
          No guard results
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          {/* Table header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr auto auto",
              gap: 8,
              padding: "4px 0",
              borderBottom: `1px solid ${COLOR_BORDER}`,
              fontSize: 9,
              fontFamily: FONT_MONO,
              color: COLOR_TEXT_MUTED,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            <span>Guard</span>
            <span style={{ textAlign: "center" }}>Verdict</span>
            <span style={{ textAlign: "right" }}>Time</span>
          </div>

          {/* Table rows */}
          {sorted.map((result, i) => (
            <div
              key={`${result.guardName}-${i}`}
              style={{
                display: "grid",
                gridTemplateColumns: "1fr auto auto",
                gap: 8,
                alignItems: "center",
                padding: "4px 0",
                borderBottom: i < sorted.length - 1 ? `1px solid ${COLOR_BORDER}` : "none",
              }}
            >
              <span
                style={{
                  fontSize: FONT_SIZE_BODY,
                  fontFamily: FONT_MONO,
                  color: COLOR_TEXT_PRIMARY,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {result.guardName}
              </span>
              <VerdictPill verdict={result.verdict} />
              <span
                style={{
                  fontSize: FONT_SIZE_LABEL,
                  fontFamily: FONT_MONO,
                  color: COLOR_TEXT_MUTED,
                  textAlign: "right",
                  whiteSpace: "nowrap",
                }}
              >
                {result.durationMs.toFixed(1)}ms
              </span>
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}

// ── Signature Section ────────────────────────────────────────────

function SignatureSection({ receipt }: { receipt: ReceiptData }) {
  const status = receipt.verificationStatus ?? "Unverified";

  return (
    <SectionCard>
      <SectionHeader title="Signature" />
      <LabelValue label="Ed25519 Signature">
        <span style={{ fontFamily: FONT_MONO, fontSize: FONT_SIZE_BODY, wordBreak: "break-all" }}>
          {truncateHash(receipt.signature, 12, 8)}
        </span>
      </LabelValue>
      <LabelValue label="Public Key">
        <span style={{ fontFamily: FONT_MONO, fontSize: FONT_SIZE_BODY, wordBreak: "break-all" }}>
          {truncateHash(receipt.publicKey, 12, 8)}
        </span>
      </LabelValue>
      <div style={{ marginTop: 6 }}>
        <span
          style={{
            fontSize: FONT_SIZE_LABEL,
            fontFamily: FONT_MONO,
            color: COLOR_TEXT_MUTED,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            marginRight: 6,
          }}
        >
          Status
        </span>
        <VerificationBadge status={status} />
      </div>
    </SectionCard>
  );
}

// ── Merkle Proof Section ─────────────────────────────────────────

function MerkleProofSection({ proof }: { proof: MerkleProof }) {
  return (
    <SectionCard>
      <SectionHeader title="Merkle Proof" />
      <LabelValue label="Root Hash">
        <span style={{ fontFamily: FONT_MONO, fontSize: FONT_SIZE_BODY, wordBreak: "break-all" }}>
          {truncateHash(proof.root, 12, 8)}
        </span>
      </LabelValue>
      <LabelValue label="Position">
        {proof.index} / {proof.total}
      </LabelValue>
      <div style={{ marginTop: 6 }}>
        <span
          style={{
            display: "inline-block",
            padding: "1px 6px",
            borderRadius: 3,
            fontSize: 9,
            fontFamily: FONT_MONO,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            background: "rgba(74, 222, 128, 0.12)",
            color: COLOR_ALLOW,
          }}
        >
          Anchored
        </span>
      </div>
    </SectionCard>
  );
}

// ── Receipt Detail View ──────────────────────────────────────────

function ReceiptDetail({ metadata }: { metadata: Record<string, unknown> }) {
  const receipt = metadata as unknown as ReceiptData;

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      <VerdictBanner receipt={receipt} />
      <PolicySection receipt={receipt} />
      <GuardResultsSection results={receipt.guardResults ?? []} />
      <SignatureSection receipt={receipt} />
      {receipt.merkleProof && <MerkleProofSection proof={receipt.merkleProof} />}
    </div>
  );
}

// ── Associated Receipts View ─────────────────────────────────────

function AssociatedReceipts({
  entityType,
  metadata,
}: {
  entityType: SelectionEntityType;
  metadata?: Record<string, unknown>;
}) {
  const dispatch = useWorkbenchDispatch();

  const receipts = (metadata?.receipts ?? []) as ReceiptSummary[];

  const handleReceiptClick = useCallback(
    (receipt: ReceiptSummary) => {
      dispatch({
        type: "SET_SELECTION",
        payload: {
          entityType: "receipt",
          entityId: (receipt.receiptId as string) ?? null,
          metadata: receipt as Record<string, unknown>,
        },
      });
    },
    [dispatch],
  );

  if (receipts.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 8,
          color: COLOR_TEXT_MUTED,
          fontFamily: FONT_MONO,
          fontSize: FONT_SIZE_BODY,
          padding: 16,
          textAlign: "center",
        }}
      >
        No receipts associated with this {entityLabel(entityType)}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      <div
        style={{
          padding: SECTION_PADDING,
          borderBottom: `1px solid ${COLOR_BORDER}`,
        }}
      >
        <SectionHeader title={`Receipts (${receipts.length})`} />
      </div>
      <div style={{ overflow: "auto", flex: 1 }}>
        {receipts.map((receipt, i) => {
          const rid = (receipt.receiptId as string) ?? `receipt-${i}`;
          const verdict = (receipt.verdict as "allow" | "deny") ?? "deny";
          return (
            <button
              key={rid}
              onClick={() => handleReceiptClick(receipt)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                width: "100%",
                padding: `8px ${SECTION_PADDING}px`,
                background: "none",
                border: "none",
                borderBottom: `1px solid ${COLOR_BORDER}`,
                cursor: "pointer",
                textAlign: "left",
              }}
            >
              <VerdictPill verdict={verdict} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    fontSize: FONT_SIZE_BODY,
                    fontFamily: FONT_MONO,
                    color: COLOR_TEXT_PRIMARY,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {truncateHash(receipt.receiptId as string | undefined)}
                </div>
                <div
                  style={{
                    fontSize: FONT_SIZE_LABEL,
                    fontFamily: FONT_MONO,
                    color: COLOR_TEXT_MUTED,
                    marginTop: 1,
                  }}
                >
                  {receipt.policyName ?? "unknown policy"}
                </div>
              </div>
              <div
                style={{
                  fontSize: FONT_SIZE_LABEL,
                  fontFamily: FONT_MONO,
                  color: COLOR_TEXT_MUTED,
                  whiteSpace: "nowrap",
                  flexShrink: 0,
                }}
              >
                {formatTimestamp(receipt.timestamp as string | undefined)}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Component ───────────────────────────────────────────────

export function ProofTab() {
  const selection = useSelection();

  // Nothing selected
  if (!selection.entityType) {
    return <EmptyState />;
  }

  // Receipt selected: show full detail view
  if (selection.entityType === "receipt") {
    return <ReceiptDetail metadata={selection.metadata ?? {}} />;
  }

  // Any other entity: show associated receipts
  return <AssociatedReceipts entityType={selection.entityType} metadata={selection.metadata} />;
}
