/**
 * ReceiptDetailPage -- readonly receipt detail panel opened from edge click.
 *
 * Shows verdict, policy hash, evidence summary (guard results), timestamp,
 * and Ed25519 signature in a dark-themed, monospace panel matching the
 * receipt-node.tsx aesthetic.
 *
 * Opened via pane-store.openApp("/receipt/:id") when clicking a receipt-type
 * edge on the swarm board.
 */

import { useParams } from "react-router-dom";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { IconCheck, IconX, IconAlertTriangle, IconShieldCheck, IconShieldOff, IconShieldQuestion } from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Verdict styling — matches receipt-node.tsx colors
// ---------------------------------------------------------------------------

const VERDICT_CONFIG: Record<
  "allow" | "deny" | "warn",
  { color: string; bg: string; icon: typeof IconCheck; label: string }
> = {
  allow: {
    color: "#38a876",
    bg: "#38a87618",
    icon: IconCheck,
    label: "ALLOW",
  },
  deny: {
    color: "#b85450",
    bg: "#b8545018",
    icon: IconX,
    label: "DENY",
  },
  warn: {
    color: "#c49a3c",
    bg: "#c49a3c18",
    icon: IconAlertTriangle,
    label: "WARN",
  },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ReceiptDetailPage() {
  const { id } = useParams<{ id: string }>();
  const node = useSwarmBoardStore((s) =>
    s.nodes.find((n) => n.id === id),
  );

  if (!node || !id) {
    return (
      <div
        className="flex flex-col items-center justify-center h-full"
        style={{ backgroundColor: "#0a0c11", color: "#4a5568" }}
      >
        <p className="text-sm font-mono">Receipt not found</p>
        <p className="text-xs font-mono mt-1 text-[#2a2f3a]">
          ID: {id ?? "unknown"}
        </p>
      </div>
    );
  }

  const d = node.data as SwarmBoardNodeData;
  const verdict = d.verdict ?? "allow";
  const vc = VERDICT_CONFIG[verdict];
  const VerdictIcon = vc.icon;
  const guards = d.guardResults ?? [];

  // Signature hash derived from sessionId (matches receipt-node.tsx sigHash logic)
  const sigHash = d.sessionId
    ? `0x${d.sessionId.replace(/[^a-f0-9]/gi, "").padEnd(40, "0").slice(0, 40)}`
    : "0x" + "0".repeat(40);

  const passedCount = guards.filter((g) => g.allowed).length;
  const failedCount = guards.filter((g) => !g.allowed).length;

  const timeStr = d.createdAt
    ? new Date(d.createdAt).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "Unknown";

  return (
    <div
      className="h-full overflow-auto"
      style={{ backgroundColor: "#0a0c11", color: "#ece7dc" }}
    >
      <div className="max-w-2xl mx-auto py-8 px-6">
        {/* Verdict header */}
        <div className="flex items-center gap-4 mb-8">
          <div
            className="shrink-0 flex items-center justify-center w-12 h-12 rounded"
            style={{ backgroundColor: vc.bg }}
          >
            <VerdictIcon size={28} stroke={2.5} style={{ color: vc.color }} />
          </div>
          <div>
            <div
              className="text-2xl font-bold tracking-tight"
              style={{ color: vc.color, letterSpacing: "0.04em" }}
            >
              {vc.label}
            </div>
            <div className="text-xs font-mono mt-0.5" style={{ color: "#4a5568" }}>
              {passedCount} passed
              {failedCount > 0 && (
                <>
                  {" / "}
                  <span style={{ color: "#b85450" }}>{failedCount} failed</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Section: Policy Hash */}
        <Section title="Policy Hash">
          <code
            className="text-xs font-mono break-all"
            style={{ color: "#6f7f9a" }}
          >
            {sigHash.slice(0, 18)}
          </code>
        </Section>

        {/* Section: Evidence Summary */}
        <Section title="Evidence Summary">
          {guards.length === 0 ? (
            <p className="text-xs font-mono" style={{ color: "#2a2f3a" }}>
              No guard results available
            </p>
          ) : (
            <div className="space-y-1">
              {guards.map((gr, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 py-1 px-2 rounded"
                  style={{ backgroundColor: "#0e1018" }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{
                      backgroundColor: gr.allowed ? "#38a876" : "#b85450",
                    }}
                  />
                  <span
                    className="text-xs font-mono flex-1 truncate"
                    style={{ color: "#6f7f9a" }}
                  >
                    {gr.guard}
                  </span>
                  <span
                    className="text-[10px] font-mono shrink-0"
                    style={{
                      color: gr.allowed ? "#38a876" : "#b85450",
                    }}
                  >
                    {gr.allowed ? "PASS" : "FAIL"}
                  </span>
                  {gr.duration_ms != null && (
                    <span
                      className="text-[10px] font-mono shrink-0"
                      style={{
                        color: "#2a2f3a",
                        fontVariantNumeric: "tabular-nums",
                      }}
                    >
                      {gr.duration_ms}ms
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </Section>

        {/* Section: Signature */}
        <Section title="Signature">
          <div className="flex items-start gap-3">
            <code
              className="text-xs font-mono break-all flex-1"
              style={{ color: "#6f7f9a", fontVariantNumeric: "tabular-nums" }}
            >
              {d.signature ?? sigHash}
            </code>
          </div>
        </Section>

        {/* Section: Verification */}
        <Section title="Verification">
          <SignatureVerificationBadge
            verified={d.signatureVerified}
            hasSignature={Boolean(d.signature && d.publicKey)}
          />
        </Section>

        {/* Section: Timestamp */}
        <Section title="Timestamp">
          <span
            className="text-xs font-mono"
            style={{ color: "#6f7f9a", fontVariantNumeric: "tabular-nums" }}
          >
            {timeStr}
          </span>
        </Section>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Signature verification badge
// ---------------------------------------------------------------------------

function SignatureVerificationBadge({
  verified,
  hasSignature,
}: {
  verified?: boolean;
  hasSignature: boolean;
}) {
  if (verified === true) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono uppercase rounded-md bg-[#38a876]/10 text-[#38a876] border border-[#38a876]/20">
        <IconShieldCheck size={12} stroke={2} />
        Signature Verified
      </span>
    );
  }

  if (verified === false) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono uppercase rounded-md bg-[#b85450]/10 text-[#b85450] border border-[#b85450]/20">
        <IconShieldOff size={12} stroke={2} />
        Signature Invalid
      </span>
    );
  }

  if (hasSignature) {
    // TODO: When @clawdstrike/hush-wasm is available in the workbench, call
    // verifyDetachedPayload() from signature-adapter.ts to perform real Ed25519
    // verification in the browser. For now, show a pending state.
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono uppercase rounded-md bg-[#6f7f9a]/10 text-[#6f7f9a] border border-[#6f7f9a]/20">
        <IconShieldQuestion size={12} stroke={2} />
        Verification Pending
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono uppercase rounded-md bg-[#2a2f3a]/20 text-[#4a5568] border border-[#2a2f3a]/30">
      <IconShieldQuestion size={12} stroke={2} />
      No Signature Data
    </span>
  );
}

// ---------------------------------------------------------------------------
// Section helper
// ---------------------------------------------------------------------------

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-6">
      <h3
        className="text-[10px] font-mono uppercase tracking-widest mb-2"
        style={{ color: "#2a2f3a" }}
      >
        {title}
      </h3>
      {children}
    </div>
  );
}

// Default export for lazy loading
export default ReceiptDetailPage;
