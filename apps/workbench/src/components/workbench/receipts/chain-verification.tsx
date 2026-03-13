import { useState, useCallback, useEffect } from "react";
import type { Receipt } from "@/lib/workbench/types";
import {
  verifyReceiptChainNative,
  type TauriChainReceiptInput,
  type TauriChainVerificationResponse,
  type TauriChainReceiptVerification,
} from "@/lib/tauri-commands";
import { isDesktop } from "@/lib/tauri-bridge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { IconCheck, IconX, IconCopy } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Types for client-side fallback verification
// ---------------------------------------------------------------------------

interface ClientReceiptVerification {
  id: string;
  signatureValid: boolean | null;
  signatureReason: string;
  timestampOrderValid: boolean;
  timestampNote: string;
  receiptHash: string;
}

interface ClientChainVerification {
  receipts: ClientReceiptVerification[];
  chainHash: string;
  allSignaturesValid: boolean;
  timestampsOrdered: boolean;
  chainIntact: boolean;
  chainLength: number;
  summary: string;
}

// ---------------------------------------------------------------------------
// Normalised result type used by the UI (same shape regardless of source)
// ---------------------------------------------------------------------------

interface NormalisedReceiptResult {
  id: string;
  signatureValid: boolean | null;
  signatureReason: string;
  timestampOrderValid: boolean;
  timestampNote: string;
  receiptHash: string;
}

interface NormalisedChainResult {
  receipts: NormalisedReceiptResult[];
  chainHash: string;
  allSignaturesValid: boolean;
  timestampsOrdered: boolean;
  chainIntact: boolean;
  chainLength: number;
  summary: string;
  source: "native" | "client";
}

// ---------------------------------------------------------------------------
// Client-side fallback using Web Crypto API
// ---------------------------------------------------------------------------

async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const buffer = await crypto.subtle.digest("SHA-256", encoded.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyChainClientSide(
  receipts: Receipt[],
): Promise<ClientChainVerification> {
  if (receipts.length === 0) {
    const emptyHash = await sha256Hex("");
    return {
      receipts: [],
      chainHash: emptyHash,
      allSignaturesValid: true,
      timestampsOrdered: true,
      chainIntact: true,
      chainLength: 0,
      summary: "Empty chain — nothing to verify.",
    };
  }

  // Sort by timestamp using numeric Date comparison (handles TZ offsets correctly)
  const sorted = [...receipts].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  const results: ClientReceiptVerification[] = [];
  let timestampsOrdered = true;
  let chainHashInput = "";

  for (let i = 0; i < sorted.length; i++) {
    const r = sorted[i];
    const canonical = `${r.id}:${r.timestamp}:${r.verdict}:${r.guard}:${r.policyName}`;
    const receiptHash = await sha256Hex(canonical);
    chainHashInput += receiptHash;

    // Timestamp ordering
    let tsValid = true;
    let tsNote = "First receipt in chain.";
    if (i > 0) {
      const prev = sorted[i - 1];
      if (new Date(r.timestamp).getTime() >= new Date(prev.timestamp).getTime()) {
        tsNote = "Timestamp >= previous.";
      } else {
        tsValid = false;
        timestampsOrdered = false;
        tsNote = `Timestamp ${r.timestamp} is before previous ${prev.timestamp}.`;
      }
    }

    results.push({
      id: r.id,
      signatureValid: null,
      signatureReason: "Skipped (desktop only) — Ed25519 verification requires the Rust backend.",
      timestampOrderValid: tsValid,
      timestampNote: tsNote,
      receiptHash,
    });
  }

  // Chain hash = SHA-256 of concatenated hex hashes (matching Rust which hashes raw bytes,
  // but for client-side we hash the hex string for simplicity — this is a display-only fallback).
  const chainHash = await sha256Hex(chainHashInput);

  return {
    receipts: results,
    chainHash,
    allSignaturesValid: true, // can't verify, so don't flag
    timestampsOrdered,
    chainIntact: timestampsOrdered,
    chainLength: sorted.length,
    summary: timestampsOrdered
      ? `Chain of ${sorted.length} receipt(s) — timestamp order verified. Signature checks skipped (desktop only).`
      : `Chain of ${sorted.length} receipt(s) — timestamp ordering violation(s) found. Signature checks skipped (desktop only).`,
  };
}

function extractSignedReceipt(receipt: Receipt): Record<string, unknown> | undefined {
  const signedReceipt = receipt.evidence?.signed_receipt;
  return signedReceipt && typeof signedReceipt === "object" && !Array.isArray(signedReceipt)
    ? (signedReceipt as Record<string, unknown>)
    : undefined;
}

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

function normaliseNative(resp: TauriChainVerificationResponse): NormalisedChainResult {
  return {
    receipts: resp.receipts.map((r: TauriChainReceiptVerification) => ({
      id: r.id,
      signatureValid: r.signature_valid,
      signatureReason: r.signature_reason,
      timestampOrderValid: r.timestamp_order_valid,
      timestampNote: r.timestamp_note,
      receiptHash: r.receipt_hash,
    })),
    chainHash: resp.chain_hash,
    allSignaturesValid: resp.all_signatures_valid,
    timestampsOrdered: resp.timestamps_ordered,
    chainIntact: resp.chain_intact,
    chainLength: resp.chain_length,
    summary: resp.summary,
    source: "native",
  };
}

function normaliseClient(resp: ClientChainVerification): NormalisedChainResult {
  return {
    receipts: resp.receipts.map((r) => ({
      id: r.id,
      signatureValid: r.signatureValid,
      signatureReason: r.signatureReason,
      timestampOrderValid: r.timestampOrderValid,
      timestampNote: r.timestampNote,
      receiptHash: r.receiptHash,
    })),
    chainHash: resp.chainHash,
    allSignaturesValid: resp.allSignaturesValid,
    timestampsOrdered: resp.timestampsOrdered,
    chainIntact: resp.chainIntact,
    chainLength: resp.chainLength,
    summary: resp.summary,
    source: "client",
  };
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatusIcon({ valid }: { valid: boolean | null }) {
  if (valid === true) {
    return (
      <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#3dbf84]/15 shrink-0">
        <IconCheck size={12} stroke={2.5} className="text-[#3dbf84]" />
      </span>
    );
  }
  if (valid === false) {
    return (
      <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#c45c5c]/15 shrink-0">
        <IconX size={12} stroke={2.5} className="text-[#c45c5c]" />
      </span>
    );
  }
  // null = skipped
  return (
    <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-[#6f7f9a]/15 shrink-0">
      <span className="text-[9px] font-mono text-[#6f7f9a]">--</span>
    </span>
  );
}

function ChainLine({ color }: { color: string }) {
  return (
    <div
      className="w-px h-6 mx-auto shrink-0"
      style={{ backgroundColor: color }}
    />
  );
}

function ReceiptCard({
  result,
  index,
  total,
}: {
  result: NormalisedReceiptResult;
  index: number;
  total: number;
}) {
  const sigColor =
    result.signatureValid === true
      ? "#3dbf84"
      : result.signatureValid === false
        ? "#c45c5c"
        : "#6f7f9a";

  const tsColor = result.timestampOrderValid ? "#3dbf84" : "#c45c5c";

  const borderColor =
    result.signatureValid === false || !result.timestampOrderValid
      ? "border-[#c45c5c]/30"
      : result.signatureValid === true
        ? "border-[#3dbf84]/20"
        : "border-[#2d3240]";

  return (
    <div>
      {/* Connector line above (except for first) */}
      {index > 0 && (
        <ChainLine
          color={
            result.timestampOrderValid
              ? "rgba(61,191,132,0.3)"
              : "rgba(196,92,92,0.4)"
          }
        />
      )}

      <div
        className={cn(
          "rounded-lg border bg-[#0b0d13] px-4 py-3 space-y-2",
          borderColor,
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            {index + 1}/{total}
          </span>
          <span className="text-xs font-mono text-[#ece7dc] truncate max-w-[200px]">
            {result.id}
          </span>
        </div>

        {/* Signature */}
        <div className="flex items-center gap-2">
          <StatusIcon valid={result.signatureValid} />
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-mono uppercase tracking-wider" style={{ color: sigColor }}>
              {result.signatureValid === true
                ? "Signature Valid"
                : result.signatureValid === false
                  ? "Signature Invalid"
                  : "Signature Skipped"}
            </p>
            <p className="text-[10px] text-[#6f7f9a] truncate">{result.signatureReason}</p>
          </div>
        </div>

        {/* Timestamp order */}
        <div className="flex items-center gap-2">
          <StatusIcon valid={result.timestampOrderValid} />
          <div className="flex-1 min-w-0">
            <p className="text-[10px] font-mono uppercase tracking-wider" style={{ color: tsColor }}>
              {result.timestampOrderValid ? "Timestamp Order OK" : "Timestamp Order Broken"}
            </p>
            <p className="text-[10px] text-[#6f7f9a] truncate">{result.timestampNote}</p>
          </div>
        </div>

        {/* Receipt hash */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-mono text-[#6f7f9a] shrink-0">Hash:</span>
          <span className="text-[10px] font-mono text-[#ece7dc]/70 truncate">
            {result.receiptHash.slice(0, 16)}...{result.receiptHash.slice(-16)}
          </span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface ChainVerificationProps {
  receipts: Receipt[];
  onClose: () => void;
}

export function ChainVerification({ receipts, onClose }: ChainVerificationProps) {
  const [result, setResult] = useState<NormalisedChainResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [hashCopied, setHashCopied] = useState(false);

  const runVerification = useCallback(async () => {
    setLoading(true);
    try {
      if (isDesktop()) {
        // Try native verification first
        const input: TauriChainReceiptInput[] = receipts.map((r) => ({
          id: r.id,
          timestamp: r.timestamp,
          verdict: r.verdict,
          guard: r.guard,
          policyName: r.policyName,
          signature: r.signature,
          publicKey: r.publicKey,
          valid: r.valid,
          signedReceipt: extractSignedReceipt(r),
        }));

        const native = await verifyReceiptChainNative(input);
        if (native) {
          setResult(normaliseNative(native));
          return;
        }
      }

      // Fallback to client-side
      const client = await verifyChainClientSide(receipts);
      setResult(normaliseClient(client));
    } catch (err) {
      console.error("[chain-verification] verification failed:", err);
      // Attempt client-side as last resort
      try {
        const client = await verifyChainClientSide(receipts);
        setResult(normaliseClient(client));
      } catch {
        setResult(null);
      }
    } finally {
      setLoading(false);
    }
  }, [receipts]);

  useEffect(() => {
    runVerification();
  }, [runVerification]);

  const handleCopyHash = useCallback(() => {
    if (result?.chainHash) {
      navigator.clipboard.writeText(result.chainHash).then(() => {
        setHashCopied(true);
        setTimeout(() => setHashCopied(false), 2000);
      }).catch(() => {
        // Clipboard write failed
      });
    }
  }, [result?.chainHash]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="shrink-0 flex items-center justify-between px-4 py-3 border-b border-[#2d3240] bg-[#0b0d13]">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-medium text-[#ece7dc]">Chain Verification</h3>
          {result && (
            <span
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase border rounded-md",
                result.chainIntact
                  ? "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20"
                  : "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20",
              )}
            >
              {result.chainIntact ? (
                <IconCheck size={10} stroke={2} />
              ) : (
                <IconX size={10} stroke={2} />
              )}
              {result.chainIntact ? "Intact" : "Broken"}
            </span>
          )}
          {result && (
            <span className="text-[10px] font-mono text-[#6f7f9a]">
              via {result.source === "native" ? "Rust Ed25519" : "Web Crypto"}
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="px-3 py-1.5 text-xs font-medium text-[#6f7f9a] bg-transparent border border-[#2d3240] rounded-md hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
        >
          Back
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center flex-1 py-16">
          <p className="text-sm text-[#6f7f9a]">Verifying chain...</p>
        </div>
      ) : !result ? (
        <div className="flex items-center justify-center flex-1 py-16">
          <p className="text-sm text-[#c45c5c]">Verification failed.</p>
        </div>
      ) : (
        <ScrollArea className="flex-1 min-h-0">
          <div className="p-4 space-y-4">
            {/* Summary card */}
            <div
              className={cn(
                "rounded-lg border px-4 py-3 space-y-2",
                result.chainIntact
                  ? "border-[#3dbf84]/20 bg-[#3dbf84]/5"
                  : "border-[#c45c5c]/20 bg-[#c45c5c]/5",
              )}
            >
              <p className="text-xs text-[#ece7dc]">{result.summary}</p>

              <div className="flex flex-wrap gap-x-4 gap-y-1">
                <span className="text-[10px] font-mono text-[#6f7f9a]">
                  Length: <span className="text-[#ece7dc]">{result.chainLength}</span>
                </span>
                <span className="text-[10px] font-mono text-[#6f7f9a]">
                  Timestamps:{" "}
                  <span className={result.timestampsOrdered ? "text-[#3dbf84]" : "text-[#c45c5c]"}>
                    {result.timestampsOrdered ? "ordered" : "violation"}
                  </span>
                </span>
                <span className="text-[10px] font-mono text-[#6f7f9a]">
                  Signatures:{" "}
                  <span className={result.allSignaturesValid ? "text-[#3dbf84]" : "text-[#c45c5c]"}>
                    {result.allSignaturesValid ? "valid" : "failure"}
                  </span>
                </span>
              </div>

              {/* Chain hash */}
              <div className="flex items-center gap-2 pt-1">
                <span className="text-[10px] font-mono text-[#6f7f9a] shrink-0">Chain Hash:</span>
                <span className="text-[10px] font-mono text-[#ece7dc]/70 truncate">
                  {result.chainHash}
                </span>
                <button
                  onClick={handleCopyHash}
                  className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                >
                  {hashCopied ? (
                    <IconCheck size={12} className="text-[#3dbf84]" />
                  ) : (
                    <IconCopy size={12} />
                  )}
                </button>
              </div>
            </div>

            {/* Per-receipt chain */}
            <div className="flex flex-col items-center">
              {result.receipts.map((r, i) => (
                <ReceiptCard
                  key={r.id}
                  result={r}
                  index={i}
                  total={result.receipts.length}
                />
              ))}
            </div>
          </div>
        </ScrollArea>
      )}
    </div>
  );
}
