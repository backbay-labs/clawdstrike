import { useState, useCallback } from "react";
import type { Receipt } from "@/lib/workbench/types";
import type { FleetConnection } from "@/lib/workbench/fleet-client";
import { verifyReceiptRemote } from "@/lib/workbench/fleet-client";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { CodeBlock } from "@/components/ui/code-block";
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from "@/components/ui/collapsible";
import { IconCopy, IconCheck, IconChevronDown, IconShieldCheck, IconX } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface ReceiptDetailProps {
  receipt: Receipt;
  /** Fleet connection for server-side verification. Undefined when disconnected. */
  fleetConnection?: FleetConnection;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Clipboard write failed (e.g. permissions)
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
    >
      {copied ? (
        <IconCheck size={12} className="text-[#3dbf84]" />
      ) : (
        <IconCopy size={12} />
      )}
    </button>
  );
}

function FieldRow({
  label,
  children,
  mono = false,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start gap-3 py-2 border-b border-[#2d3240] last:border-b-0">
      <span className="shrink-0 w-28 text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] pt-0.5">
        {label}
      </span>
      <div className={cn("flex-1 min-w-0 text-xs text-[#ece7dc]", mono && "font-mono")}>
        {children}
      </div>
    </div>
  );
}

export function ReceiptDetail({ receipt, fleetConnection }: ReceiptDetailProps) {
  const [showRaw, setShowRaw] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [serverVerification, setServerVerification] = useState<{
    valid: boolean;
    reason?: string;
    verified_at: string;
  } | null>(null);
  const [verifyError, setVerifyError] = useState("");

  const handleServerVerify = useCallback(async () => {
    if (!fleetConnection) return;
    setVerifying(true);
    setVerifyError("");
    setServerVerification(null);
    try {
      const res = await verifyReceiptRemote(fleetConnection, receipt.id);
      setServerVerification({
        valid: res.valid,
        reason: res.reason,
        verified_at: res.verified_at,
      });
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setVerifying(false);
    }
  }, [fleetConnection, receipt.id]);

  const rawJson = JSON.stringify(receipt, null, 2);

  const truncatedSig =
    receipt.signature.length > 32
      ? `${receipt.signature.slice(0, 16)}...${receipt.signature.slice(-16)}`
      : receipt.signature;

  return (
    <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13] overflow-hidden">
      {/* Header with toggle */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#2d3240] bg-[#131721]">
        <div className="flex items-center gap-3">
          <VerdictBadge verdict={receipt.verdict} />
          <span className="text-xs font-mono text-[#ece7dc]">{receipt.guard}</span>
          <span className="text-[10px] text-[#6f7f9a]">
            {new Date(receipt.timestamp).toLocaleString()}
          </span>
        </div>
        <button
          onClick={() => setShowRaw(!showRaw)}
          className="px-2 py-1 text-[10px] font-mono uppercase text-[#6f7f9a] border border-[#2d3240] rounded-md hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
        >
          {showRaw ? "Structured" : "Raw JSON"}
        </button>
      </div>

      {showRaw ? (
        <div className="p-0">
          <CodeBlock language="json" filename="receipt.json" code={rawJson} />
        </div>
      ) : (
        <div className="px-4 py-2">
          <FieldRow label="Verdict">
            <VerdictBadge verdict={receipt.verdict} />
          </FieldRow>

          <FieldRow label="Guard" mono>
            {receipt.guard}
          </FieldRow>

          <FieldRow label="Policy" mono>
            {receipt.policyName}
          </FieldRow>

          <FieldRow label="Action" mono>
            <span className="text-[#d4a84b]">{receipt.action.type}</span>
            <span className="mx-1 text-[#6f7f9a]">&rarr;</span>
            <span>{receipt.action.target}</span>
          </FieldRow>

          <FieldRow label="Timestamp">
            {new Date(receipt.timestamp).toLocaleString()}
          </FieldRow>

          {/* Evidence (collapsible) */}
          <div className="py-2 border-b border-[#2d3240]">
            <Collapsible open={evidenceOpen} onOpenChange={setEvidenceOpen}>
              <CollapsibleTrigger className="flex items-center gap-2 w-full text-left">
                <span className="shrink-0 w-28 text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                  Evidence
                </span>
                <IconChevronDown
                  size={12}
                  className={cn(
                    "text-[#6f7f9a] transition-transform",
                    evidenceOpen && "rotate-180"
                  )}
                />
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="mt-2">
                  <CodeBlock
                    language="json"
                    filename="evidence"
                    code={JSON.stringify(receipt.evidence, null, 2)}
                  />
                </div>
              </CollapsibleContent>
            </Collapsible>
          </div>

          <FieldRow label="Signature" mono>
            <div className="flex items-center gap-1">
              <span className="truncate">{truncatedSig}</span>
              <CopyButton text={receipt.signature} />
            </div>
          </FieldRow>

          <FieldRow label="Public Key" mono>
            <span className="text-xs break-all">
              {receipt.publicKey.length > 32
                ? `${receipt.publicKey.slice(0, 16)}...${receipt.publicKey.slice(-16)}`
                : receipt.publicKey}
            </span>
            <CopyButton text={receipt.publicKey} />
          </FieldRow>

          <FieldRow label="Key Type" mono>
            {receipt.keyType === "persistent" ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20 rounded-md">
                Persistent (Stronghold)
              </span>
            ) : receipt.keyType === "ephemeral" ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#6f7f9a]/10 text-[#6f7f9a] border border-[#6f7f9a]/20 rounded-md">
                Ephemeral
              </span>
            ) : (
              <span className="text-[10px] text-[#6f7f9a]">Unknown</span>
            )}
          </FieldRow>

          <FieldRow label="Verification">
            <div className="flex items-center gap-2 flex-wrap">
              {receipt.valid ? (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#3dbf84]/10 text-[#3dbf84] border border-[#3dbf84]/20 rounded-md">
                  <IconCheck size={10} stroke={2} />
                  Signature Valid
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#6f7f9a]/10 text-[#6f7f9a] border border-[#6f7f9a]/20 rounded-md">
                  Cannot Verify
                </span>
              )}

              {/* Server-side verification (P3-4) */}
              {fleetConnection && (
                <>
                  {serverVerification ? (
                    serverVerification.valid ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#3dbf84]/10 text-[#3dbf84] border border-[#3dbf84]/20 rounded-md">
                        <IconShieldCheck size={10} stroke={2} />
                        Server Verified
                      </span>
                    ) : (
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#c45c5c]/10 text-[#c45c5c] border border-[#c45c5c]/20 rounded-md"
                        title={serverVerification.reason}
                      >
                        <IconX size={10} stroke={2} />
                        Server Rejected
                      </span>
                    )
                  ) : (
                    <button
                      onClick={handleServerVerify}
                      disabled={verifying}
                      className={cn(
                        "inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase border rounded-md transition-colors",
                        verifying
                          ? "text-[#6f7f9a] bg-[#131721] border-[#2d3240] cursor-wait"
                          : "text-[#d4a84b] bg-[#d4a84b]/10 border-[#d4a84b]/20 hover:bg-[#d4a84b]/20",
                      )}
                    >
                      <IconShieldCheck size={10} stroke={2} />
                      {verifying ? "Verifying..." : "Verify on Server"}
                    </button>
                  )}
                  {verifyError && (
                    <span className="text-[9px] font-mono text-[#c45c5c]">
                      {verifyError}
                    </span>
                  )}
                </>
              )}
            </div>
          </FieldRow>
        </div>
      )}
    </div>
  );
}
