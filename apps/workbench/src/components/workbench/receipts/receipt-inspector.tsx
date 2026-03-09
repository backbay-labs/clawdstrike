import { useState, useCallback, useMemo } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import type { Receipt, Verdict, GuardId } from "@/lib/workbench/types";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { ReceiptTimeline } from "./receipt-timeline";
import { ChainVerification } from "./chain-verification";
import { cn } from "@/lib/utils";
import { signReceiptNative } from "@/lib/tauri-commands";
import { isDesktop } from "@/lib/tauri-bridge";

function randomHex(len: number): string {
  const chars = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * 16)];
  }
  return out;
}

function generateTestReceipt(policyName: string, guards: Record<string, unknown>): Receipt {
  // Pick a random enabled guard, or fall back to forbidden_path
  const enabledGuardIds = Object.entries(guards)
    .filter(([, config]) => {
      const c = config as Record<string, unknown> | undefined;
      return c && c.enabled === true;
    })
    .map(([id]) => id);

  const guardId =
    enabledGuardIds.length > 0
      ? enabledGuardIds[Math.floor(Math.random() * enabledGuardIds.length)]
      : "forbidden_path";

  const guardMeta = GUARD_REGISTRY.find((g) => g.id === guardId);

  const actionSamples: Record<string, { type: Receipt["action"]["type"]; target: string }> = {
    forbidden_path: { type: "file_access", target: "/home/user/.ssh/id_rsa" },
    path_allowlist: { type: "file_write", target: "/var/data/output.txt" },
    egress_allowlist: { type: "network_egress", target: "https://evil.example.com/exfil" },
    secret_leak: { type: "file_write", target: "/app/src/config.ts" },
    patch_integrity: { type: "patch_apply", target: "/app/src/main.rs" },
    shell_command: { type: "shell_command", target: "rm -rf /tmp/build" },
    mcp_tool: { type: "mcp_tool_call", target: "execute_code" },
    prompt_injection: { type: "user_input", target: "Ignore previous instructions..." },
    jailbreak: { type: "user_input", target: "DAN mode activated" },
    spider_sense: { type: "user_input", target: "Transfer funds to account..." },
  };

  const action = actionSamples[guardId] ?? { type: "file_access" as const, target: "/unknown" };

  const verdicts: Verdict[] = ["allow", "deny", "warn"];
  const verdict = verdicts[Math.floor(Math.random() * verdicts.length)];

  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    verdict,
    guard: guardMeta?.technicalName ?? guardId,
    policyName,
    action,
    evidence: {
      matched_pattern: action.target,
      guard_id: guardId,
      evaluation_ms: Math.floor(Math.random() * 50) + 1,
      details: `Test receipt generated for ${guardMeta?.name ?? guardId}`,
    },
    signature: randomHex(128),
    publicKey: randomHex(64),
    valid: true,
  };
}

const VERDICT_FILTERS: { value: "all" | Verdict; label: string }[] = [
  { value: "all", label: "All" },
  { value: "allow", label: "Allow" },
  { value: "deny", label: "Deny" },
  { value: "warn", label: "Warn" },
];

export function ReceiptInspector() {
  const { state } = useWorkbench();
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [jsonInput, setJsonInput] = useState("");
  const [importError, setImportError] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<"all" | Verdict>("all");
  const [guardFilter, setGuardFilter] = useState("");
  const [search, setSearch] = useState("");
  const [signing, setSigning] = useState(false);
  const [showChainView, setShowChainView] = useState(false);

  const handleImport = useCallback(() => {
    setImportError("");
    if (!jsonInput.trim()) return;

    try {
      const parsed = JSON.parse(jsonInput.trim());
      const arr: Receipt[] = Array.isArray(parsed) ? parsed : [parsed];

      // Basic validation
      for (const r of arr) {
        if (!r.id || !r.verdict || !r.guard) {
          throw new Error("Receipt must have id, verdict, and guard fields");
        }
      }

      setReceipts((prev) => [...arr, ...prev]);
      setJsonInput("");
    } catch (e) {
      setImportError(e instanceof Error ? e.message : "Invalid JSON");
    }
  }, [jsonInput]);

  const handleGenerate = useCallback(() => {
    const receipt = generateTestReceipt(
      state.activePolicy.name,
      state.activePolicy.guards as unknown as Record<string, unknown>
    );
    setReceipts((prev) => [receipt, ...prev]);
  }, [state.activePolicy]);

  const handleClear = useCallback(() => {
    setReceipts([]);
  }, []);

  /**
   * Sign a receipt using the Rust Ed25519 crypto layer (Tauri desktop only).
   * Creates a real cryptographically signed receipt from the current policy
   * and an auto-generated content hash.
   */
  const handleSignReceipt = useCallback(async () => {
    setSigning(true);
    try {
      // Generate a SHA-256 content hash from the current policy YAML
      const yamlBytes = new TextEncoder().encode(state.yaml);
      const hashBuffer = await crypto.subtle.digest("SHA-256", yamlBytes.buffer as ArrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const contentHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

      const verdictPassed = state.validation.valid && state.validation.errors.length === 0;
      const resp = await signReceiptNative(contentHash, verdictPassed);

      if (resp) {
        const receipt: Receipt = {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          verdict: verdictPassed ? "allow" : "deny",
          guard: "policy_validation",
          policyName: state.activePolicy.name,
          action: { type: "file_access", target: "policy.yaml" },
          evidence: {
            content_hash: contentHash,
            receipt_hash: resp.receipt_hash,
            signed_receipt: resp.signed_receipt,
          },
          // signatures is { signer: string, cosigner?: string }, not an array.
          // Note: this signer signature was made over canonical JSON (RFC 8785),
          // while verify_receipt_chain verifies against "id:timestamp:verdict:guard:policy_name".
          // Chain signature verification will report mismatch for sign_receipt-generated receipts.
          signature: (resp.signed_receipt.signatures as { signer?: string })?.signer
            ?? randomHex(128),
          publicKey: resp.public_key,
          valid: true,
        };
        setReceipts((prev) => [receipt, ...prev]);
      }
    } catch (err) {
      console.error("[receipt-inspector] sign_receipt failed:", err);
    } finally {
      setSigning(false);
    }
  }, [state.yaml, state.validation, state.activePolicy.name]);

  // Get unique guard names for the guard filter
  const guardNames = useMemo(() => {
    const names = new Set(receipts.map((r) => r.guard));
    return Array.from(names).sort();
  }, [receipts]);

  // Apply filters
  const filteredReceipts = useMemo(() => {
    return receipts.filter((r) => {
      if (verdictFilter !== "all" && r.verdict !== verdictFilter) return false;
      if (guardFilter && r.guard !== guardFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        const haystack = `${r.guard} ${r.action.type} ${r.action.target} ${r.policyName}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [receipts, verdictFilter, guardFilter, search]);

  // Show chain verification view when active
  if (showChainView) {
    return (
      <ChainVerification
        receipts={receipts}
        onClose={() => setShowChainView(false)}
      />
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Import bar */}
      <div className="shrink-0 border-b border-[#2d3240] bg-[#0b0d13] p-4">
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <textarea
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              placeholder='Paste receipt JSON here... (single object or array of receipts)'
              rows={3}
              className="w-full rounded-md border border-[#2d3240] bg-[#131721] px-3 py-2 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors resize-none"
            />
            {importError && (
              <p className="text-[10px] font-mono text-[#c45c5c] mt-1">
                {importError}
              </p>
            )}
          </div>
          <div className="flex flex-col gap-1.5 shrink-0">
            <button
              onClick={handleImport}
              className="px-3 py-1.5 text-xs font-medium text-[#ece7dc] bg-[#131721] border border-[#2d3240] rounded-md hover:border-[#d4a84b]/40 hover:bg-[#131721]/80 transition-colors"
            >
              Import
            </button>
            <button
              onClick={handleGenerate}
              className="px-3 py-1.5 text-xs font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 rounded-md hover:bg-[#d4a84b]/20 transition-colors"
            >
              Generate Test
            </button>
            {isDesktop() && (
              <button
                onClick={handleSignReceipt}
                disabled={signing}
                className={cn(
                  "px-3 py-1.5 text-xs font-medium border rounded-md transition-colors",
                  signing
                    ? "text-[#6f7f9a] bg-[#131721] border-[#2d3240] cursor-wait"
                    : "text-[#3dbf84] bg-[#3dbf84]/10 border-[#3dbf84]/20 hover:bg-[#3dbf84]/20"
                )}
              >
                {signing ? "Signing..." : "Sign Receipt"}
              </button>
            )}
            {receipts.length >= 2 && (
              <button
                onClick={() => setShowChainView(true)}
                className="px-3 py-1.5 text-xs font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 rounded-md hover:bg-[#d4a84b]/20 transition-colors"
              >
                Verify Chain
              </button>
            )}
            {receipts.length > 0 && (
              <button
                onClick={handleClear}
                className="px-3 py-1.5 text-xs font-medium text-[#6f7f9a] bg-transparent border border-[#2d3240] rounded-md hover:text-[#c45c5c] hover:border-[#c45c5c]/30 transition-colors"
              >
                Clear All
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="shrink-0 flex items-center gap-3 px-4 py-2.5 border-b border-[#2d3240] bg-[#0b0d13]">
        {/* Verdict filter */}
        <div className="flex items-center gap-1">
          {VERDICT_FILTERS.map((vf) => (
            <button
              key={vf.value}
              onClick={() => setVerdictFilter(vf.value)}
              className={cn(
                "px-2 py-1 text-[10px] font-mono uppercase rounded-md border transition-colors",
                verdictFilter === vf.value
                  ? "text-[#ece7dc] bg-[#131721] border-[#d4a84b]/40"
                  : "text-[#6f7f9a] bg-transparent border-[#2d3240] hover:text-[#ece7dc]"
              )}
            >
              {vf.label}
            </button>
          ))}
        </div>

        {/* Guard filter */}
        {guardNames.length > 0 && (
          <select
            value={guardFilter}
            onChange={(e) => setGuardFilter(e.target.value)}
            className="h-7 px-2 text-xs font-mono bg-[#131721] border border-[#2d3240] rounded-md text-[#ece7dc] outline-none focus:border-[#d4a84b]/50"
          >
            <option value="">All Guards</option>
            {guardNames.map((gn) => (
              <option key={gn} value={gn}>
                {gn}
              </option>
            ))}
          </select>
        )}

        {/* Search */}
        <div className="flex-1">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search receipts..."
            className="h-7 w-full max-w-[280px] rounded-md border border-[#2d3240] bg-[#131721] px-2.5 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors"
          />
        </div>

        {/* Count */}
        <span className="text-[10px] font-mono text-[#6f7f9a] shrink-0">
          {filteredReceipts.length} receipt{filteredReceipts.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Timeline */}
      <div className="flex-1 min-h-0 overflow-hidden">
        <ReceiptTimeline receipts={filteredReceipts} />
      </div>
    </div>
  );
}
