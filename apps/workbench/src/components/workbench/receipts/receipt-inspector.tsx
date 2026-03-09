import { useState, useCallback, useMemo } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { usePersistedReceipts } from "@/lib/workbench/use-persisted-receipts";
import type { Receipt, Verdict, GuardId, TestActionType } from "@/lib/workbench/types";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { ReceiptTimeline } from "./receipt-timeline";
import { ChainVerification } from "./chain-verification";
import { cn } from "@/lib/utils";
import { signReceiptNative, simulateActionNative } from "@/lib/tauri-commands";
import { isDesktop } from "@/lib/tauri-bridge";
import { emitAuditEvent } from "@/lib/workbench/local-audit";

function randomHex(len: number): string {
  const bytes = new Uint8Array(len / 2);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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

/**
 * Sample actions for "Generate Real Receipt". Each entry maps a user-facing
 * action type to the native engine action_type string plus a representative target.
 */
const SAMPLE_ACTIONS: {
  label: string;
  uiType: TestActionType;
  engineType: string;
  target: string;
  content?: string;
}[] = [
  { label: "File Read", uiType: "file_access", engineType: "file_access", target: "/home/user/.ssh/id_rsa" },
  { label: "File Write", uiType: "file_write", engineType: "file_write", target: "/app/src/config.ts", content: "API_KEY=sk-secret-1234" },
  { label: "Shell Command", uiType: "shell_command", engineType: "shell", target: "rm -rf /tmp/build" },
  { label: "Network Egress", uiType: "network_egress", engineType: "network", target: "evil.example.com:443" },
  { label: "MCP Tool Call", uiType: "mcp_tool_call", engineType: "mcp_tool", target: "execute_code" },
  { label: "Patch Apply", uiType: "patch_apply", engineType: "patch", target: "/app/src/main.rs", content: "--- a/main.rs\n+++ b/main.rs\n@@ -1 +1 @@\n-old\n+new" },
];

const VERDICT_FILTERS: { value: "all" | Verdict; label: string }[] = [
  { value: "all", label: "All" },
  { value: "allow", label: "Allow" },
  { value: "deny", label: "Deny" },
  { value: "warn", label: "Warn" },
];

export function ReceiptInspector() {
  const { state } = useWorkbench();
  const { receipts, setReceipts, clearReceipts } = usePersistedReceipts();
  const [jsonInput, setJsonInput] = useState("");
  const [importError, setImportError] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<"all" | Verdict>("all");
  const [guardFilter, setGuardFilter] = useState("");
  const [search, setSearch] = useState("");
  const [signing, setSigning] = useState(false);
  const [showChainView, setShowChainView] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [selectedAction, setSelectedAction] = useState(0); // index into SAMPLE_ACTIONS
  const [generateError, setGenerateError] = useState("");

  const handleImport = useCallback(() => {
    setImportError("");
    if (!jsonInput.trim()) return;

    try {
      const parsed = JSON.parse(jsonInput.trim());
      const arr: Receipt[] = Array.isArray(parsed) ? parsed : [parsed];

      // Validate all required fields
      const VALID_VERDICTS = ["allow", "deny", "warn"] as const;
      for (const r of arr) {
        if (!r.id || typeof r.id !== "string") throw new Error("Receipt must have a string 'id'");
        if (!r.verdict || typeof r.verdict !== "string") throw new Error("Receipt must have a string 'verdict'");
        if (!VALID_VERDICTS.includes(r.verdict)) {
          throw new Error(`Receipt verdict must be one of ${VALID_VERDICTS.join(", ")}, got "${r.verdict}"`);
        }
        if (!r.guard || typeof r.guard !== "string") throw new Error("Receipt must have a string 'guard'");
        if (!r.action || typeof r.action !== "object") throw new Error("Receipt must have an 'action' object");
        if (!r.action.type || typeof r.action.type !== "string") throw new Error("Receipt action must have a string 'type'");
        if (!r.action.target || typeof r.action.target !== "string") throw new Error("Receipt action must have a string 'target'");
        if (!r.timestamp) r.timestamp = new Date().toISOString(); // default if missing
        if (!r.policyName) r.policyName = "unknown"; // default if missing
        if (!r.signature) r.signature = "none"; // mark as unsigned
        if (!r.publicKey) r.publicKey = ""; // mark as no key
      }

      setReceipts((prev) => [...arr, ...prev]);
      setJsonInput("");
      emitAuditEvent({
        eventType: "receipt.import",
        source: "receipt",
        summary: `Imported ${arr.length} receipt(s)`,
        details: { count: arr.length, receiptIds: arr.map((r) => r.id) },
      });
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
    emitAuditEvent({
      eventType: "receipt.generate",
      source: "receipt",
      summary: `Generated test receipt — ${receipt.verdict} (${receipt.guard})`,
      details: { receiptId: receipt.id, verdict: receipt.verdict, guard: receipt.guard, policyName: receipt.policyName },
    });
  }, [state.activePolicy]);

  /**
   * Generate a real receipt using the native Rust policy engine + Ed25519 signing.
   *
   * Flow:
   * 1. simulateActionNative() evaluates the selected action against the current policy
   * 2. signReceiptNative() creates a real Ed25519-signed receipt for the verdict
   * 3. Both are combined into a Receipt with real verdict, signature, chain hash, and timestamp
   *
   * Falls back to generateTestReceipt() when not running in Tauri.
   */
  const handleGenerateReal = useCallback(async () => {
    setGenerateError("");

    // Fallback: if not running in desktop mode, generate a test receipt
    if (!isDesktop()) {
      handleGenerate();
      return;
    }

    setGenerating(true);
    try {
      const sample = SAMPLE_ACTIONS[selectedAction];
      const policyYaml = state.yaml;
      const policyName = state.activePolicy.name;

      // Step 1: Simulate the action against the current policy via the Rust engine
      const simResp = await simulateActionNative(
        policyYaml,
        sample.engineType,
        sample.target,
        sample.content,
      );

      if (!simResp) {
        setGenerateError("Simulation returned no response");
        return;
      }

      // Step 2: Compute content hash for signing (SHA-256 of the simulation payload)
      const simPayload = JSON.stringify({
        policy: policyName,
        action_type: sample.engineType,
        target: sample.target,
        allowed: simResp.allowed,
        guard: simResp.guard,
        timestamp: new Date().toISOString(),
      });
      const payloadBytes = new TextEncoder().encode(simPayload);
      const hashBuffer = await crypto.subtle.digest("SHA-256", payloadBytes.buffer as ArrayBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const contentHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

      // Step 3: Sign the receipt via the Rust Ed25519 crypto layer
      const signResp = await signReceiptNative(contentHash, simResp.allowed);

      if (!signResp) {
        setGenerateError("Signing returned no response");
        return;
      }

      // Step 4: Extract the Ed25519 signer signature
      const signatures = signResp.signed_receipt.signatures as
        | { signer?: unknown; cosigner?: unknown }
        | undefined;
      const rawSigner = signatures?.signer;
      const extractedSignature =
        typeof rawSigner === "string" && rawSigner.length > 0
          ? rawSigner
          : null;

      if (!extractedSignature) {
        console.warn(
          "[receipt-inspector] Could not extract signer signature from signed_receipt:",
          rawSigner,
        );
      }

      // Step 5: Determine the verdict — map simulation results to our Verdict type
      //   - allowed=true -> "allow"
      //   - allowed=false with severity "warn" -> "warn"
      //   - allowed=false otherwise -> "deny"
      let verdict: Verdict = "allow";
      if (!simResp.allowed) {
        const hasWarnOnly = simResp.results.every(
          (r) => r.allowed || r.severity === "warning" || r.severity === "warn"
        );
        verdict = hasWarnOnly ? "warn" : "deny";
      }

      // Step 6: Find the primary guard that drove the decision
      const denyingGuard = simResp.results.find((r) => !r.allowed);
      const primaryGuard = denyingGuard?.guard ?? simResp.guard ?? "aggregate";

      // Step 7: Build per-guard evidence from simulation results
      const guardEvidence: Record<string, unknown>[] = simResp.results.map((r) => ({
        guard: r.guard,
        allowed: r.allowed,
        severity: r.severity,
        message: r.message,
        ...(r.details ? { details: r.details } : {}),
      }));

      // Step 8: Build evaluation path evidence
      const evaluationPath = simResp.evaluation_path.map((step) => ({
        guard: step.guard,
        stage: step.stage,
        duration_ms: step.stage_duration_ms,
        result: step.result,
      }));

      const receipt: Receipt = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        verdict,
        guard: primaryGuard,
        policyName,
        action: { type: sample.uiType, target: sample.target },
        evidence: {
          engine: "native",
          content_hash: contentHash,
          receipt_hash: signResp.receipt_hash,
          signed_receipt: signResp.signed_receipt,
          simulation_allowed: simResp.allowed,
          simulation_message: simResp.message,
          guard_results: guardEvidence,
          evaluation_path: evaluationPath,
          total_guards_evaluated: simResp.results.length,
          ...(extractedSignature ? {} : { signature_extraction_failed: true }),
        },
        signature: extractedSignature ?? "unsigned",
        publicKey: signResp.public_key,
        valid: extractedSignature !== null,
      };

      setReceipts((prev) => [receipt, ...prev]);
      emitAuditEvent({
        eventType: "receipt.generate_real",
        source: "receipt",
        summary: `Generated real receipt — ${receipt.verdict} (${receipt.guard}) via native engine`,
        details: {
          receiptId: receipt.id,
          verdict: receipt.verdict,
          guard: receipt.guard,
          policyName: receipt.policyName,
          actionType: sample.engineType,
          target: sample.target,
          valid: receipt.valid,
          publicKey: receipt.publicKey?.slice(0, 16) + "...",
          guardsEvaluated: simResp.results.length,
        },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[receipt-inspector] generate real receipt failed:", err);
      setGenerateError(message);
    } finally {
      setGenerating(false);
    }
  }, [state.yaml, state.activePolicy.name, selectedAction, handleGenerate]);

  const handleClear = useCallback(() => {
    clearReceipts();
  }, [clearReceipts]);

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
        // Extract the signer signature from the Rust SignedReceipt shape:
        // { receipt: {...}, signatures: { signer: "<hex>", cosigner?: "<hex>" } }
        // The `signer` field is a hex-encoded Ed25519 signature string.
        const signatures = resp.signed_receipt.signatures as
          | { signer?: unknown; cosigner?: unknown }
          | undefined;
        const rawSigner = signatures?.signer;
        const extractedSignature =
          typeof rawSigner === "string" && rawSigner.length > 0
            ? rawSigner
            : null;

        if (!extractedSignature) {
          console.warn(
            "[receipt-inspector] Could not extract signer signature from signed_receipt. " +
              "Expected resp.signed_receipt.signatures.signer to be a non-empty string, " +
              "got:",
            rawSigner,
            "Full signatures object:",
            signatures,
          );
        }

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
            ...(extractedSignature ? {} : { signature_extraction_failed: true }),
          },
          // Note: this signer signature was made over canonical JSON (RFC 8785),
          // while verify_receipt_chain verifies against "id:timestamp:verdict:guard:policy_name".
          // Chain signature verification will report mismatch for sign_receipt-generated receipts.
          signature: extractedSignature ?? "unsigned",
          publicKey: resp.public_key,
          // Mark as invalid if we couldn't extract a real signature — the receipt
          // data is present but the cryptographic binding is missing/unparseable.
          valid: extractedSignature !== null,
        };
        setReceipts((prev) => [receipt, ...prev]);
        emitAuditEvent({
          eventType: "receipt.sign",
          source: "receipt",
          summary: `Signed receipt — ${receipt.verdict} (${receipt.guard})`,
          details: {
            receiptId: receipt.id,
            verdict: receipt.verdict,
            guard: receipt.guard,
            policyName: receipt.policyName,
            valid: receipt.valid,
            publicKey: receipt.publicKey?.slice(0, 16) + "...",
          },
        });
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
            {generateError && (
              <p className="text-[10px] font-mono text-[#c45c5c] mt-1">
                Generate failed: {generateError}
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
            {isDesktop() ? (
              <>
                {/* Action type selector + Generate Real Receipt (desktop only) */}
                <div className="flex items-center gap-1">
                  <select
                    value={selectedAction}
                    onChange={(e) => setSelectedAction(Number(e.target.value))}
                    disabled={generating}
                    className="h-7 flex-1 min-w-0 px-1.5 text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded-md text-[#ece7dc] outline-none focus:border-[#3dbf84]/50 disabled:opacity-50"
                  >
                    {SAMPLE_ACTIONS.map((sa, i) => (
                      <option key={sa.engineType} value={i}>
                        {sa.label}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  onClick={handleGenerateReal}
                  disabled={generating}
                  className={cn(
                    "px-3 py-1.5 text-xs font-medium border rounded-md transition-colors",
                    generating
                      ? "text-[#6f7f9a] bg-[#131721] border-[#2d3240] cursor-wait"
                      : "text-[#3dbf84] bg-[#3dbf84]/10 border-[#3dbf84]/20 hover:bg-[#3dbf84]/20"
                  )}
                >
                  {generating ? "Generating..." : "Generate Real"}
                </button>
                <button
                  onClick={handleSignReceipt}
                  disabled={signing}
                  className={cn(
                    "px-3 py-1.5 text-xs font-medium border rounded-md transition-colors",
                    signing
                      ? "text-[#6f7f9a] bg-[#131721] border-[#2d3240] cursor-wait"
                      : "text-[#6f7f9a] bg-[#131721] border-[#2d3240] hover:border-[#d4a84b]/40 hover:text-[#ece7dc]"
                  )}
                >
                  {signing ? "Signing..." : "Sign Only"}
                </button>
              </>
            ) : (
              <button
                onClick={handleGenerate}
                className="px-3 py-1.5 text-xs font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 rounded-md hover:bg-[#d4a84b]/20 transition-colors"
              >
                Generate Test
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
