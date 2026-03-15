import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { getRecentFiles } from "@/lib/workbench/policy-store";
import { BUILTIN_RULESETS, type BuiltinRuleset } from "@/lib/workbench/builtin-rulesets";
import {
  listBuiltinRulesets,
  loadBuiltinRuleset,
} from "@/lib/tauri-commands";
import { isDesktop } from "@/lib/tauri-bridge";
import { cn } from "@/lib/utils";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { useHintSettingsSafe, type HintId } from "@/lib/workbench/use-hint-settings";
import {
  IconFile,
  IconFolderOpen,
  IconBrain,
  IconTerminal,
  IconShieldCheck,
  IconPlugConnected,
  IconBooks,
  IconLayoutGrid,
  IconCopy,
  IconCheck,
  IconEye,
  IconEyeOff,
  IconRefresh,
  IconLoader2,
  IconPlayerStop,
} from "@tabler/icons-react";
import { PolicyCard } from "./policy-card";
import { ImportExport } from "./import-export";
import { YamlViewDialog } from "./yaml-view-dialog";
import { CatalogBrowser } from "./catalog-browser";
import { SigmaHQBrowser } from "./sigmahq-browser";

const MCP_LAUNCH_COMMAND = "bun run apps/workbench/mcp-server/index.ts";

type LibraryTab = "my-policies" | "catalog" | "sigmahq";

/**
 * Merge native rulesets from the Rust engine with the client-side fallback list.
 * Native rulesets may include policies the client doesn't know about.
 */
function useBuiltinRulesets() {
  const [rulesets, setRulesets] = useState<BuiltinRuleset[]>(BUILTIN_RULESETS);
  const [loading, setLoading] = useState(false);
  const [nativeAvailable, setNativeAvailable] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    (async () => {
      const nativeList = await listBuiltinRulesets();
      if (cancelled) return;

      if (!nativeList) {
        setLoading(false);
        return;
      }

      setNativeAvailable(true);

      const merged: BuiltinRuleset[] = [];
      const clientMap = new Map(BUILTIN_RULESETS.map((r) => [r.id, r]));

      for (const nr of nativeList) {
        if (cancelled) return;
        let yaml: string | null = null;
        try {
          yaml = await loadBuiltinRuleset(nr.id);
        } catch {
          // use client fallback if available
        }

        const clientEntry = clientMap.get(nr.id);
        merged.push({
          id: nr.id,
          name: nr.name,
          description: nr.description || clientEntry?.description || "",
          yaml: yaml ?? clientEntry?.yaml ?? "",
        });
        clientMap.delete(nr.id);
      }

      // Add any client-only rulesets that aren't in the native list
      for (const remaining of clientMap.values()) {
        merged.push(remaining);
      }

      if (!cancelled) {
        setRulesets(merged);
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return { rulesets, loading, nativeAvailable };
}

import { useMcpStatus } from "@/lib/workbench/use-mcp-status";


const LIBRARY_PROMPT_CARDS: { hintId: HintId; fallbackLabel: string; fallbackPrompt: string }[] = [
  {
    hintId: "library.audit",
    fallbackLabel: "Audit My Policy",
    fallbackPrompt:
      "Read my active policy YAML. Run this full audit: 1) workbench_validate_policy for errors 2) workbench_guard_coverage for coverage gaps 3) workbench_compliance_check against HIPAA, SOC2, PCI-DSS 4) workbench_suggest_scenarios + workbench_run_all_scenarios for testing. Output a security report with scores, test results, and a prioritized fix list.",
  },
  {
    hintId: "library.testSuite",
    fallbackLabel: "Build Test Suite",
    fallbackPrompt:
      "Read my policy YAML. Call workbench_suggest_scenarios for auto-generated tests. Then use workbench_create_scenario to build 5 additional edge cases: 1) symlink traversal to /etc/shadow, 2) DNS rebinding egress to internal IP, 3) base64-encoded AWS key in file write, 4) chained shell command with pipe to nc, 5) MCP tool call with injected args. Run all with workbench_run_all_scenarios and output the full test suite as JSON I can save.",
  },
  {
    hintId: "library.harden",
    fallbackLabel: "Harden Policy",
    fallbackPrompt:
      "Read my policy YAML. Call workbench_harden_policy with level 'aggressive'. Then call workbench_diff_policies comparing my original against the hardened version. For each change, explain the security improvement. Run workbench_compliance_check on both versions and show the score improvement. Output the hardened YAML.",
  },
  {
    hintId: "library.compare",
    fallbackLabel: "Compare Versions",
    fallbackPrompt:
      "Call workbench_list_rulesets to show available built-in policies. Then read my policy YAML and call workbench_diff_policies comparing it against the 'strict' ruleset. Show exactly which guards I'm missing and which settings are weaker. Suggest the minimum changes to match strict-level security.",
  },
];

function LibraryPromptCards() {
  const hintCtx = useHintSettingsSafe();

  // Respect the master toggle — when hints are disabled, hide the cards
  if (hintCtx && !hintCtx.showHints) return null;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
      {LIBRARY_PROMPT_CARDS.map((card) => {
        const resolved = hintCtx
          ? hintCtx.getHint(card.hintId)
          : { hint: card.fallbackLabel, prompt: card.fallbackPrompt };
        return (
          <LibraryCopyableCard
            key={card.hintId}
            label={resolved.hint}
            prompt={resolved.prompt}
          />
        );
      })}
    </div>
  );
}

function LibraryCopyableCard({ label, prompt }: { label: string; prompt: string }) {
  const [cardCopied, setCardCopied] = useState(false);

  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(prompt);
          setCardCopied(true);
          setTimeout(() => setCardCopied(false), 2000);
        } catch {
          // Clipboard API may fail
        }
      }}
      className="rounded-md bg-[#0b0d13]/50 border border-[#8b5cf6]/15 hover:border-[#8b5cf6]/30 hover:bg-[#8b5cf6]/[0.04] px-2.5 py-2 text-center transition-colors group"
      title={prompt}
    >
      <p className="text-[10px] font-mono text-[#8b5cf6]/80 truncate">{label}</p>
      <p className="text-[9px] text-[#6f7f9a] mt-0.5 flex items-center justify-center gap-1">
        {cardCopied ? (
          <>
            <IconCheck size={9} className="text-[#3dbf84]" />
            <span className="text-[#3dbf84]">Copied!</span>
          </>
        ) : (
          <>
            <IconCopy
              size={9}
              className="opacity-0 group-hover:opacity-100 transition-opacity"
            />
            Copy prompt
          </>
        )}
      </p>
    </button>
  );
}

export function LibraryGallery() {
  const { state, openFile, openFileByPath } = useWorkbench();
  const { multiDispatch } = useMultiPolicy();
  const navigate = useNavigate();
  const [viewYaml, setViewYaml] = useState<{ name: string; yaml: string } | null>(null);
  const { rulesets, loading, nativeAvailable } = useBuiltinRulesets();
  const [activeTab, setActiveTab] = useState<LibraryTab>("my-policies");

  const [mcpCopied, setMcpCopied] = useState<string | null>(null);
  const [showToken, setShowToken] = useState(false);
  const desktop = isDesktop();
  const recentFiles = desktop ? getRecentFiles() : [];
  const { status: mcpStatus, isRestarting: mcpRestarting, isStopping: mcpStopping, handleRestart: mcpRestart, handleStop: mcpStop } = useMcpStatus();

  const copyToClipboard = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setMcpCopied(label);
    setTimeout(() => setMcpCopied(null), 2000);
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header + Import/Export */}
      <div className="flex items-start justify-between gap-4 mb-8 flex-wrap">
        <div>
          <h1 className="font-syne font-bold text-xl text-[#ece7dc] mb-1">
            Policy Library
          </h1>
          <p className="text-sm text-[#6f7f9a]">
            Browse built-in rulesets, manage saved policies, and import/export YAML.
          </p>
        </div>
        <ImportExport />
      </div>

      {/* Tab switcher */}
      <div className="mb-8">
        <SubTabBar
          tabs={[
            { id: "my-policies", label: "My Policies", icon: IconBooks },
            { id: "catalog", label: "Catalog", icon: IconLayoutGrid },
            { id: "sigmahq", label: "SigmaHQ", icon: IconShieldCheck },
          ] satisfies SubTab[]}
          activeTab={activeTab}
          onTabChange={(id) => setActiveTab(id as LibraryTab)}
        />
      </div>

      {/* Tab content */}
      {activeTab === "catalog" ? (
        <CatalogBrowser />
      ) : activeTab === "sigmahq" ? (
        <SigmaHQBrowser
          onImport={(yaml) => {
            multiDispatch({
              type: "NEW_TAB",
              fileType: "sigma_rule",
              yaml,
            });
            navigate("/editor");
          }}
        />
      ) : (
        <>
          {/* Recent files (desktop only) */}
          {desktop && recentFiles.length > 0 && (
            <section className="mb-8">
              <h2 className="font-syne font-bold text-sm text-[#ece7dc] mb-4 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-[#3dbf84]" />
                Recent Files
              </h2>
              <div className="space-y-1">
                {recentFiles.map((fp) => {
                  const fileName = fp.split("/").pop() ?? fp;
                  return (
                    <button
                      key={fp}
                      onClick={() => openFileByPath(fp)}
                      title={fp}
                      className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-left text-sm text-[#ece7dc] hover:bg-[#131721] transition-colors group"
                    >
                      <IconFile size={14} className="shrink-0 text-[#6f7f9a] group-hover:text-[#d4a84b]" />
                      <span className="truncate">{fileName}</span>
                      <span className="ml-auto text-[11px] text-[#6f7f9a] truncate max-w-[300px] hidden sm:inline">
                        {fp}
                      </span>
                    </button>
                  );
                })}
              </div>
              <button
                onClick={openFile}
                className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
              >
                <IconFolderOpen size={14} />
                Open another file...
              </button>
            </section>
          )}

          {/* Built-in rulesets */}
          <section className="mb-8">
            <h2 className="font-syne font-bold text-sm text-[#ece7dc] mb-4 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b]" />
              Built-in Rulesets
              {nativeAvailable && (
                <span className="text-[9px] font-mono text-[#3dbf84]/60 ml-1">
                  (from engine)
                </span>
              )}
              {loading && (
                <span className="text-[9px] font-mono text-[#d4a84b]/70 animate-pulse ml-1">
                  loading...
                </span>
              )}
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {rulesets.map((rs) => (
                <PolicyCard
                  key={rs.id}
                  id={rs.id}
                  name={rs.name}
                  description={rs.description}
                  yaml={rs.yaml}
                  isBuiltin
                  onViewYaml={() => setViewYaml({ name: rs.name, yaml: rs.yaml })}
                />
              ))}
            </div>
          </section>

          {/* User policies */}
          <section>
            <h2 className="font-syne font-bold text-sm text-[#ece7dc] mb-4 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#6f7f9a]" />
              Your Policies
            </h2>
            {state.savedPolicies.length === 0 ? (
              <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-14 text-center flex flex-col items-center">
                <div className="w-12 h-12 rounded-2xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-4">
                  <IconFile size={20} className="empty-state-icon text-[#6f7f9a]" />
                </div>
                <p className="text-[13px] font-medium text-[#6f7f9a] mb-1">
                  No saved policies yet
                </p>
                <p className="text-[11px] text-[#6f7f9a]/60 max-w-[300px] leading-relaxed">
                  Use the editor to build a policy, then save it here for quick access
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {state.savedPolicies.map((sp) => (
                  <PolicyCard
                    key={sp.id}
                    id={sp.id}
                    name={sp.policy.name}
                    description={sp.policy.description}
                    yaml={sp.yaml}
                    guardCount={Object.keys(sp.policy.guards).length}
                    version={sp.policy.version}
                    isBuiltin={false}
                    onViewYaml={() =>
                      setViewYaml({ name: sp.policy.name, yaml: sp.yaml })
                    }
                  />
                ))}
              </div>
            )}
          </section>

          {/* AI Integrations */}
          <section className="mt-8">
            <h2 className="font-syne font-bold text-sm text-[#ece7dc] mb-4 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#8b5cf6]" />
              AI Integrations
            </h2>
            <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
              <div className="flex items-start gap-4 mb-5">
                <div className="w-10 h-10 rounded-xl bg-[#8b5cf6]/10 border border-[#8b5cf6]/20 flex items-center justify-center shrink-0">
                  <IconBrain size={18} className="text-[#8b5cf6]" />
                </div>
                <div>
                  <p className="text-[13px] font-medium text-[#ece7dc] mb-1">
                    ClawdStrike MCP Server
                  </p>
                  <p className="text-[11px] text-[#6f7f9a] leading-relaxed">
                    {desktop
                      ? "The desktop app includes a secure MCP sidecar that auto-starts on launch with per-session token auth. Connect Claude Code by copying the config below into your project\u2019s .mcp.json."
                      : "Connect Claude Code to the workbench\u2019s MCP server for AI-assisted policy building. Add the config below to your project\u2019s .mcp.json to get started."}
                  </p>
                  <p className="text-[10px] text-[#6f7f9a]/60 mt-1">
                    14 tools · 5 prompts · 3 resources — scenario testing, validation, compliance scoring, hardening, and synthesis
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
                {/* Left card — MCP Server status & management */}
                <div className="rounded-lg bg-[#131721]/50 border border-[#2d3240]/40 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <IconPlugConnected size={13} className="text-[#d4a84b]" />
                    <span className="text-[11px] font-mono font-medium text-[#ece7dc]">
                      {desktop ? "Embedded Sidecar" : "MCP Server"}
                    </span>
                    {mcpStatus?.running ? (
                      <span
                        className="ml-auto flex items-center gap-1.5 text-[9px] font-mono text-[#3dbf84]"
                        title="MCP sidecar server is running — auto-started on app launch"
                      >
                        <span className="relative flex h-2 w-2">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#3dbf84] opacity-40" />
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-[#3dbf84]" />
                        </span>
                        running
                      </span>
                    ) : desktop ? (
                      <span
                        className="ml-auto flex items-center gap-1.5 text-[9px] font-mono text-[#c45c5c]"
                        title="MCP sidecar is not running — click Start to restart"
                      >
                        <span className="relative flex h-2 w-2">
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-[#c45c5c]" />
                        </span>
                        stopped
                      </span>
                    ) : null}
                  </div>

                  {mcpStatus?.running ? (
                    /* ---- Live sidecar: show connection details ---- */
                    <div className="flex flex-col gap-2">
                      <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
                        SSE transport with bearer-token auth. Token rotates each session.
                      </p>

                      {/* Endpoint URL */}
                      <div className="flex items-center gap-1.5">
                        <span className="text-[9px] text-[#6f7f9a] shrink-0 w-14">Endpoint</span>
                        <code className="flex-1 text-[10px] font-mono text-[#d4a84b]/80 bg-[#0b0d13] rounded px-2 py-1 truncate">
                          {mcpStatus.url}
                        </code>
                        <button
                          onClick={() => copyToClipboard(mcpStatus.url, "url")}
                          className="shrink-0 flex items-center justify-center w-6 h-6 rounded-md bg-[#0b0d13] border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#d4a84b] hover:border-[#d4a84b]/30 transition-colors"
                          title="Copy endpoint URL"
                        >
                          {mcpCopied === "url" ? (
                            <IconCheck size={10} className="text-[#3dbf84]" />
                          ) : (
                            <IconCopy size={10} />
                          )}
                        </button>
                      </div>

                      {/* Auth Token */}
                      <div className="flex items-center gap-1.5">
                        <span className="text-[9px] text-[#6f7f9a] shrink-0 w-14">Token</span>
                        <code className="flex-1 text-[10px] font-mono text-[#d4a84b]/80 bg-[#0b0d13] rounded px-2 py-1 truncate">
                          {showToken
                            ? mcpStatus.token
                            : `${mcpStatus.token.slice(0, 8)}${"*".repeat(20)}`}
                        </code>
                        <button
                          onClick={() => setShowToken((v) => !v)}
                          className="shrink-0 flex items-center justify-center w-6 h-6 rounded-md bg-[#0b0d13] border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                          title={showToken ? "Hide token" : "Reveal token"}
                        >
                          {showToken ? <IconEyeOff size={10} /> : <IconEye size={10} />}
                        </button>
                        <button
                          onClick={() => copyToClipboard(mcpStatus.token, "token")}
                          className="shrink-0 flex items-center justify-center w-6 h-6 rounded-md bg-[#0b0d13] border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#d4a84b] hover:border-[#d4a84b]/30 transition-colors"
                          title="Copy auth token"
                        >
                          {mcpCopied === "token" ? (
                            <IconCheck size={10} className="text-[#3dbf84]" />
                          ) : (
                            <IconCopy size={10} />
                          )}
                        </button>
                      </div>

                      {/* Restart + Stop buttons */}
                      <div className="mt-1 flex items-center gap-1.5">
                        <button
                          onClick={mcpRestart}
                          disabled={mcpRestarting || mcpStopping}
                          className={cn(
                            "flex-1 flex items-center justify-center gap-1.5 h-7 rounded-md text-[10px] font-medium border transition-colors",
                            mcpRestarting
                              ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
                              : "text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]",
                          )}
                        >
                          {mcpRestarting ? (
                            <IconLoader2 size={11} stroke={1.5} className="animate-spin" />
                          ) : (
                            <IconRefresh size={11} stroke={1.5} />
                          )}
                          {mcpRestarting ? "Restarting..." : "Restart"}
                        </button>
                        <button
                          onClick={mcpStop}
                          disabled={mcpRestarting || mcpStopping}
                          className={cn(
                            "flex-1 flex items-center justify-center gap-1.5 h-7 rounded-md text-[10px] font-medium border transition-colors",
                            mcpStopping
                              ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
                              : "text-[#ece7dc] border-[#c45c5c]/30 bg-[#131721] hover:border-[#c45c5c]/60 hover:text-[#c45c5c]",
                          )}
                        >
                          {mcpStopping ? (
                            <IconLoader2 size={11} stroke={1.5} className="animate-spin" />
                          ) : (
                            <IconPlayerStop size={11} stroke={1.5} />
                          )}
                          {mcpStopping ? "Stopping..." : "Stop"}
                        </button>
                      </div>
                    </div>
                  ) : desktop ? (
                    /* ---- Desktop but sidecar stopped ---- */
                    <div className="flex flex-col gap-2">
                      <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
                        Sidecar normally auto-starts on app launch. Click below to restart it.
                      </p>
                      {mcpStatus?.error ? (
                        <div className="rounded-md border border-[#c45c5c]/30 bg-[#2a1416]/60 px-2.5 py-2">
                          <p className="text-[10px] font-medium text-[#f0b7b7]">
                            Start failed
                          </p>
                          <p className="mt-1 text-[10px] leading-relaxed text-[#d7b0b0]">
                            {mcpStatus.error}
                          </p>
                        </div>
                      ) : null}
                      <button
                        onClick={mcpRestart}
                        disabled={mcpRestarting}
                        className={cn(
                          "flex items-center justify-center gap-1.5 h-7 rounded-md text-[10px] font-medium border transition-colors",
                          mcpRestarting
                            ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
                            : "text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]",
                        )}
                      >
                        {mcpRestarting ? (
                          <IconLoader2 size={11} stroke={1.5} className="animate-spin" />
                        ) : (
                          <IconRefresh size={11} stroke={1.5} />
                        )}
                        {mcpRestarting ? "Starting..." : "Start Server"}
                      </button>
                    </div>
                  ) : (
                    /* ---- Web mode: standalone run instructions ---- */
                    <div className="flex flex-col gap-2">
                      <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
                        Run the MCP server standalone, or use the stdio config to let Claude Code spawn it automatically.
                      </p>
                      <div className="flex items-center gap-1.5">
                        <code className="flex-1 text-[10px] font-mono text-[#d4a84b]/80 bg-[#0b0d13] rounded px-2 py-1.5 overflow-x-auto">
                          {MCP_LAUNCH_COMMAND}
                        </code>
                        <button
                          onClick={() => copyToClipboard(MCP_LAUNCH_COMMAND, "cmd")}
                          className="shrink-0 flex items-center justify-center w-7 h-7 rounded-md bg-[#0b0d13] border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#d4a84b] hover:border-[#d4a84b]/30 transition-colors"
                          title="Copy MCP launch command"
                        >
                          {mcpCopied === "cmd" ? (
                            <IconCheck size={12} className="text-[#3dbf84]" />
                          ) : (
                            <IconCopy size={12} />
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Right card — .mcp.json config for Claude Code */}
                <div className="rounded-lg bg-[#131721]/50 border border-[#2d3240]/40 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <IconTerminal size={13} className="text-[#3dbf84]" />
                    <span className="text-[11px] font-mono font-medium text-[#ece7dc]">
                      Connect Claude Code
                    </span>
                  </div>
                  <p className="text-[10px] text-[#6f7f9a] leading-relaxed mb-2">
                    {mcpStatus?.running
                      ? <>Add this to your project&apos;s <code className="text-[#d4a84b]/70">.mcp.json</code> to connect via the running sidecar (SSE + auth).</>
                      : <>Add this to your project&apos;s <code className="text-[#d4a84b]/70">.mcp.json</code> — Claude Code will spawn the server via stdio automatically.</>}
                  </p>
                  <div className="relative">
                    {mcpStatus?.running ? (
                      /* SSE config pointing to the live sidecar */
                      <>
                        <pre className="text-[9px] font-mono text-[#6f7f9a]/70 bg-[#0b0d13] rounded px-2 py-1.5 overflow-x-auto leading-relaxed whitespace-pre">
{`{
  "mcpServers": {
    "clawdstrike-workbench": {
      "url": "${mcpStatus.url}",
      "headers": {
        "Authorization": "Bearer ${showToken ? mcpStatus.token : mcpStatus.token.slice(0, 8) + "..."}"
      }
    }
  }
}`}
                        </pre>
                        <button
                          onClick={() => {
                            const config = JSON.stringify(
                              {
                                mcpServers: {
                                  "clawdstrike-workbench": {
                                    url: mcpStatus.url,
                                    headers: {
                                      Authorization: `Bearer ${mcpStatus.token}`,
                                    },
                                  },
                                },
                              },
                              null,
                              2,
                            );
                            copyToClipboard(config, "config");
                          }}
                          className="absolute top-1.5 right-1.5 flex items-center justify-center w-6 h-6 rounded-md bg-[#131721]/80 border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#3dbf84] hover:border-[#3dbf84]/30 transition-colors"
                          title="Copy SSE config for .mcp.json"
                        >
                          {mcpCopied === "config" ? (
                            <IconCheck size={10} className="text-[#3dbf84]" />
                          ) : (
                            <IconCopy size={10} />
                          )}
                        </button>
                      </>
                    ) : (
                      /* Stdio config — Claude Code spawns the process */
                      <>
                        <pre className="text-[9px] font-mono text-[#6f7f9a]/70 bg-[#0b0d13] rounded px-2 py-1.5 overflow-x-auto leading-relaxed whitespace-pre">
{`{
  "mcpServers": {
    "clawdstrike-workbench": {
      "command": "bun",
      "args": [
        "run",
        "apps/workbench/mcp-server/index.ts"
      ]
    }
  }
}`}
                        </pre>
                        <button
                          onClick={() => {
                            const config = JSON.stringify(
                              {
                                mcpServers: {
                                  "clawdstrike-workbench": {
                                    command: "bun",
                                    args: ["run", "apps/workbench/mcp-server/index.ts"],
                                  },
                                },
                              },
                              null,
                              2,
                            );
                            copyToClipboard(config, "stdio");
                          }}
                          className="absolute top-1.5 right-1.5 flex items-center justify-center w-6 h-6 rounded-md bg-[#131721]/80 border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#3dbf84] hover:border-[#3dbf84]/30 transition-colors"
                          title="Copy stdio config for .mcp.json"
                        >
                          {mcpCopied === "stdio" ? (
                            <IconCheck size={10} className="text-[#3dbf84]" />
                          ) : (
                            <IconCopy size={10} />
                          )}
                        </button>
                      </>
                    )}
                  </div>
                  {mcpStatus?.running && (
                    <p className="text-[9px] text-[#6f7f9a]/50 mt-2 leading-relaxed">
                      Token rotates on each app restart. Update your .mcp.json when you see auth errors.
                    </p>
                  )}
                </div>
              </div>

              <LibraryPromptCards />
            </div>
          </section>
        </>
      )}

      {/* YAML view dialog */}
      <YamlViewDialog
        open={viewYaml !== null}
        onClose={() => setViewYaml(null)}
        name={viewYaml?.name ?? ""}
        yaml={viewYaml?.yaml ?? ""}
      />
    </div>
  );
}
