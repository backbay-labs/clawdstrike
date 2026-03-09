import { useState, useEffect } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { getRecentFiles } from "@/lib/workbench/policy-store";
import { BUILTIN_RULESETS, type BuiltinRuleset } from "@/lib/workbench/builtin-rulesets";
import { listBuiltinRulesets, loadBuiltinRuleset } from "@/lib/tauri-commands";
import { isDesktop } from "@/lib/tauri-bridge";
import { cn } from "@/lib/utils";
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
} from "@tabler/icons-react";
import { PolicyCard } from "./policy-card";
import { ImportExport } from "./import-export";
import { YamlViewDialog } from "./yaml-view-dialog";
import { CatalogBrowser } from "./catalog-browser";

const MCP_LAUNCH_COMMAND = "bun run apps/workbench/mcp-server/index.ts";

type LibraryTab = "my-policies" | "catalog";

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

export function LibraryGallery() {
  const { state, openFile, openFileByPath } = useWorkbench();
  const [viewYaml, setViewYaml] = useState<{ name: string; yaml: string } | null>(null);
  const { rulesets, loading, nativeAvailable } = useBuiltinRulesets();
  const [activeTab, setActiveTab] = useState<LibraryTab>("my-policies");

  const [mcpCopied, setMcpCopied] = useState(false);
  const desktop = isDesktop();
  const recentFiles = desktop ? getRecentFiles() : [];

  const copyMcpCommand = async () => {
    await navigator.clipboard.writeText(MCP_LAUNCH_COMMAND);
    setMcpCopied(true);
    setTimeout(() => setMcpCopied(false), 2000);
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header + Import/Export */}
      <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
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
      <div className="flex items-center gap-1 mb-6 border-b border-[#2d3240]/40 pb-px">
        <button
          onClick={() => setActiveTab("my-policies")}
          className={cn(
            "flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-t-md transition-colors -mb-px border-b-2",
            activeTab === "my-policies"
              ? "text-[#ece7dc] border-[#d4a84b] bg-[#131721]/30"
              : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:bg-[#131721]/20",
          )}
        >
          <IconBooks size={15} stroke={1.5} />
          My Policies
        </button>
        <button
          onClick={() => setActiveTab("catalog")}
          className={cn(
            "flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-t-md transition-colors -mb-px border-b-2",
            activeTab === "catalog"
              ? "text-[#ece7dc] border-[#d4a84b] bg-[#131721]/30"
              : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:bg-[#131721]/20",
          )}
        >
          <IconLayoutGrid size={15} stroke={1.5} />
          Catalog
        </button>
      </div>

      {/* Tab content */}
      {activeTab === "catalog" ? (
        <CatalogBrowser />
      ) : (
        <>
          {/* Recent files (desktop only) */}
          {desktop && recentFiles.length > 0 && (
            <section className="mb-10">
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
          <section className="mb-10">
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
          <section className="mt-10">
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
                    Claude Code Workbench Plugin
                  </p>
                  <p className="text-[11px] text-[#6f7f9a] leading-relaxed">
                    Use AI coding assistants to build test scenarios, run policy simulations,
                    check compliance, and tighten security — all from your terminal.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
                <div className="rounded-lg bg-[#131721]/50 border border-[#2d3240]/40 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <IconPlugConnected size={13} className="text-[#d4a84b]" />
                    <span className="text-[11px] font-mono font-medium text-[#ece7dc]">
                      MCP Server
                    </span>
                    <span
                      className="ml-auto flex items-center gap-1.5 text-[9px] font-mono text-[#3dbf84]"
                      title="MCP server is available (embedded in workbench)"
                    >
                      <span className="relative flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#3dbf84] opacity-40" />
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-[#3dbf84]" />
                      </span>
                      available
                    </span>
                  </div>
                  <p className="text-[10px] text-[#6f7f9a] leading-relaxed mb-2">
                    10 tools for scenario testing, policy validation, compliance scoring, and policy synthesis.
                  </p>
                  <div className="flex items-center gap-1.5">
                    <code className="flex-1 text-[10px] font-mono text-[#d4a84b]/80 bg-[#0b0d13] rounded px-2 py-1.5 overflow-x-auto">
                      {MCP_LAUNCH_COMMAND}
                    </code>
                    <button
                      onClick={copyMcpCommand}
                      className="shrink-0 flex items-center justify-center w-7 h-7 rounded-md bg-[#0b0d13] border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#d4a84b] hover:border-[#d4a84b]/30 transition-colors"
                      title="Copy MCP launch command"
                    >
                      {mcpCopied ? (
                        <IconCheck size={12} className="text-[#3dbf84]" />
                      ) : (
                        <IconCopy size={12} />
                      )}
                    </button>
                  </div>
                </div>

                <div className="rounded-lg bg-[#131721]/50 border border-[#2d3240]/40 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <IconTerminal size={13} className="text-[#3dbf84]" />
                    <span className="text-[11px] font-mono font-medium text-[#ece7dc]">
                      Plugin Install
                    </span>
                  </div>
                  <p className="text-[10px] text-[#6f7f9a] leading-relaxed mb-2">
                    Install the plugin in Claude Code for skills and auto-validation hooks.
                  </p>
                  <code className="block text-[10px] font-mono text-[#3dbf84]/80 bg-[#0b0d13] rounded px-2 py-1.5 overflow-x-auto">
                    claude plugin add ./workbench-plugin
                  </code>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { cmd: "/workbench:build-scenario", label: "Build Scenarios", icon: IconShieldCheck },
                  { cmd: "/workbench:tighten-policy", label: "Tighten Policy", icon: IconShieldCheck },
                  { cmd: "/workbench:security-audit", label: "Security Audit", icon: IconShieldCheck },
                  { cmd: "/workbench:observe-analyze", label: "Observe & Analyze", icon: IconShieldCheck },
                ].map(({ cmd, label }) => (
                  <div
                    key={cmd}
                    className="rounded-md bg-[#0b0d13]/50 border border-[#2d3240]/30 px-2.5 py-2 text-center"
                  >
                    <p className="text-[10px] font-mono text-[#8b5cf6]/80 truncate">{cmd}</p>
                    <p className="text-[9px] text-[#6f7f9a] mt-0.5">{label}</p>
                  </div>
                ))}
              </div>
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
