import { useCallback, useEffect, useRef, useState } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { yamlToPolicy, policyToYaml } from "@/lib/workbench/yaml-utils";
import type { WorkbenchPolicy } from "@/lib/workbench/types";
import { BUILTIN_RULESETS } from "@/lib/workbench/builtin-rulesets";
import {
  listBuiltinRulesets,
  loadBuiltinRuleset,
} from "@/lib/tauri-commands";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectGroup,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// ---------------------------------------------------------------------------
// Hook: load the built-in ruleset list from the Rust engine (with fallback)
// ---------------------------------------------------------------------------

interface RulesetListEntry {
  id: string;
  label: string;
}

function useBuiltinRulesetList() {
  const [rulesets, setRulesets] = useState<RulesetListEntry[]>(
    BUILTIN_RULESETS.map((r) => ({ id: r.id, label: r.name }))
  );
  const [loading, setLoading] = useState(false);
  const [nativeAvailable, setNativeAvailable] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    (async () => {
      const nativeList = await listBuiltinRulesets();
      if (cancelled) return;

      if (!nativeList) {
        // Not running in Tauri -- keep client-side fallback
        setLoading(false);
        return;
      }

      setNativeAvailable(true);

      const merged: RulesetListEntry[] = [];
      const clientIds = new Set(BUILTIN_RULESETS.map((r) => r.id));

      for (const nr of nativeList) {
        merged.push({ id: nr.id, label: nr.name });
        clientIds.delete(nr.id);
      }

      // Append any client-only rulesets the engine doesn't know about
      for (const id of clientIds) {
        const client = BUILTIN_RULESETS.find((r) => r.id === id);
        if (client) {
          merged.push({ id: client.id, label: client.name });
        }
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

// ---------------------------------------------------------------------------
// Resolve a built-in ruleset to { policy, yaml } via the Rust engine,
// falling back to the client-side BUILTIN_RULESETS data.
// ---------------------------------------------------------------------------

function clientFallbackForRuleset(
  name: string
): { policy: WorkbenchPolicy; yaml: string } | null {
  const entry = BUILTIN_RULESETS.find((r) => r.id === name);
  if (!entry) return null;

  const [policy, errors] = yamlToPolicy(entry.yaml);
  if (!policy || errors.length > 0) {
    // Last resort: synthesize a minimal policy so callers always get something
    const fallback: WorkbenchPolicy = {
      version: "1.2.0",
      name: entry.name,
      description: entry.description,
      extends: name,
      guards: {},
      settings: {},
    };
    return { policy: fallback, yaml: policyToYaml(fallback) };
  }

  return { policy, yaml: entry.yaml };
}

async function resolveBuiltinRuleset(
  name: string
): Promise<{ policy: WorkbenchPolicy; yaml: string }> {
  // Try the Rust engine first
  const nativeYaml = await loadBuiltinRuleset(name);
  if (nativeYaml) {
    const [policy, errors] = yamlToPolicy(nativeYaml);
    if (policy && errors.length === 0) {
      return { policy, yaml: nativeYaml };
    }
    // If parsing the native YAML somehow fails, fall through to client data
    console.warn(
      `[policy-selector] Failed to parse native YAML for "${name}", using fallback`,
      errors
    );
  }

  // Client-side fallback
  const fallback = clientFallbackForRuleset(name);
  if (fallback) return fallback;

  // Ultimate fallback: minimal extends-only policy
  const minimal: WorkbenchPolicy = {
    version: "1.2.0",
    name,
    description: `Built-in ${name} ruleset`,
    extends: name,
    guards: {},
    settings: {},
  };
  return { policy: minimal, yaml: policyToYaml(minimal) };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface PolicySelectorProps {
  label: string;
  onSelect: (policy: WorkbenchPolicy, yaml: string) => void;
}

export function PolicySelector({ label, onSelect }: PolicySelectorProps) {
  const { state } = useWorkbench();
  const { rulesets, loading: listLoading, nativeAvailable } = useBuiltinRulesetList();

  // Cache resolved built-in rulesets so repeated selections don't re-fetch
  const cacheRef = useRef<Map<string, { policy: WorkbenchPolicy; yaml: string }>>(
    new Map()
  );

  const [loadingRuleset, setLoadingRuleset] = useState(false);

  const handleSelect = useCallback(
    async (value: string) => {
      if (value === "__current__") {
        onSelect(state.activePolicy, state.yaml);
        return;
      }

      if (value.startsWith("saved:")) {
        const id = value.slice(6);
        const saved = state.savedPolicies.find((p) => p.id === id);
        if (saved) {
          onSelect(saved.policy, saved.yaml);
        }
        return;
      }

      // Built-in ruleset -- check cache first
      const cached = cacheRef.current.get(value);
      if (cached) {
        onSelect(cached.policy, cached.yaml);
        return;
      }

      // Async load from the Rust engine (with fallback)
      setLoadingRuleset(true);
      try {
        const result = await resolveBuiltinRuleset(value);
        cacheRef.current.set(value, result);
        onSelect(result.policy, result.yaml);
      } finally {
        setLoadingRuleset(false);
      }
    },
    [state, onSelect]
  );

  const isLoading = listLoading || loadingRuleset;

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2">
        <label className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          {label}
        </label>
        {nativeAvailable && (
          <span className="text-[9px] font-mono text-[#3dbf84]/60">
            (engine)
          </span>
        )}
        {isLoading && (
          <span className="text-[9px] font-mono text-[#d4a84b]/70 animate-pulse">
            loading...
          </span>
        )}
      </div>
      <Select defaultValue="__current__" onValueChange={(val) => { if (val) handleSelect(val); }}>
        <SelectTrigger className="w-full bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
          <SelectValue placeholder="Select a policy..." />
        </SelectTrigger>
        <SelectContent className="bg-[#131721] border-[#2d3240]">
          <SelectGroup>
            <SelectLabel className="text-[#6f7f9a]">Active</SelectLabel>
            <SelectItem
              value="__current__"
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              Current Policy
            </SelectItem>
          </SelectGroup>

          <SelectSeparator />

          <SelectGroup>
            <SelectLabel className="text-[#6f7f9a]">Built-in Rulesets</SelectLabel>
            {rulesets.map((r) => (
              <SelectItem
                key={r.id}
                value={r.id}
                className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
              >
                {r.label}
              </SelectItem>
            ))}
          </SelectGroup>

          {state.savedPolicies.length > 0 && (
            <>
              <SelectSeparator />
              <SelectGroup>
                <SelectLabel className="text-[#6f7f9a]">Saved Policies</SelectLabel>
                {state.savedPolicies.map((sp) => (
                  <SelectItem
                    key={sp.id}
                    value={`saved:${sp.id}`}
                    className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    {sp.policy.name}
                  </SelectItem>
                ))}
              </SelectGroup>
            </>
          )}
        </SelectContent>
      </Select>
    </div>
  );
}
