/**
 * PolicyViewerView - Browse and validate policies
 */
import { useState, useMemo } from "react";
import { clsx } from "clsx";
import { GlassPanel, GlassCard } from "@backbay/glia/primitives";
import { GlowButton } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import { usePolicy } from "@/context/PolicyContext";
import { useConnection } from "@/context/ConnectionContext";
import { BUILTIN_RULESETS, type BuiltinRuleset } from "@/types/policies";

type PolicySource = BuiltinRuleset | "current" | "custom";

export function PolicyViewerView() {
  const { status } = useConnection();
  const { currentPolicy, policyBundle, isLoading, error, reloadPolicy } = usePolicy();
  const [selectedSource, setSelectedSource] = useState<PolicySource>("current");
  const [isReloading, setIsReloading] = useState(false);

  const policyYaml = useMemo(() => {
    if (selectedSource === "current" && currentPolicy) {
      return formatPolicyYaml(currentPolicy as unknown as Record<string, unknown>);
    }
    // For built-in rulesets, show placeholder
    const ruleset = BUILTIN_RULESETS.find((r) => r.id === selectedSource);
    if (ruleset) {
      return `# ${ruleset.name} Policy\n# ${ruleset.description}\n\nversion: "1.1.0"\nname: "${ruleset.id}"\nextends: "ruleset:${ruleset.id}"`;
    }
    return "# No policy loaded";
  }, [selectedSource, currentPolicy]);

  const handleReload = async () => {
    setIsReloading(true);
    try {
      await reloadPolicy();
    } catch (e) {
      console.error("Failed to reload policy:", e);
    } finally {
      setIsReloading(false);
    }
  };

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full text-sdr-text-secondary">
        Not connected to daemon
      </div>
    );
  }

  return (
    <div className="flex h-full">
      {/* Policy list sidebar */}
      <GlassPanel className="w-64 border-r border-sdr-border flex flex-col">
        <div className="px-4 py-3 border-b border-sdr-border">
          <h2 className="font-medium text-sdr-text-primary">Policies</h2>
        </div>

        <div className="flex-1 overflow-y-auto">
          {/* Current policy */}
          <div className="p-2">
            <div className="text-xs text-sdr-text-muted uppercase tracking-wide px-2 py-1">
              Active
            </div>
            <GlassCard
              className={clsx(
                "cursor-pointer mb-1",
                selectedSource === "current" && "ring-1 ring-sdr-accent-blue"
              )}
              onClick={() => setSelectedSource("current")}
            >
              <div className="font-medium text-sm">{currentPolicy?.name ?? "Current Policy"}</div>
              <div className="text-xs text-sdr-text-muted truncate">
                {isLoading ? "Loading..." : error ?? "Active daemon policy"}
              </div>
            </GlassCard>
          </div>

          {/* Built-in rulesets */}
          <div className="p-2 border-t border-sdr-border">
            <div className="text-xs text-sdr-text-muted uppercase tracking-wide px-2 py-1">
              Built-in Rulesets
            </div>
            {BUILTIN_RULESETS.map((ruleset) => (
              <GlassCard
                key={ruleset.id}
                className={clsx(
                  "cursor-pointer mb-1",
                  selectedSource === ruleset.id && "ring-1 ring-sdr-accent-blue"
                )}
                onClick={() => setSelectedSource(ruleset.id)}
              >
                <div className="font-medium text-sm">{ruleset.name}</div>
                <div className="text-xs text-sdr-text-muted truncate">{ruleset.description}</div>
              </GlassCard>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="p-3 border-t border-sdr-border">
          <GlowButton
            onClick={handleReload}
            disabled={isReloading}
            variant="secondary"
            className="w-full"
          >
            {isReloading ? "Reloading..." : "Reload Policy"}
          </GlowButton>
        </div>
      </GlassPanel>

      {/* Policy content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <div>
            <h1 className="text-lg font-semibold text-sdr-text-primary">
              {selectedSource === "current"
                ? currentPolicy?.name ?? "Current Policy"
                : BUILTIN_RULESETS.find((r) => r.id === selectedSource)?.name ?? "Policy"}
            </h1>
            {policyBundle?.policy_hash && selectedSource === "current" && (
              <p className="text-xs text-sdr-text-muted font-mono mt-0.5">
                Hash: {policyBundle.policy_hash.slice(0, 16)}...
              </p>
            )}
          </div>

          <div className="flex items-center gap-2">
            <ValidationBadge valid={!error} />
          </div>
        </div>

        {/* Guard summary */}
        {selectedSource === "current" && currentPolicy && (
          <GuardSummary guards={currentPolicy.guards} />
        )}

        {/* YAML content */}
        <div className="flex-1 overflow-auto p-4 bg-sdr-bg-primary">
          <pre className="text-sm font-mono text-sdr-text-secondary whitespace-pre-wrap">
            {policyYaml}
          </pre>
        </div>
      </div>
    </div>
  );
}


function ValidationBadge({ valid }: { valid: boolean }) {
  return (
    <Badge variant={valid ? "default" : "destructive"}>
      {valid ? (
        <>
          <CheckIcon className="w-3 h-3" />
          Valid
        </>
      ) : (
        <>
          <XIcon className="w-3 h-3" />
          Invalid
        </>
      )}
    </Badge>
  );
}

function GuardSummary({ guards }: { guards: unknown }) {
  const guardsObj = guards as Record<string, unknown>;
  const enabledGuards = Object.entries(guardsObj)
    .filter(([key, value]) => {
      if (key === "custom") return false;
      return typeof value === "object" && value !== null && (value as { enabled?: boolean }).enabled !== false;
    })
    .map(([key]) => key);

  return (
    <div className="flex items-center gap-2 px-4 py-2 border-b border-sdr-border bg-sdr-bg-secondary/50">
      <span className="text-xs text-sdr-text-muted">Guards:</span>
      {enabledGuards.map((guard) => (
        <Badge key={guard} variant="outline">
          {guard.replace(/_/g, " ")}
        </Badge>
      ))}
      {enabledGuards.length === 0 && (
        <span className="text-xs text-sdr-text-muted">No guards enabled</span>
      )}
    </div>
  );
}

function formatPolicyYaml(policy: Record<string, unknown>): string {
  // Simple YAML-like formatting
  const lines: string[] = [];

  function formatValue(value: unknown, indent: number): void {
    const prefix = "  ".repeat(indent);

    if (value === null || value === undefined) {
      return;
    }

    if (typeof value === "object" && !Array.isArray(value)) {
      Object.entries(value as Record<string, unknown>).forEach(([k, v]) => {
        if (typeof v === "object" && v !== null && !Array.isArray(v)) {
          lines.push(`${prefix}${k}:`);
          formatValue(v, indent + 1);
        } else if (Array.isArray(v)) {
          lines.push(`${prefix}${k}:`);
          v.forEach((item) => {
            if (typeof item === "object") {
              lines.push(`${prefix}  -`);
              formatValue(item, indent + 2);
            } else {
              lines.push(`${prefix}  - ${JSON.stringify(item)}`);
            }
          });
        } else {
          lines.push(`${prefix}${k}: ${JSON.stringify(v)}`);
        }
      });
    }
  }

  formatValue(policy, 0);
  return lines.join("\n");
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M20 6L9 17l-5-5" />
    </svg>
  );
}

function XIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}
