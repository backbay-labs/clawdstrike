/**
 * PolicyViewerView - Browse and validate policies
 */
import { useState, useMemo } from "react";
import { clsx } from "clsx";
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
      <div className="w-64 border-r border-sdr-border bg-sdr-bg-secondary flex flex-col">
        <div className="px-4 py-3 border-b border-sdr-border">
          <h2 className="font-medium text-sdr-text-primary">Policies</h2>
        </div>

        <div className="flex-1 overflow-y-auto">
          {/* Current policy */}
          <div className="p-2">
            <div className="text-xs text-sdr-text-muted uppercase tracking-wide px-2 py-1">
              Active
            </div>
            <PolicyListItem
              name={currentPolicy?.name ?? "Current Policy"}
              description={isLoading ? "Loading..." : error ?? "Active daemon policy"}
              selected={selectedSource === "current"}
              onClick={() => setSelectedSource("current")}
            />
          </div>

          {/* Built-in rulesets */}
          <div className="p-2 border-t border-sdr-border">
            <div className="text-xs text-sdr-text-muted uppercase tracking-wide px-2 py-1">
              Built-in Rulesets
            </div>
            {BUILTIN_RULESETS.map((ruleset) => (
              <PolicyListItem
                key={ruleset.id}
                name={ruleset.name}
                description={ruleset.description}
                selected={selectedSource === ruleset.id}
                onClick={() => setSelectedSource(ruleset.id)}
              />
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="p-3 border-t border-sdr-border">
          <button
            onClick={handleReload}
            disabled={isReloading}
            className="w-full px-3 py-2 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors disabled:opacity-50"
          >
            {isReloading ? "Reloading..." : "Reload Policy"}
          </button>
        </div>
      </div>

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

interface PolicyListItemProps {
  name: string;
  description: string;
  selected: boolean;
  onClick: () => void;
}

function PolicyListItem({ name, description, selected, onClick }: PolicyListItemProps) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "w-full text-left px-3 py-2 rounded-md transition-colors",
        selected
          ? "bg-sdr-accent-blue/20 text-sdr-text-primary"
          : "text-sdr-text-secondary hover:bg-sdr-bg-tertiary hover:text-sdr-text-primary"
      )}
    >
      <div className="font-medium text-sm">{name}</div>
      <div className="text-xs text-sdr-text-muted truncate">{description}</div>
    </button>
  );
}

function ValidationBadge({ valid }: { valid: boolean }) {
  return (
    <span
      className={clsx(
        "flex items-center gap-1 px-2 py-1 text-xs font-medium rounded",
        valid
          ? "bg-sdr-accent-green/20 text-sdr-accent-green"
          : "bg-sdr-accent-red/20 text-sdr-accent-red"
      )}
    >
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
    </span>
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
        <span
          key={guard}
          className="px-2 py-0.5 text-xs bg-sdr-accent-blue/20 text-sdr-accent-blue rounded"
        >
          {guard.replace(/_/g, " ")}
        </span>
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
