import { useCallback } from "react";
import { WobbleCard } from "@/components/ui/wobble-card";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { yamlToPolicy } from "@/lib/workbench/yaml-utils";
import { cn } from "@/lib/utils";
import { IconEye, IconDownload, IconTrash } from "@tabler/icons-react";

interface PolicyCardProps {
  id: string;
  name: string;
  description: string;
  yaml: string;
  guardCount?: number;
  version?: string;
  isBuiltin: boolean;
  onViewYaml: () => void;
}

export function PolicyCard({
  id,
  name,
  description,
  yaml,
  guardCount,
  version,
  isBuiltin,
  onViewYaml,
}: PolicyCardProps) {
  const { loadPolicy, dispatch } = useWorkbench();

  // Count guards from yaml if not provided
  const effectiveGuardCount = guardCount ?? countGuards(yaml);
  const effectiveVersion = version ?? extractVersion(yaml);

  const handleLoad = useCallback(() => {
    const [policy] = yamlToPolicy(yaml);
    if (policy) {
      loadPolicy(policy);
    }
  }, [yaml, loadPolicy]);

  const handleDelete = useCallback(() => {
    dispatch({ type: "DELETE_SAVED_POLICY", id });
  }, [id, dispatch]);

  if (isBuiltin) {
    return (
      <WobbleCard
        containerClassName="bg-[#0b0d13] border border-[#2d3240] min-h-[160px] card-shadow"
        className="!p-4 !py-4 flex flex-col justify-between h-full"
      >
        <div>
          <div className="flex items-start justify-between gap-2 mb-2">
            <h3 className="font-syne font-bold text-sm text-[#ece7dc]">
              {name}
            </h3>
            <div className="flex items-center gap-1 shrink-0">
              {effectiveVersion && (
                <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#131721] text-[#6f7f9a] border border-[#2d3240] rounded">
                  v{effectiveVersion}
                </span>
              )}
              <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20 rounded">
                {effectiveGuardCount} guards
              </span>
            </div>
          </div>
          <p className="text-xs text-[#6f7f9a] line-clamp-2 mb-3 leading-relaxed">
            {description}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleLoad}
            className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
          >
            <IconDownload size={12} stroke={1.5} />
            Load
          </button>
          <button
            onClick={onViewYaml}
            className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#ece7dc] transition-colors"
          >
            <IconEye size={12} stroke={1.5} />
            View YAML
          </button>
        </div>
      </WobbleCard>
    );
  }

  // User policy card — regular styling
  return (
    <div className="flex flex-col justify-between rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-4 min-h-[160px] guard-card-hover hover:border-[#2d3240] card-shadow">
      <div>
        <div className="flex items-start justify-between gap-2 mb-2">
          <h3 className="font-syne font-bold text-sm text-[#ece7dc]">
            {name || "Untitled"}
          </h3>
          <div className="flex items-center gap-1 shrink-0">
            {effectiveVersion && (
              <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#131721] text-[#6f7f9a] border border-[#2d3240] rounded">
                v{effectiveVersion}
              </span>
            )}
            <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#6f7f9a]/10 text-[#6f7f9a] border border-[#6f7f9a]/20 rounded">
              {effectiveGuardCount} guards
            </span>
          </div>
        </div>
        <p className="text-xs text-[#6f7f9a] line-clamp-2 mb-3 leading-relaxed">
          {description || "No description"}
        </p>
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={handleLoad}
          className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
        >
          <IconDownload size={12} stroke={1.5} />
          Load
        </button>
        <button
          onClick={onViewYaml}
          className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#ece7dc] transition-colors"
        >
          <IconEye size={12} stroke={1.5} />
          View YAML
        </button>
        <button
          onClick={handleDelete}
          className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[#c45c5c]/60 text-[11px] font-medium hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors ml-auto"
        >
          <IconTrash size={12} stroke={1.5} />
          Delete
        </button>
      </div>
    </div>
  );
}

/** Extract guard count from YAML text. */
function countGuards(yaml: string): number {
  const [policy] = yamlToPolicy(yaml);
  if (policy) {
    return Object.keys(policy.guards).filter((k) => {
      const g = policy.guards[k as keyof typeof policy.guards];
      return g && (g as { enabled?: boolean }).enabled !== false;
    }).length;
  }
  return 0;
}

/** Extract version from YAML text. */
function extractVersion(yaml: string): string | undefined {
  const match = yaml.match(/version:\s*["']?([^"'\s]+)/);
  return match?.[1];
}
