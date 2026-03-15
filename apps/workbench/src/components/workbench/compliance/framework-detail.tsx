import { useMemo } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import {
  scoreFramework,
  COMPLIANCE_FRAMEWORKS,
} from "@/lib/workbench/compliance-requirements";
import type { ComplianceFramework } from "@/lib/workbench/types";
import type { ComplianceRequirementDef } from "@/lib/workbench/compliance-requirements";
import { ScrollArea } from "@/components/ui/scroll-area";
import { IconCheck, IconX, IconArrowRight } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { Breadcrumb } from "@/components/workbench/shared/breadcrumb";

interface FrameworkDetailProps {
  framework: ComplianceFramework;
  onClose: () => void;
}

function RequirementRow({
  req,
  met,
}: {
  req: ComplianceRequirementDef;
  met: boolean;
}) {
  return (
    <div
      className={`flex items-start gap-3 px-4 py-3 border-b border-[#2d3240] last:border-b-0 ${
        met ? "opacity-60" : ""
      }`}
    >
      <div className="shrink-0 mt-0.5">
        {met ? (
          <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#3dbf84]/10">
            <IconCheck size={12} className="text-[#3dbf84]" stroke={2} />
          </span>
        ) : (
          <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#c45c5c]/10">
            <IconX size={12} className="text-[#c45c5c]" stroke={2} />
          </span>
        )}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-[#ece7dc]">
            {req.title}
          </span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            {req.citation}
          </span>
        </div>
        <p className="text-xs text-[#6f7f9a] mt-0.5 leading-relaxed">
          {req.description}
        </p>
        {req.guardDeps.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {req.guardDeps.map((gid) => (
              <span
                key={gid}
                className="px-1.5 py-0.5 text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded text-[#6f7f9a]"
              >
                {gid}
              </span>
            ))}
          </div>
        )}
      </div>

      {!met && (
        <Link
          to="/editor"
          className="shrink-0 flex items-center gap-1 px-2 py-1 text-[10px] font-mono uppercase text-[#d4a84b] border border-[#d4a84b]/20 rounded-md hover:bg-[#d4a84b]/10 transition-colors"
        >
          Fix
          <IconArrowRight size={10} stroke={1.5} />
        </Link>
      )}
    </div>
  );
}

export function FrameworkDetail({ framework, onClose }: FrameworkDetailProps) {
  const { state } = useWorkbench();
  const { activePolicy } = state;

  const frameworkDef = COMPLIANCE_FRAMEWORKS.find((f) => f.id === framework);

  const result = useMemo(
    () => scoreFramework(framework, activePolicy.guards, activePolicy.settings),
    [framework, activePolicy.guards, activePolicy.settings]
  );

  if (!frameworkDef) return null;

  const scoreColor =
    result.score > 80 ? "#3dbf84" : result.score >= 50 ? "#d4a84b" : "#c45c5c";

  return (
    <div className="flex flex-col h-full">
      {/* Breadcrumb */}
      <Breadcrumb items={[{ label: "Compliance", href: "/compliance" }, { label: frameworkDef.name }]} />

      {/* Header */}
      <div className="shrink-0 flex items-center justify-between px-4 py-3 border-b border-[#2d3240] bg-[#0b0d13]">
        <div className="flex items-center gap-3">
          <button
            onClick={onClose}
            className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors text-xs font-mono"
          >
            &larr; Back
          </button>
          <span className="font-syne font-semibold text-sm text-[#ece7dc]">
            {frameworkDef.name}
          </span>
          <span className="text-xs text-[#6f7f9a]">
            {frameworkDef.description}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="text-sm font-mono font-bold"
            style={{ color: scoreColor }}
          >
            {result.score}%
          </span>
          <span className="text-xs text-[#6f7f9a]">
            {result.met.length}/{frameworkDef.requirements.length} met
          </span>
        </div>
      </div>

      {/* Score bar */}
      <div className="shrink-0 px-4 py-2 border-b border-[#2d3240] bg-[#0b0d13]">
        <div className="w-full h-2 rounded-full bg-[#131721] overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${result.score}%`,
              backgroundColor: scoreColor,
            }}
          />
        </div>
      </div>

      {/* Requirements list */}
      <ScrollArea className="flex-1">
        {/* Gaps first */}
        {result.gaps.length > 0 && (
          <div>
            <div className="sticky top-0 z-10 px-4 py-2 bg-[#05060a] border-b border-[#2d3240]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#c45c5c]">
                Gaps ({result.gaps.length})
              </span>
            </div>
            {result.gaps.map((req) => (
              <RequirementRow key={req.id} req={req} met={false} />
            ))}
          </div>
        )}

        {/* Met requirements */}
        {result.met.length > 0 && (
          <div>
            <div className="sticky top-0 z-10 px-4 py-2 bg-[#05060a] border-b border-[#2d3240]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#3dbf84]">
                Met ({result.met.length})
              </span>
            </div>
            {result.met.map((req) => (
              <RequirementRow key={req.id} req={req} met={true} />
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
