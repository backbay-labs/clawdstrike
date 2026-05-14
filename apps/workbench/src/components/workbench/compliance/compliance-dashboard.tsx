import { useState, useMemo } from "react";
import { motion } from "motion/react";
import {
  scoreFramework,
  COMPLIANCE_FRAMEWORKS,
} from "@/lib/workbench/compliance-requirements";
import type { ComplianceFramework } from "@/lib/workbench/types";
import { FrameworkDetail } from "./framework-detail";
import {
  IconHeartbeat,
  IconShieldLock,
  IconCreditCard,
} from "@tabler/icons-react";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

const frameworkIcons: Record<ComplianceFramework, typeof IconHeartbeat> = {
  hipaa: IconHeartbeat,
  soc2: IconShieldLock,
  "pci-dss": IconCreditCard,
};

function ScoreRing({
  score,
  size = 80,
  strokeWidth = 6,
}: {
  score: number;
  size?: number;
  strokeWidth?: number;
}) {
  const color =
    score > 80 ? "#3dbf84" : score >= 50 ? "#d4a84b" : "#c45c5c";
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        {/* Background ring */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#2d3240"
          strokeWidth={strokeWidth}
        />
        {/* Score arc — stroke-draw animation */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span
          className="text-lg font-mono font-bold"
          style={{ color }}
        >
          {score}%
        </span>
      </div>
    </div>
  );
}

function FrameworkCard({
  frameworkId,
  onClick,
}: {
  frameworkId: ComplianceFramework;
  onClick: () => void;
}) {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const activeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const activePolicy = editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} };

  const framework = COMPLIANCE_FRAMEWORKS.find((f) => f.id === frameworkId);
  const result = useMemo(
    () => scoreFramework(frameworkId, activePolicy.guards, activePolicy.settings),
    [frameworkId, activePolicy.guards, activePolicy.settings]
  );

  if (!framework) return null;

  const Icon = frameworkIcons[frameworkId];
  const scoreColor =
    result.score > 80 ? "#3dbf84" : result.score >= 50 ? "#d4a84b" : "#c45c5c";

  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center gap-4 p-5 rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] hover:border-[#2d3240] hover:bg-[#0d0f17] transition-all duration-150 text-left group guard-card-hover card-shadow"
    >
      {/* Icon + Name */}
      <div className="flex items-center gap-3 w-full">
        <div
          className="flex items-center justify-center w-10 h-10 rounded-lg"
          style={{ backgroundColor: `${scoreColor}10` }}
        >
          <Icon size={20} style={{ color: scoreColor }} stroke={1.5} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-syne font-semibold text-sm text-[#ece7dc]">
            {framework.name}
          </div>
          <div className="text-[10px] text-[#6f7f9a] truncate">
            {framework.description}
          </div>
        </div>
      </div>

      {/* Score Ring */}
      <ScoreRing score={result.score} />

      {/* Stats */}
      <div className="flex items-center justify-between w-full">
        <span className="text-xs text-[#6f7f9a]">
          <span className="font-mono" style={{ color: scoreColor }}>
            {result.met.length}
          </span>
          /{framework.requirements.length} requirements met
        </span>
        <span className="text-[10px] font-mono text-[#6f7f9a] group-hover:text-[#d4a84b] transition-colors">
          View &rarr;
        </span>
      </div>

      {/* Gap indicators */}
      {result.gaps.length > 0 && (
        <div className="w-full pt-2 border-t border-[#2d3240]">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#c45c5c]">
            {result.gaps.length} gap{result.gaps.length !== 1 ? "s" : ""}
          </span>
          <div className="flex flex-wrap gap-1 mt-1.5">
            {result.gaps.slice(0, 3).map((gap) => (
              <span
                key={gap.id}
                className="px-1.5 py-0.5 text-[10px] font-mono bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded text-[#c45c5c] truncate max-w-[140px]"
              >
                {gap.title}
              </span>
            ))}
            {result.gaps.length > 3 && (
              <span className="px-1.5 py-0.5 text-[10px] font-mono text-[#6f7f9a]">
                +{result.gaps.length - 3} more
              </span>
            )}
          </div>
        </div>
      )}
    </button>
  );
}

export function ComplianceDashboard() {
  const [selectedFramework, setSelectedFramework] =
    useState<ComplianceFramework | null>(null);

  if (selectedFramework) {
    return (
      <FrameworkDetail
        framework={selectedFramework}
        onClose={() => setSelectedFramework(null)}
      />
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="shrink-0 px-6 py-4 border-b border-[#2d3240] bg-[#0b0d13]">
        <h1 className="font-syne font-bold text-base text-[#ece7dc]">
          Compliance Dashboard
        </h1>
        <p className="text-xs text-[#6f7f9a] mt-1">
          Evaluate your active policy against industry compliance frameworks.
          Click a framework to see detailed requirement coverage.
        </p>
        <ClaudeCodeHint
          hintId="compliance.check"
          className="mt-3"
        />
      </div>

      {/* Framework cards */}
      <div className="flex-1 p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 max-w-4xl">
          {COMPLIANCE_FRAMEWORKS.map((fw) => (
            <FrameworkCard
              key={fw.id}
              frameworkId={fw.id}
              onClick={() => setSelectedFramework(fw.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
