import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  IconEye,
  IconSearch,
  IconBrain,
  IconUsers,
  IconArrowLeft,
  IconArrowRight,
  IconCheck,
  IconPlus,
  IconTrash,
  IconSparkles,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useOperator } from "@/lib/workbench/operator-store";
import {
  createSentinel,
  getSentinelCapabilities,
  getSentinelDriverDefinition,
  getSentinelDriverDefinitions,
  getSentinelExecutionModeConfig,
  getSentinelExecutionModes,
  getRecommendedDriverForMode,
  getRecommendedGoalTypeForMode,
  deriveEnforcementTier,
  validateGoalsForMode,
} from "@/lib/workbench/sentinel-manager";
import type {
  SentinelMode,
  SentinelDriverKind,
  SentinelExecutionMode,
  SentinelGoal,
  PolicyRef,
  DataSource,
  EscalationPolicy,
  CreateSentinelConfig,
  Sentinel,
} from "@/lib/workbench/sentinel-manager";


const MODE_CONFIGS: {
  mode: SentinelMode;
  icon: typeof IconEye;
  label: string;
  description: string;
  color: string;
}[] = [
  {
    mode: "watcher",
    icon: IconEye,
    label: "Watcher",
    description: "Continuous monitoring and anomaly detection",
    color: "#5b8def",
  },
  {
    mode: "hunter",
    icon: IconSearch,
    label: "Hunter",
    description: "Exploratory or scheduled threat hunts",
    color: "#d4784b",
  },
  {
    mode: "curator",
    icon: IconBrain,
    label: "Curator",
    description: "Group signals, summarize findings, promote patterns",
    color: "#8b7355",
  },
  {
    mode: "liaison",
    icon: IconUsers,
    label: "Liaison",
    description: "Participate in swarms and exchange intel",
    color: "#7b6b8b",
  },
];

const GOAL_TYPES = ["detect", "hunt", "monitor", "enrich"] as const;
type GoalType = (typeof GOAL_TYPES)[number];

const GOAL_TYPE_LABELS: Record<GoalType, string> = {
  detect: "Detect",
  hunt: "Hunt",
  monitor: "Monitor",
  enrich: "Enrich",
};

const SOURCE_TYPES = [
  "fleet_audit",
  "hunt_stream",
  "external_feed",
  "spine_envelope",
  "speakeasy_topic",
] as const;

const SOURCE_TYPE_LABELS: Record<string, string> = {
  fleet_audit: "Fleet Audit Events",
  hunt_stream: "Hunt Stream",
  external_feed: "External Feed",
  spine_envelope: "Spine Envelope",
  speakeasy_topic: "Speakeasy Topic",
};

const STEPS = [
  { label: "Mode", number: 1 },
  { label: "Identity & Goals", number: 2 },
  { label: "Runtime & Policy", number: 3 },
  { label: "Review", number: 4 },
] as const;

const DRIVER_DEFINITIONS = getSentinelDriverDefinitions();
const EXECUTION_MODE_DEFINITIONS = getSentinelExecutionModes();

const RUNTIME_TARGET_PLACEHOLDERS: Record<SentinelDriverKind, string> = {
  claude_code: "Local repo or workspace path",
  openclaw: "Gateway URL, node ID, or node label",
  hushd_agent: "Fleet agent ID or runtime target",
  openai_agent: "Remote agent session or endpoint",
  mcp_worker: "MCP server or worker identifier",
};


function StepIndicator({
  currentStep,
}: {
  currentStep: number;
}) {
  return (
    <div className="flex items-center gap-2">
      {STEPS.map((step, i) => {
        const isActive = currentStep === step.number;
        const isComplete = currentStep > step.number;

        return (
          <div key={step.number} className="flex items-center gap-2">
            {i > 0 && (
              <div
                className={cn(
                  "h-px w-8",
                  isComplete || isActive ? "bg-[#d4a84b]/40" : "bg-[#2d3240]/60",
                )}
              />
            )}
            <div className="flex items-center gap-1.5">
              <div
                className={cn(
                  "w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-semibold transition-colors",
                  isActive
                    ? "bg-[#d4a84b] text-[#05060a]"
                    : isComplete
                      ? "bg-[#d4a84b]/20 text-[#d4a84b]"
                      : "bg-[#2d3240]/60 text-[#6f7f9a]/50",
                )}
              >
                {isComplete ? (
                  <IconCheck size={10} stroke={2.5} />
                ) : (
                  step.number
                )}
              </div>
              <span
                className={cn(
                  "text-[10px] font-medium hidden sm:inline",
                  isActive
                    ? "text-[#ece7dc]"
                    : isComplete
                      ? "text-[#d4a84b]/60"
                      : "text-[#6f7f9a]/40",
                )}
              >
                {step.label}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}


function ModeSelectionStep({
  selected,
  onSelect,
}: {
  selected: SentinelMode | null;
  onSelect: (mode: SentinelMode) => void;
}) {
  return (
    <div>
      <h2 className="text-[13px] font-semibold text-[#ece7dc] mb-1">
        Choose a Mode
      </h2>
      <p className="text-[11px] text-[#6f7f9a]/60 mb-5">
        Each mode determines what your sentinel can do and how it operates.
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {MODE_CONFIGS.map((cfg) => {
          const Icon = cfg.icon;
          const isSelected = selected === cfg.mode;
          const caps = getSentinelCapabilities(cfg.mode);

          return (
            <button
              key={cfg.mode}
              onClick={() => onSelect(cfg.mode)}
              className={cn(
                "flex flex-col items-start gap-3 rounded-lg border px-4 py-4 text-left transition-all duration-200",
                isSelected
                  ? "border-[#d4a84b] bg-[#d4a84b]/5"
                  : "border-[#2d3240]/60 bg-[#0b0d13] hover:border-[#2d3240] hover:bg-[#0b0d13]/80",
              )}
            >
              <div className="flex items-center gap-3">
                <div
                  className="w-9 h-9 rounded-md flex items-center justify-center shrink-0"
                  style={{ backgroundColor: cfg.color + "18" }}
                >
                  <Icon size={18} stroke={1.5} style={{ color: cfg.color }} />
                </div>
                <div>
                  <h3
                    className={cn(
                      "text-[12px] font-semibold",
                      isSelected ? "text-[#d4a84b]" : "text-[#ece7dc]",
                    )}
                  >
                    {cfg.label}
                  </h3>
                  <p className="text-[10px] text-[#6f7f9a]/60 mt-0.5">
                    {cfg.description}
                  </p>
                </div>
              </div>

              {/* Capability pills */}
              <div className="flex flex-wrap gap-1">
                {caps.canMonitor && <CapPill label="Monitor" />}
                {caps.canHunt && <CapPill label="Hunt" />}
                {caps.canCurate && <CapPill label="Curate" />}
                {caps.canLiaison && <CapPill label="Liaison" />}
                {caps.canPromoteIntel && <CapPill label="Promote Intel" />}
                {caps.canUpdateBaselines && <CapPill label="Baselines" />}
                {caps.supportsSchedule && <CapPill label="Schedule" />}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function CapPill({ label }: { label: string }) {
  return (
    <span className="rounded-full px-2 py-0.5 text-[8px] font-medium text-[#6f7f9a]/60 bg-[#131721] border border-[#2d3240]/40">
      {label}
    </span>
  );
}


interface GoalDraft {
  type: GoalType;
  description: string;
  sourceType: string;
  sourceIdentifier: string;
  escalationConfidence: number;
}

function IdentityGoalsStep({
  name,
  onNameChange,
  description,
  onDescriptionChange,
  goals,
  onGoalsChange,
  mode,
  validationErrors,
}: {
  name: string;
  onNameChange: (v: string) => void;
  description: string;
  onDescriptionChange: (v: string) => void;
  goals: GoalDraft[];
  onGoalsChange: (goals: GoalDraft[]) => void;
  mode: SentinelMode;
  validationErrors: string[];
}) {
  const addGoal = () => {
    onGoalsChange([
      ...goals,
      {
        type: getRecommendedGoalTypeForMode(mode),
        description: "",
        sourceType: "fleet_audit",
        sourceIdentifier: "",
        escalationConfidence: 0.7,
      },
    ]);
  };

  const removeGoal = (idx: number) => {
    onGoalsChange(goals.filter((_, i) => i !== idx));
  };

  const updateGoal = (idx: number, patch: Partial<GoalDraft>) => {
    onGoalsChange(goals.map((g, i) => (i === idx ? { ...g, ...patch } : g)));
  };

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-[13px] font-semibold text-[#ece7dc] mb-1">
          Identity & Goals
        </h2>
        <p className="text-[11px] text-[#6f7f9a]/60 mb-5">
          Name your sentinel and define what it should accomplish.
        </p>
      </div>

      {/* Name */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Name <span className="text-[#c45c5c]">*</span>
        </label>
        <input
          type="text"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. Aegis, Prowl, Scribe..."
          maxLength={128}
          className="rounded-md border border-[#2d3240]/60 bg-[#0b0d13] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 transition-colors"
        />
      </div>

      {/* Description */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Description
        </label>
        <textarea
          value={description}
          onChange={(e) => onDescriptionChange(e.target.value)}
          placeholder="Optional description of this sentinel's purpose..."
          rows={2}
          maxLength={512}
          className="rounded-md border border-[#2d3240]/60 bg-[#0b0d13] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 resize-none transition-colors"
        />
      </div>

      {/* Goals */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
            Goals
          </label>
          <button
            onClick={addGoal}
            className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/10 transition-colors"
          >
            <IconPlus size={11} stroke={1.5} />
            Add Goal
          </button>
        </div>

        {goals.length === 0 && (
          <div className="rounded-md border border-dashed border-[#2d3240]/40 px-4 py-6 text-center">
            <p className="text-[11px] text-[#6f7f9a]/40">
              No goals defined yet. Add a goal to specify what this sentinel should do.
            </p>
          </div>
        )}

        {goals.map((goal, idx) => (
          <div
            key={idx}
            className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/60 p-3 flex flex-col gap-2.5"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-[#6f7f9a]/40">
                Goal {idx + 1}
              </span>
              <button
                onClick={() => removeGoal(idx)}
                className="text-[#6f7f9a]/40 hover:text-[#c45c5c] transition-colors"
              >
                <IconTrash size={12} stroke={1.5} />
              </button>
            </div>

            {/* Goal type */}
            <div className="flex items-center gap-2">
              <label className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 w-[60px] shrink-0">
                Type
              </label>
              <div className="flex gap-1">
                {GOAL_TYPES.map((gt) => (
                  <button
                    key={gt}
                    onClick={() => updateGoal(idx, { type: gt })}
                    className={cn(
                      "rounded-md px-2 py-1 text-[9px] font-medium capitalize transition-colors",
                      goal.type === gt
                        ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                        : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                    )}
                  >
                    {GOAL_TYPE_LABELS[gt]}
                  </button>
                ))}
              </div>
            </div>

            {/* Goal description */}
            <div className="flex items-start gap-2">
              <label className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 w-[60px] shrink-0 mt-1.5">
                Describe
              </label>
              <input
                type="text"
                value={goal.description}
                onChange={(e) =>
                  updateGoal(idx, { description: e.target.value })
                }
                placeholder="What should this goal detect/monitor/hunt?"
                maxLength={256}
                className="flex-1 rounded-md border border-[#2d3240]/40 bg-[#131721]/40 px-2.5 py-1.5 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/25 outline-none focus:border-[#d4a84b]/30 transition-colors"
              />
            </div>

            {/* Source type */}
            <div className="flex items-center gap-2">
              <label className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 w-[60px] shrink-0">
                Source
              </label>
              <div className="flex gap-1 flex-wrap">
                {SOURCE_TYPES.map((st) => (
                  <button
                    key={st}
                    onClick={() => updateGoal(idx, { sourceType: st })}
                    className={cn(
                      "rounded-md px-2 py-1 text-[9px] font-medium transition-colors",
                      goal.sourceType === st
                        ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                        : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                    )}
                  >
                    {SOURCE_TYPE_LABELS[st]}
                  </button>
                ))}
              </div>
            </div>

            {/* Escalation confidence threshold */}
            <div className="flex items-center gap-2">
              <label className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 w-[60px] shrink-0">
                Escalate
              </label>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={goal.escalationConfidence * 100}
                onChange={(e) =>
                  updateGoal(idx, {
                    escalationConfidence: parseInt(e.target.value, 10) / 100,
                  })
                }
                className="flex-1 h-1 accent-[#d4a84b]"
              />
              <span className="text-[10px] font-mono text-[#ece7dc]/60 w-[36px] text-right">
                {Math.round(goal.escalationConfidence * 100)}%
              </span>
            </div>
          </div>
        ))}

        {/* Validation errors */}
        {validationErrors.length > 0 && (
          <div className="rounded-md border border-[#c45c5c]/20 bg-[#c45c5c]/5 px-3 py-2">
            {validationErrors.map((err, i) => (
              <p key={i} className="text-[10px] text-[#c45c5c]">
                {err}
              </p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


function PolicyScheduleStep({
  driver,
  onDriverChange,
  executionMode,
  onExecutionModeChange,
  runtimeTarget,
  onRuntimeTargetChange,
  policyName,
  onPolicyNameChange,
  policyRuleset,
  onPolicyRulesetChange,
  schedule,
  onScheduleChange,
  mode,
  escalationMinSeverity,
  onEscalationMinSeverityChange,
  requireHumanConfirmation,
  onRequireHumanConfirmationChange,
}: {
  driver: SentinelDriverKind;
  onDriverChange: (v: SentinelDriverKind) => void;
  executionMode: SentinelExecutionMode;
  onExecutionModeChange: (v: SentinelExecutionMode) => void;
  runtimeTarget: string;
  onRuntimeTargetChange: (v: string) => void;
  policyName: string;
  onPolicyNameChange: (v: string) => void;
  policyRuleset: string;
  onPolicyRulesetChange: (v: string) => void;
  schedule: string;
  onScheduleChange: (v: string) => void;
  mode: SentinelMode;
  escalationMinSeverity: string;
  onEscalationMinSeverityChange: (v: string) => void;
  requireHumanConfirmation: boolean;
  onRequireHumanConfirmationChange: (v: boolean) => void;
}) {
  const caps = getSentinelCapabilities(mode);
  const selectedDriver = getSentinelDriverDefinition(driver);
  const selectedExecutionMode = getSentinelExecutionModeConfig(executionMode);
  const enforcementTier = deriveEnforcementTier(driver, executionMode);

  const RULESETS = [
    "permissive",
    "default",
    "strict",
    "ai-agent",
    "cicd",
    "ai-agent-posture",
    "remote-desktop",
    "spider-sense",
  ];

  const SCHEDULE_PRESETS = [
    { label: "Hourly", value: "@hourly" },
    { label: "Daily", value: "@daily" },
    { label: "Weekly", value: "@weekly" },
    { label: "Every 15m", value: "*/15 * * * *" },
    { label: "Custom", value: "" },
  ];

  const SEVERITIES = ["info", "low", "medium", "high", "critical"];

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-[13px] font-semibold text-[#ece7dc] mb-1">
          Runtime, Policy & Schedule
        </h2>
        <p className="text-[11px] text-[#6f7f9a]/60 mb-5">
          Bind this sentinel to a runtime, then assign its policy and operating cadence.
        </p>
      </div>

      <div className="flex flex-col gap-3 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/60 p-4">
        <h3 className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Runtime Driver
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {DRIVER_DEFINITIONS.map((definition) => {
            const isSelected = driver === definition.kind;
            const isRecommended = definition.recommendedModes.includes(mode);
            return (
              <button
                key={definition.kind}
                onClick={() => onDriverChange(definition.kind)}
                className={cn(
                  "rounded-lg border px-3 py-3 text-left transition-colors",
                  isSelected
                    ? "border-[#d4a84b] bg-[#d4a84b]/5"
                    : "border-[#2d3240]/50 bg-[#131721]/30 hover:border-[#2d3240]",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className={cn(
                    "text-[11px] font-semibold",
                    isSelected ? "text-[#d4a84b]" : "text-[#ece7dc]",
                  )}>
                    {definition.label}
                  </span>
                  {isRecommended && (
                    <span className="rounded-full border border-[#3dbf84]/20 bg-[#3dbf84]/10 px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-[0.08em] text-[#3dbf84]">
                      Recommended
                    </span>
                  )}
                </div>
                <p className="mt-1 text-[10px] text-[#6f7f9a]/60 leading-relaxed">
                  {definition.description}
                </p>
                <div className="mt-2 flex flex-wrap gap-1">
                  <span className="rounded-full border border-[#2d3240]/40 bg-[#131721] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#6f7f9a]/60">
                    {definition.endpointType}
                  </span>
                  <span className="rounded-full border border-[#2d3240]/40 bg-[#131721] px-2 py-0.5 text-[8px] font-medium uppercase tracking-[0.08em] text-[#6f7f9a]/60">
                    Tier {definition.maxEnforcementTier} max
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/60 p-4">
        <h3 className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Execution Mode
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {EXECUTION_MODE_DEFINITIONS.map((candidate) => {
            const isSelected = executionMode === candidate.mode;
            const tierPreview = deriveEnforcementTier(driver, candidate.mode);
            return (
              <button
                key={candidate.mode}
                onClick={() => onExecutionModeChange(candidate.mode)}
                className={cn(
                  "rounded-lg border px-3 py-3 text-left transition-colors",
                  isSelected
                    ? "border-[#d4a84b] bg-[#d4a84b]/5"
                    : "border-[#2d3240]/50 bg-[#131721]/30 hover:border-[#2d3240]",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className={cn(
                    "text-[11px] font-semibold",
                    isSelected ? "text-[#d4a84b]" : "text-[#ece7dc]",
                  )}>
                    {candidate.label}
                  </span>
                  <span className="rounded-full border border-[#2d3240]/40 bg-[#131721] px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/60">
                    Tier {tierPreview}
                  </span>
                </div>
                <p className="mt-1 text-[10px] text-[#6f7f9a]/60 leading-relaxed">
                  {candidate.description}
                </p>
              </button>
            );
          })}
        </div>
        <p className="text-[10px] text-[#6f7f9a]/55">
          {selectedDriver.label} is currently configured for{" "}
          <span className="text-[#ece7dc]/70">{selectedExecutionMode.label.toLowerCase()}</span>{" "}
          with an expected enforcement tier of{" "}
          <span className="text-[#ece7dc]/70">Tier {enforcementTier}</span>.
        </p>
      </div>

      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Runtime Target (optional)
        </label>
        <input
          type="text"
          value={runtimeTarget}
          onChange={(e) => onRuntimeTargetChange(e.target.value)}
          placeholder={RUNTIME_TARGET_PLACEHOLDERS[driver]}
          maxLength={512}
          className="rounded-md border border-[#2d3240]/60 bg-[#0b0d13] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 transition-colors"
        />
        <p className="text-[10px] text-[#6f7f9a]/45">
          Use this to pre-bind the sentinel to a workspace, gateway/node, fleet
          agent, or remote runtime identifier.
        </p>
      </div>

      {/* Policy selection */}
      <div className="flex flex-col gap-3">
        <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Policy Ruleset
        </label>
        <div className="flex flex-wrap gap-1.5">
          {RULESETS.map((rs) => (
            <button
              key={rs}
              onClick={() => onPolicyRulesetChange(rs)}
              className={cn(
                "rounded-md px-2.5 py-1.5 text-[10px] font-medium capitalize transition-colors",
                policyRuleset === rs
                  ? "bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20"
                  : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 border border-[#2d3240]/40",
              )}
            >
              {rs}
            </button>
          ))}
        </div>
      </div>

      {/* Policy name override */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Policy Name (optional override)
        </label>
        <input
          type="text"
          value={policyName}
          onChange={(e) => onPolicyNameChange(e.target.value)}
          placeholder="Leave blank to use ruleset name"
          maxLength={128}
          className="rounded-md border border-[#2d3240]/60 bg-[#0b0d13] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 transition-colors"
        />
      </div>

      {/* Schedule (only for modes that support it) */}
      {caps.supportsSchedule && (
        <div className="flex flex-col gap-3">
          <label className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
            Schedule
          </label>
          <div className="flex flex-wrap gap-1.5">
            {SCHEDULE_PRESETS.map((preset) => (
              <button
                key={preset.label}
                onClick={() => onScheduleChange(preset.value)}
                className={cn(
                  "rounded-md px-2.5 py-1.5 text-[10px] font-medium transition-colors",
                  schedule === preset.value
                    ? "bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20"
                    : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 border border-[#2d3240]/40",
                )}
              >
                {preset.label}
              </button>
            ))}
          </div>
          {/* Custom cron input when "Custom" is selected or value doesn't match a preset */}
          {!SCHEDULE_PRESETS.some((p) => p.value === schedule && p.value !== "") && (
            <input
              type="text"
              value={schedule}
              onChange={(e) => onScheduleChange(e.target.value)}
              placeholder="Cron expression: */15 * * * *"
              maxLength={64}
              className="rounded-md border border-[#2d3240]/60 bg-[#0b0d13] px-3 py-2 text-[12px] font-mono text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 transition-colors"
            />
          )}
        </div>
      )}

      {/* Escalation thresholds */}
      <div className="flex flex-col gap-3 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]/60 p-4">
        <h3 className="text-[10px] font-medium uppercase tracking-wider text-[#6f7f9a]/50">
          Escalation Thresholds
        </h3>

        <div className="flex items-center gap-3">
          <label className="text-[10px] text-[#6f7f9a]/60 w-[140px] shrink-0">
            Minimum Severity
          </label>
          <div className="flex gap-1">
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                onClick={() => onEscalationMinSeverityChange(sev)}
                className={cn(
                  "rounded-md px-2 py-1 text-[9px] font-medium capitalize transition-colors",
                  escalationMinSeverity === sev
                    ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                    : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                )}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <label className="text-[10px] text-[#6f7f9a]/60 w-[140px] shrink-0">
            Require Human Confirm
          </label>
          <button
            onClick={() =>
              onRequireHumanConfirmationChange(!requireHumanConfirmation)
            }
            className={cn(
              "w-8 h-4 rounded-full relative transition-colors",
              requireHumanConfirmation
                ? "bg-[#d4a84b]"
                : "bg-[#2d3240]",
            )}
          >
            <span
              className={cn(
                "absolute top-0.5 w-3 h-3 rounded-full bg-[#ece7dc] transition-all",
                requireHumanConfirmation ? "left-4" : "left-0.5",
              )}
            />
          </button>
          <span className="text-[10px] text-[#6f7f9a]/60">
            {requireHumanConfirmation ? "Yes" : "No"}
          </span>
        </div>
      </div>
    </div>
  );
}


function ReviewStep({
  mode,
  name,
  description,
  goals,
  driver,
  executionMode,
  runtimeTarget,
  policyRuleset,
  policyName,
  schedule,
  escalationMinSeverity,
  requireHumanConfirmation,
  isCreating,
}: {
  mode: SentinelMode;
  name: string;
  description: string;
  goals: GoalDraft[];
  driver: SentinelDriverKind;
  executionMode: SentinelExecutionMode;
  runtimeTarget: string;
  policyRuleset: string;
  policyName: string;
  schedule: string;
  escalationMinSeverity: string;
  requireHumanConfirmation: boolean;
  isCreating: boolean;
}) {
  const modeConfig = MODE_CONFIGS.find((m) => m.mode === mode);
  const ModeIcon = modeConfig?.icon ?? IconEye;
  const modeColor = modeConfig?.color ?? "#6f7f9a";
  const driverDefinition = getSentinelDriverDefinition(driver);
  const executionModeConfig = getSentinelExecutionModeConfig(executionMode);
  const enforcementTier = deriveEnforcementTier(driver, executionMode);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-[13px] font-semibold text-[#ece7dc] mb-1">
          Review & Create
        </h2>
        <p className="text-[11px] text-[#6f7f9a]/60 mb-5">
          Verify your sentinel configuration before deploying.
        </p>
      </div>

      <div className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] overflow-hidden">
        {/* Sentinel identity preview */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-[#2d3240]/40">
          <div
            className="w-10 h-10 rounded-md flex items-center justify-center shrink-0"
            style={{ backgroundColor: modeColor + "18" }}
          >
            <ModeIcon size={20} stroke={1.5} style={{ color: modeColor }} />
          </div>
          <div>
            <h3 className="text-[13px] font-semibold text-[#ece7dc]">
              {name || "(unnamed)"}
            </h3>
            <div className="flex items-center gap-2 mt-0.5">
              <span
                className="rounded px-1.5 py-0.5 text-[9px] font-medium uppercase"
                style={{
                  backgroundColor: modeColor + "15",
                  color: modeColor,
                }}
              >
                {mode}
              </span>
              {description && (
                <span className="text-[10px] text-[#6f7f9a]/50 truncate max-w-[200px]">
                  {description}
                </span>
              )}
            </div>
          </div>
          <div className="ml-auto">
            <IconSparkles
              size={16}
              stroke={1.5}
              className={cn(
                "text-[#d4a84b]",
                isCreating && "animate-pulse",
              )}
            />
          </div>
        </div>

        {/* Details */}
        <div className="px-4 py-3 flex flex-col gap-2.5">
          <ReviewRow label="Driver" value={driverDefinition.label} />
          <ReviewRow
            label="Execution"
            value={`${executionModeConfig.label} (Tier ${enforcementTier})`}
          />
          {runtimeTarget && <ReviewRow label="Target" value={runtimeTarget} mono />}
          <ReviewRow label="Policy" value={policyName || policyRuleset} />
          {schedule && <ReviewRow label="Schedule" value={schedule} mono />}
          <ReviewRow
            label="Escalation"
            value={`Min severity: ${escalationMinSeverity} \u00b7 Human confirm: ${requireHumanConfirmation ? "yes" : "no"}`}
          />
          <ReviewRow
            label="Goals"
            value={
              goals.length === 0
                ? "None defined"
                : `${goals.length} goal${goals.length !== 1 ? "s" : ""}`
            }
          />
        </div>

        {/* Goal list */}
        {goals.length > 0 && (
          <div className="border-t border-[#2d3240]/40 px-4 py-3">
            <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50">
              Goal Summary
            </span>
            <div className="mt-2 flex flex-col gap-1.5">
              {goals.map((goal, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 text-[10px]"
                >
                  <span className="rounded px-1.5 py-0.5 text-[8px] font-medium uppercase bg-[#131721] text-[#6f7f9a]/60 border border-[#2d3240]/40">
                    {goal.type}
                  </span>
                  <span className="text-[#ece7dc]/70 truncate">
                    {goal.description || "(no description)"}
                  </span>
                  <span className="ml-auto text-[#6f7f9a]/40 font-mono shrink-0">
                    {SOURCE_TYPE_LABELS[goal.sourceType]}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Identity note */}
        <div className="border-t border-[#2d3240]/40 px-4 py-3 bg-[#131721]/30">
          <p className="text-[10px] text-[#6f7f9a]/50">
            An Ed25519 identity (keypair, fingerprint, and sigil) will be
            generated automatically when the sentinel is created.
          </p>
        </div>
      </div>
    </div>
  );
}

function ReviewRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline gap-3 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[80px]">{label}</span>
      <span
        className={cn("text-[#ece7dc]/70 truncate", mono && "font-mono")}
      >
        {value}
      </span>
    </div>
  );
}


export function SentinelCreate({
  onCreated,
  createFn,
}: {
  onCreated: (sentinel: Sentinel) => void;
  /** Optional store-backed create function. When provided, this is used instead
   *  of the raw engine `createSentinel` so that the created sentinel is
   *  dispatched to the React Context store automatically. */
  createFn?: (config: CreateSentinelConfig) => Promise<Sentinel>;
}) {
  const navigate = useNavigate();
  const { currentOperator, getSecretKey } = useOperator();
  const mountedRef = useRef(true);
  useEffect(() => () => { mountedRef.current = false; }, []);
  const [step, setStep] = useState(1);
  const [isCreating, setIsCreating] = useState(false);

  // Step 1: Mode
  const [mode, setMode] = useState<SentinelMode | null>(null);

  // Step 2: Identity & Goals
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [goals, setGoals] = useState<GoalDraft[]>([]);

  // Step 3: Policy & Schedule
  const [driver, setDriver] = useState<SentinelDriverKind>("hushd_agent");
  const [executionMode, setExecutionMode] = useState<SentinelExecutionMode>("assist");
  const [runtimeTarget, setRuntimeTarget] = useState("");
  const [policyName, setPolicyName] = useState("");
  const [policyRuleset, setPolicyRuleset] = useState("default");
  const [schedule, setSchedule] = useState("");
  const [escalationMinSeverity, setEscalationMinSeverity] = useState("medium");
  const [requireHumanConfirmation, setRequireHumanConfirmation] = useState(true);

  const handleModeSelect = useCallback((nextMode: SentinelMode) => {
    setMode(nextMode);
    const recommendedDriver = getRecommendedDriverForMode(nextMode);
    setDriver(recommendedDriver);
    setExecutionMode(getSentinelDriverDefinition(recommendedDriver).defaultExecutionMode);
  }, []);

  // Validation
  const goalValidationErrors = useMemo(() => {
    if (!mode || goals.length === 0) return [];
    const sentinelGoals: SentinelGoal[] = goals.map((g) => ({
      type: g.type as SentinelGoal["type"],
      description: g.description,
      sources: [
        {
          type: g.sourceType as DataSource["type"],
          identifier: g.sourceIdentifier || "default",
        },
      ],
      escalation: {
        minConfidence: g.escalationConfidence,
        minSeverity: escalationMinSeverity as EscalationPolicy["minSeverity"],
        minCorrelatedSignals: 1,
        requireHumanConfirmation,
      },
    }));
    return validateGoalsForMode(mode, sentinelGoals);
  }, [mode, goals, escalationMinSeverity, requireHumanConfirmation]);

  const canNext = useCallback((): boolean => {
    switch (step) {
      case 1:
        return mode !== null;
      case 2:
        return name.trim().length > 0 && goalValidationErrors.length === 0;
      case 3:
        return policyRuleset.length > 0;
      case 4:
        return true;
      default:
        return false;
    }
  }, [step, mode, name, goalValidationErrors, policyRuleset]);

  const handleNext = () => {
    if (step < 4 && canNext()) {
      setStep(step + 1);
    }
  };

  const handleBack = () => {
    if (step > 1) {
      setStep(step - 1);
    }
  };

  const handleCreate = useCallback(async () => {
    if (!mode || !name.trim()) return;
    setIsCreating(true);

    try {
      const sentinelGoals: SentinelGoal[] = goals.map((g) => ({
        type: g.type as SentinelGoal["type"],
        description: g.description,
        sources: [
          {
            type: g.sourceType as DataSource["type"],
            identifier: g.sourceIdentifier || "default",
          },
        ],
        escalation: {
          minConfidence: g.escalationConfidence,
          minSeverity: escalationMinSeverity as EscalationPolicy["minSeverity"],
          minCorrelatedSignals: 1,
          requireHumanConfirmation,
        },
      }));

      const policy: PolicyRef = {
        policyName: policyName || undefined,
        ruleset: policyRuleset,
      };

      const targetRef = runtimeTarget.trim();

      const secretKey = currentOperator ? await getSecretKey() : null;
      if (!mountedRef.current) return;

      const config: CreateSentinelConfig = {
        name: name.trim(),
        mode,
        owner: currentOperator?.fingerprint ?? "workbench-anonymous",
        policy,
        goals: sentinelGoals,
        schedule: schedule || null,
        fleetAgentId: driver === "hushd_agent" ? targetRef || null : null,
        runtime: {
          driver,
          executionMode,
          targetRef: targetRef || null,
        },
        operatorPublicKey: currentOperator?.publicKey,
        operatorSecretKey: secretKey ?? undefined,
      };

      const doCreate = createFn ?? createSentinel;
      const sentinel = await doCreate(config);
      if (!mountedRef.current) return;
      onCreated(sentinel);
      navigate(`/sentinels/${sentinel.id}`);
    } catch (err) {
      console.error("[sentinel-create] Failed to create sentinel:", err);
    } finally {
      if (mountedRef.current) {
        setIsCreating(false);
      }
    }
  }, [
    mode,
    name,
    goals,
    policyName,
    policyRuleset,
    schedule,
    driver,
    executionMode,
    runtimeTarget,
    escalationMinSeverity,
    requireHumanConfirmation,
    onCreated,
    createFn,
    navigate,
    currentOperator,
    getSecretKey,
  ]);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconSparkles
              size={18}
              className="text-[#d4a84b]"
              stroke={1.5}
            />
            <div>
              <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                Create Sentinel
              </h1>
              <p className="text-[11px] text-[#6f7f9a] mt-0.5">
                Deploy a new autonomous defender
              </p>
            </div>
          </div>
          <StepIndicator currentStep={step} />
        </div>
      </div>

      {/* Step content */}
      <div className="flex-1 overflow-auto">
        <div className="max-w-2xl mx-auto px-6 py-6">
          {step === 1 && (
            <ModeSelectionStep selected={mode} onSelect={handleModeSelect} />
          )}
          {step === 2 && mode && (
            <IdentityGoalsStep
              name={name}
              onNameChange={setName}
              description={description}
              onDescriptionChange={setDescription}
              goals={goals}
              onGoalsChange={setGoals}
              mode={mode}
              validationErrors={goalValidationErrors}
            />
          )}
          {step === 3 && mode && (
            <PolicyScheduleStep
              driver={driver}
              onDriverChange={setDriver}
              executionMode={executionMode}
              onExecutionModeChange={setExecutionMode}
              runtimeTarget={runtimeTarget}
              onRuntimeTargetChange={setRuntimeTarget}
              policyName={policyName}
              onPolicyNameChange={setPolicyName}
              policyRuleset={policyRuleset}
              onPolicyRulesetChange={setPolicyRuleset}
              schedule={schedule}
              onScheduleChange={setSchedule}
              mode={mode}
              escalationMinSeverity={escalationMinSeverity}
              onEscalationMinSeverityChange={setEscalationMinSeverity}
              requireHumanConfirmation={requireHumanConfirmation}
              onRequireHumanConfirmationChange={setRequireHumanConfirmation}
            />
          )}
          {step === 4 && mode && (
            <ReviewStep
              mode={mode}
              name={name}
              description={description}
              goals={goals}
              driver={driver}
              executionMode={executionMode}
              runtimeTarget={runtimeTarget}
              policyRuleset={policyRuleset}
              policyName={policyName}
              schedule={schedule}
              escalationMinSeverity={escalationMinSeverity}
              requireHumanConfirmation={requireHumanConfirmation}
              isCreating={isCreating}
            />
          )}
        </div>
      </div>

      {/* Navigation footer */}
      <div className="shrink-0 border-t border-[#2d3240]/60 px-6 py-3 flex items-center justify-between">
        <button
          onClick={step === 1 ? () => navigate("/sentinels") : handleBack}
          className="flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
        >
          <IconArrowLeft size={13} stroke={1.5} />
          {step === 1 ? "Cancel" : "Back"}
        </button>

        {step < 4 ? (
          <button
            onClick={handleNext}
            disabled={!canNext()}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-[11px] font-medium transition-colors",
              canNext()
                ? "bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] hover:bg-[#d4a84b]/20"
                : "bg-[#2d3240]/30 border border-[#2d3240]/40 text-[#6f7f9a]/30 cursor-not-allowed",
            )}
          >
            Next
            <IconArrowRight size={13} stroke={1.5} />
          </button>
        ) : (
          <button
            onClick={handleCreate}
            disabled={isCreating || !canNext()}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-[11px] font-medium transition-colors",
              isCreating
                ? "bg-[#d4a84b]/5 border border-[#d4a84b]/10 text-[#d4a84b]/50 cursor-not-allowed"
                : "bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] hover:bg-[#d4a84b]/20",
            )}
          >
            {isCreating ? (
              <>
                <IconSparkles size={13} stroke={1.5} className="animate-spin" />
                Creating...
              </>
            ) : (
              <>
                <IconCheck size={13} stroke={1.5} />
                Create Sentinel
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}
