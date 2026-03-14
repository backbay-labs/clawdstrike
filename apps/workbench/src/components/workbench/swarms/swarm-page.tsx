import { useState, useMemo, useCallback } from "react";
import {
  IconNetwork,
  IconPlus,
  IconUsers,
  IconShieldCheck,
  IconBrain,
  IconX,
  IconLock,
  IconUsersGroup,
  IconWorld,
  IconChevronRight,
  IconMessage,
  IconToggleLeft,
  IconToggleRight,
} from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { cn } from "@/lib/utils";
import { useSwarms, type CreateSwarmConfig } from "@/lib/workbench/swarm-store";
import type { Swarm, SwarmType } from "@/lib/workbench/sentinel-types";

const SWARM_TYPE_BADGE: Record<SwarmType, { label: string; color: string; icon: typeof IconLock }> = {
  personal: { label: "Personal", color: "#55788b", icon: IconLock },
  trusted: { label: "Trusted", color: "#d4a84b", icon: IconUsersGroup },
  federated: { label: "Federated", color: "#8b5cf6", icon: IconWorld },
};

const TYPE_DESCRIPTIONS: Record<SwarmType, string> = {
  personal: "Your own sentinels coordinating locally",
  trusted: "Invite team members and peers",
  federated: "Open to cross-organization participation",
};

type TypeFilter = "all" | SwarmType;

export function SwarmPage() {
  const { swarms, createSwarm } = useSwarms();
  const navigate = useNavigate();

  const [filter, setFilter] = useState<TypeFilter>("all");
  const [showCreate, setShowCreate] = useState(false);

  const filteredSwarms = useMemo(() => {
    if (filter === "all") return swarms;
    return swarms.filter((s) => s.type === filter);
  }, [swarms, filter]);

  const counts = useMemo(() => {
    let personal = 0;
    let trusted = 0;
    let federated = 0;
    for (const s of swarms) {
      if (s.type === "personal") personal++;
      if (s.type === "trusted") trusted++;
      if (s.type === "federated") federated++;
    }
    return { total: swarms.length, personal, trusted, federated };
  }, [swarms]);

  const handleCreate = useCallback(
    (config: CreateSwarmConfig) => {
      const swarm = createSwarm(config);
      setShowCreate(false);
      navigate(`/swarms/${swarm.id}`);
    },
    [createSwarm, navigate],
  );

  // Empty state
  if (swarms.length === 0 && !showCreate) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center bg-[#05060a] px-8">
        <div className="w-12 h-12 rounded-xl bg-[#55788b]/10 border border-[#55788b]/20 flex items-center justify-center mb-4">
          <IconNetwork size={24} stroke={1.5} className="text-[#55788b]" />
        </div>
        <h1 className="font-syne text-lg font-bold text-[#ece7dc] mb-2">
          Swarms
        </h1>
        <p className="text-[12px] text-[#6f7f9a] max-w-md leading-relaxed text-center mb-6">
          Swarms are coordination layers where sentinels and operators share intel,
          detections, and threat knowledge. Start with a <strong className="text-[#55788b]">Personal</strong> swarm
          for your own sentinels, invite peers to a <strong className="text-[#d4a84b]">Trusted</strong> swarm,
          or join a <strong className="text-[#8b5cf6]">Federated</strong> swarm for cross-org intel exchange.
        </p>
        <div className="flex gap-6 mb-8">
          <SwarmTypeCard type="personal" />
          <SwarmTypeCard type="trusted" />
          <SwarmTypeCard type="federated" />
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-lg border border-[#d4a84b]/30 bg-[#d4a84b]/5 px-5 py-2.5 text-[12px] font-medium text-[#d4a84b] transition-colors hover:bg-[#d4a84b]/10 hover:border-[#d4a84b]/50"
        >
          <IconPlus size={14} stroke={1.5} />
          Create Your First Swarm
        </button>
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconNetwork size={18} className="text-[#55788b]" stroke={1.5} />
            <div>
              <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                Swarms
              </h1>
              <p className="text-[11px] text-[#6f7f9a] mt-0.5">
                {counts.total} swarm{counts.total !== 1 ? "s" : ""} active
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-md border border-[#d4a84b]/30 bg-[#d4a84b]/5 px-3 py-1.5 text-[11px] font-medium text-[#d4a84b] transition-colors hover:bg-[#d4a84b]/10 hover:border-[#d4a84b]/50"
          >
            <IconPlus size={13} stroke={1.5} />
            Create Swarm
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-stretch gap-3">
          <SummaryCard label="Total" value={counts.total} />
          <SummaryCard label="Personal" value={counts.personal} dotColor="#55788b" />
          <SummaryCard label="Trusted" value={counts.trusted} dotColor="#d4a84b" />
          <SummaryCard label="Federated" value={counts.federated} dotColor="#8b5cf6" />
        </div>
      </div>

      {/* Filter bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-2.5 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50 mr-1">
          Filter
        </span>
        {(["all", "personal", "trusted", "federated"] as TypeFilter[]).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={cn(
              "rounded-md px-2.5 py-1 text-[10px] font-medium capitalize transition-colors",
              filter === f
                ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40",
            )}
          >
            {f}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-[#6f7f9a]/40">
          {filteredSwarms.length} result{filteredSwarms.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Swarm cards */}
      <div className="flex-1 overflow-auto px-6 py-4">
        <div className="flex flex-col gap-3">
          {filteredSwarms.map((swarm) => (
            <SwarmCard
              key={swarm.id}
              swarm={swarm}
              onClick={() => navigate(`/swarms/${swarm.id}`)}
            />
          ))}
          {filteredSwarms.length === 0 && (
            <div className="py-12 text-center text-[12px] text-[#6f7f9a]/40">
              No swarms match the current filter
            </div>
          )}
        </div>
      </div>

      {/* Create modal */}
      {showCreate && (
        <CreateSwarmModal
          onClose={() => setShowCreate(false)}
          onCreate={handleCreate}
        />
      )}
    </div>
  );
}

function SwarmCard({ swarm, onClick }: { swarm: Swarm; onClick: () => void }) {
  const badge = SWARM_TYPE_BADGE[swarm.type];
  const BadgeIcon = badge.icon;

  const topMembers = swarm.members.slice(0, 3);
  const topIntel = swarm.sharedIntel.slice(0, 3);
  const topSpeakeasies = swarm.speakeasies.slice(0, 3);

  return (
    <button
      onClick={onClick}
      className="group w-full text-left rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] p-5 transition-colors hover:border-[#2d3240] hover:bg-[#0f1219]"
    >
      {/* Title row */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ backgroundColor: badge.color + "15" }}
          >
            <BadgeIcon size={16} style={{ color: badge.color }} stroke={1.5} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-semibold text-[#ece7dc]">
                {swarm.name}
              </span>
              <span
                className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-wider"
                style={{
                  backgroundColor: badge.color + "15",
                  color: badge.color,
                }}
              >
                {badge.label}
              </span>
            </div>
            <div className="flex items-center gap-3 mt-0.5 text-[10px] text-[#6f7f9a]/60">
              <span className="flex items-center gap-1">
                <IconUsers size={10} stroke={1.5} />
                {swarm.stats.memberCount} member{swarm.stats.memberCount !== 1 ? "s" : ""}
              </span>
              <span className="flex items-center gap-1">
                <IconBrain size={10} stroke={1.5} />
                {swarm.stats.intelShared} intel
              </span>
              <span className="flex items-center gap-1">
                <IconShieldCheck size={10} stroke={1.5} />
                {swarm.stats.activeDetections} detection{swarm.stats.activeDetections !== 1 ? "s" : ""}
              </span>
              <span className="flex items-center gap-1">
                <IconMessage size={10} stroke={1.5} />
                {swarm.stats.speakeasyCount} speakeas{swarm.stats.speakeasyCount !== 1 ? "ies" : "y"}
              </span>
            </div>
          </div>
        </div>
        <IconChevronRight
          size={14}
          className="text-[#6f7f9a]/30 group-hover:text-[#6f7f9a]/60 transition-colors mt-1"
        />
      </div>

      {/* Preview grid */}
      {(topMembers.length > 0 || topIntel.length > 0 || topSpeakeasies.length > 0) && (
        <div className="grid grid-cols-3 gap-4 mt-2 pt-3 border-t border-[#2d3240]/40">
          {/* Members preview */}
          <div>
            <span className="text-[8px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 font-semibold">
              Members
            </span>
            <div className="flex flex-col gap-1 mt-1.5">
              {topMembers.map((m) => (
                <div key={m.fingerprint} className="flex items-center gap-1.5">
                  <SigilDot fingerprint={m.fingerprint} size={12} />
                  <span className="text-[10px] text-[#ece7dc]/60 truncate">
                    {m.displayName}
                  </span>
                </div>
              ))}
              {swarm.members.length > 3 && (
                <span className="text-[9px] text-[#6f7f9a]/40">
                  +{swarm.members.length - 3} more
                </span>
              )}
            </div>
          </div>

          {/* Intel preview */}
          <div>
            <span className="text-[8px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 font-semibold">
              Recent Intel
            </span>
            <div className="flex flex-col gap-1 mt-1.5">
              {topIntel.map((ref) => (
                <div key={ref.intelId} className="flex items-center gap-1.5">
                  <IconBrain size={10} className="text-[#6f7f9a]/40 shrink-0" />
                  <span className="text-[10px] text-[#ece7dc]/60 truncate font-mono">
                    {ref.intelId.slice(0, 12)}...
                  </span>
                </div>
              ))}
              {swarm.sharedIntel.length > 3 && (
                <span className="text-[9px] text-[#6f7f9a]/40">
                  +{swarm.sharedIntel.length - 3} more
                </span>
              )}
              {topIntel.length === 0 && (
                <span className="text-[9px] text-[#6f7f9a]/30">No intel shared yet</span>
              )}
            </div>
          </div>

          {/* Speakeasies preview */}
          <div>
            <span className="text-[8px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 font-semibold">
              Speakeasies
            </span>
            <div className="flex flex-col gap-1 mt-1.5">
              {topSpeakeasies.map((ref) => (
                <div key={ref.speakeasyId} className="flex items-center gap-1.5">
                  <IconMessage size={10} className="text-[#6f7f9a]/40 shrink-0" />
                  <span className="text-[10px] text-[#ece7dc]/60 truncate">
                    #{ref.purpose}
                  </span>
                </div>
              ))}
              {swarm.speakeasies.length > 3 && (
                <span className="text-[9px] text-[#6f7f9a]/40">
                  +{swarm.speakeasies.length - 3} more
                </span>
              )}
              {topSpeakeasies.length === 0 && (
                <span className="text-[9px] text-[#6f7f9a]/30">No rooms yet</span>
              )}
            </div>
          </div>
        </div>
      )}
    </button>
  );
}

function CreateSwarmModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: (config: CreateSwarmConfig) => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState<SwarmType>("personal");
  const [requireSignatures, setRequireSignatures] = useState(true);
  const [autoShareDetections, setAutoShareDetections] = useState(false);
  const [compartmentalized, setCompartmentalized] = useState(false);
  const [minReputation, setMinReputation] = useState(0);

  // Auto-toggle compartmentalized based on type
  const handleTypeChange = useCallback((t: SwarmType) => {
    setType(t);
    if (t === "trusted" || t === "federated") {
      setCompartmentalized(true);
    } else {
      setCompartmentalized(false);
    }
  }, []);

  const canCreate = name.trim().length > 0;

  const handleSubmit = useCallback(() => {
    if (!canCreate) return;
    onCreate({
      name: name.trim(),
      type,
      policies: {
        requireSignatures,
        autoShareDetections,
        compartmentalized,
        minReputationToPublish: minReputation > 0 ? minReputation / 100 : null,
      },
    });
  }, [canCreate, name, type, requireSignatures, autoShareDetections, compartmentalized, minReputation, onCreate]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-lg rounded-xl border border-[#2d3240] bg-[#0b0d13] shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#2d3240]/60 px-6 py-4">
          <div className="flex items-center gap-2">
            <IconNetwork size={16} className="text-[#55788b]" stroke={1.5} />
            <h2 className="text-[13px] font-semibold text-[#ece7dc]">Create Swarm</h2>
          </div>
          <button
            onClick={onClose}
            className="text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors"
          >
            <IconX size={14} />
          </button>
        </div>

        <div className="px-6 py-5 flex flex-col gap-5">
          {/* Name */}
          <div>
            <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
              Swarm Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., SecOps Collective"
              maxLength={128}
              autoFocus
              className="mt-1.5 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none transition-colors focus:border-[#d4a84b]/40"
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSubmit();
              }}
            />
          </div>

          {/* Type selection */}
          <div>
            <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
              Swarm Type
            </label>
            <div className="mt-2 grid grid-cols-3 gap-2">
              {(["personal", "trusted", "federated"] as SwarmType[]).map((t) => {
                const cfg = SWARM_TYPE_BADGE[t];
                const Icon = cfg.icon;
                const isActive = type === t;
                return (
                  <button
                    key={t}
                    onClick={() => handleTypeChange(t)}
                    className={cn(
                      "flex flex-col items-center gap-1.5 rounded-lg border px-3 py-3 transition-colors",
                      isActive
                        ? "border-[#d4a84b]/40 bg-[#d4a84b]/5"
                        : "border-[#2d3240] bg-[#05060a] hover:border-[#2d3240]/80",
                    )}
                  >
                    <Icon
                      size={16}
                      style={{ color: isActive ? cfg.color : "#6f7f9a" }}
                      stroke={1.5}
                    />
                    <span
                      className={cn(
                        "text-[10px] font-semibold capitalize",
                        isActive ? "text-[#ece7dc]" : "text-[#6f7f9a]/60",
                      )}
                    >
                      {t}
                    </span>
                    <span className="text-[8px] text-[#6f7f9a]/40 text-center leading-tight">
                      {TYPE_DESCRIPTIONS[t]}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Governance policies */}
          <div>
            <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
              Governance Policies
            </label>
            <div className="mt-2 flex flex-col gap-2.5">
              <PolicyToggle
                label="Require signatures on shared artifacts"
                enabled={requireSignatures}
                onToggle={() => setRequireSignatures((v) => !v)}
              />
              <PolicyToggle
                label="Auto-share confirmed detections"
                enabled={autoShareDetections}
                onToggle={() => setAutoShareDetections((v) => !v)}
              />
              <PolicyToggle
                label="Compartmentalized (need-to-know by default)"
                enabled={compartmentalized}
                onToggle={() => setCompartmentalized((v) => !v)}
              />

              {/* Min reputation slider */}
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-[#ece7dc]/60">
                  Min reputation to publish
                </span>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={minReputation}
                    onChange={(e) => setMinReputation(Number(e.target.value))}
                    className="w-20 accent-[#d4a84b] h-1"
                  />
                  <span className="text-[10px] font-mono text-[#6f7f9a]/60 w-7 text-right">
                    {minReputation}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-[#2d3240]/60 px-6 py-3">
          <button
            onClick={onClose}
            className="rounded-md px-3 py-1.5 text-[11px] text-[#6f7f9a]/60 transition-colors hover:text-[#ece7dc]"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!canCreate}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-[11px] font-medium transition-colors",
              canCreate
                ? "bg-[#d4a84b]/10 border border-[#d4a84b]/30 text-[#d4a84b] hover:bg-[#d4a84b]/20"
                : "bg-[#2d3240]/30 border border-[#2d3240]/40 text-[#6f7f9a]/30 cursor-not-allowed",
            )}
          >
            <IconPlus size={12} stroke={1.5} />
            Create Swarm
          </button>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  dotColor,
}: {
  label: string;
  value: number | string;
  dotColor?: string;
}) {
  return (
    <div className="flex flex-col rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] px-4 py-3 min-w-[120px]">
      <span className="text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
        {label}
      </span>
      <div className="mt-1.5 flex items-center gap-2">
        {dotColor && (
          <span
            className="h-2 w-2 rounded-full shrink-0"
            style={{ backgroundColor: dotColor }}
          />
        )}
        <span className="text-[18px] font-semibold text-[#ece7dc]">
          {value}
        </span>
      </div>
    </div>
  );
}

function SwarmTypeCard({ type }: { type: SwarmType }) {
  const cfg = SWARM_TYPE_BADGE[type];
  const Icon = cfg.icon;
  return (
    <div className="flex flex-col items-center gap-2 w-40">
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center"
        style={{ backgroundColor: cfg.color + "15" }}
      >
        <Icon size={20} style={{ color: cfg.color }} stroke={1.5} />
      </div>
      <span className="text-[11px] font-semibold capitalize" style={{ color: cfg.color }}>
        {type}
      </span>
      <span className="text-[10px] text-[#6f7f9a]/50 text-center leading-tight">
        {TYPE_DESCRIPTIONS[type]}
      </span>
    </div>
  );
}

function PolicyToggle({
  label,
  enabled,
  onToggle,
}: {
  label: string;
  enabled: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className="flex items-center justify-between w-full group"
    >
      <span className="text-[11px] text-[#ece7dc]/60 group-hover:text-[#ece7dc]/80 transition-colors">
        {label}
      </span>
      {enabled ? (
        <IconToggleRight size={20} className="text-[#d4a84b]" stroke={1.5} />
      ) : (
        <IconToggleLeft size={20} className="text-[#6f7f9a]/40" stroke={1.5} />
      )}
    </button>
  );
}

function SigilDot({ fingerprint, size = 16 }: { fingerprint: string; size?: number }) {
    const byte = parseInt(fingerprint.slice(0, 2), 16) || 0;
  const hue = Math.round((byte / 255) * 360);
  const color = `hsl(${hue}, 55%, 55%)`;

  return (
    <span
      className="inline-block rounded-full shrink-0"
      style={{
        width: size,
        height: size,
        backgroundColor: color,
        opacity: 0.7,
      }}
    />
  );
}
