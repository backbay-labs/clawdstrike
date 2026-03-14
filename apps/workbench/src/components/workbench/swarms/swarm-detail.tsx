import {
  useState,
  useMemo,
  useCallback,
  useRef,
  useEffect,
  type MouseEvent as ReactMouseEvent,
} from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  IconNetwork,
  IconUsers,
  IconShieldCheck,
  IconTopologyRing,
  IconMessage,
  IconSettings,
  IconArrowLeft,
  IconChevronDown,
  IconTrash,
  IconLogout,
  IconUser,
  IconRobot,
  IconArrowsSort,
  IconCrown,
  IconEye,
  IconEdit,
  IconZoomIn,
  IconZoomOut,
  IconFocus2,
  IconX,
  IconLock,
  IconUsersGroup,
  IconWorld,
  IconToggleLeft,
  IconToggleRight,
  IconClock,
  IconMail,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarms } from "@/lib/workbench/swarm-store";
import type {
  Swarm,
  SwarmMember,
  SwarmRole,
  SwarmType,
  TrustEdge,
  DetectionRef,
  SpeakeasyRef,
  SpeakeasyPurpose,
} from "@/lib/workbench/sentinel-types";
import type { TrustLevel } from "@/lib/workbench/delegation-types";
import { SwarmInvite } from "./swarm-invite";

type DetailTab = "members" | "detections" | "trust" | "speakeasies" | "invite" | "settings";

const TABS: { id: DetailTab; label: string; icon: typeof IconUsers }[] = [
  { id: "members", label: "Members", icon: IconUsers },
  { id: "detections", label: "Shared Detections", icon: IconShieldCheck },
  { id: "trust", label: "Trust Graph", icon: IconTopologyRing },
  { id: "speakeasies", label: "Speakeasies", icon: IconMessage },
  { id: "invite", label: "Invite", icon: IconMail },
  { id: "settings", label: "Settings", icon: IconSettings },
];

const SWARM_TYPE_BADGE: Record<SwarmType, { label: string; color: string; icon: typeof IconLock }> = {
  personal: { label: "Personal", color: "#55788b", icon: IconLock },
  trusted: { label: "Trusted", color: "#d4a84b", icon: IconUsersGroup },
  federated: { label: "Federated", color: "#8b5cf6", icon: IconWorld },
};

const ROLE_COLORS: Record<SwarmRole, string> = {
  admin: "#d4a84b",
  contributor: "#3dbf84",
  observer: "#6f7f9a",
};

const PURPOSE_COLORS: Record<SpeakeasyPurpose, string> = {
  finding: "#d4a84b",
  campaign: "#8b5cf6",
  incident: "#c45c5c",
  coordination: "#3dbf84",
  mentoring: "#55788b",
};

const TRUST_COLORS: Record<TrustLevel, string> = {
  System: "#3dbf84",
  High: "#55788b",
  Medium: "#d4a84b",
  Low: "#c45c5c",
  Untrusted: "#6f7f9a",
};

export function SwarmDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { swarms, deleteSwarm } = useSwarms();

  const swarm = useMemo(() => swarms.find((s) => s.id === id), [swarms, id]);
  const [activeTab, setActiveTab] = useState<DetailTab>("members");

  if (!swarm) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center bg-[#05060a]">
        <IconNetwork size={24} className="text-[#6f7f9a]/30 mb-3" />
        <p className="text-[12px] text-[#6f7f9a]/60">Swarm not found</p>
        <button
          onClick={() => navigate("/swarms")}
          className="mt-3 text-[11px] text-[#d4a84b] hover:text-[#d4a84b]/80 transition-colors"
        >
          Back to Swarms
        </button>
      </div>
    );
  }

  const badge = SWARM_TYPE_BADGE[swarm.type];
  const BadgeIcon = badge.icon;

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate("/swarms")}
              className="text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors"
            >
              <IconArrowLeft size={16} stroke={1.5} />
            </button>
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ backgroundColor: badge.color + "15" }}
            >
              <BadgeIcon size={16} style={{ color: badge.color }} stroke={1.5} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                  {swarm.name}
                </h1>
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
              <div className="flex items-center gap-3 mt-0.5 text-[10px] text-[#6f7f9a]/50">
                <span>{swarm.stats.memberCount} member{swarm.stats.memberCount !== 1 ? "s" : ""}</span>
                <span>Created {new Date(swarm.createdAt).toLocaleDateString()}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                if (confirm("Leave this swarm?")) {
                  // In a real implementation this would remove the current user
                  navigate("/swarms");
                }
              }}
              className="flex items-center gap-1 rounded-md border border-[#2d3240] px-2.5 py-1.5 text-[10px] text-[#6f7f9a]/60 transition-colors hover:border-[#c45c5c]/30 hover:text-[#c45c5c]"
            >
              <IconLogout size={12} stroke={1.5} />
              Leave
            </button>
            <button
              onClick={() => {
                if (confirm(`Delete swarm "${swarm.name}"? This cannot be undone.`)) {
                  deleteSwarm(swarm.id);
                  navigate("/swarms");
                }
              }}
              className="flex items-center gap-1 rounded-md border border-[#2d3240] px-2.5 py-1.5 text-[10px] text-[#6f7f9a]/60 transition-colors hover:border-[#c45c5c]/30 hover:text-[#c45c5c]"
            >
              <IconTrash size={12} stroke={1.5} />
              Delete
            </button>
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 flex items-center gap-0.5">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2.5 text-[11px] font-medium border-b-2 transition-colors",
                isActive
                  ? "border-[#d4a84b] text-[#d4a84b]"
                  : "border-transparent text-[#6f7f9a]/50 hover:text-[#ece7dc]/70",
              )}
            >
              <Icon size={13} stroke={1.5} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "members" && <MembersTab swarm={swarm} />}
        {activeTab === "detections" && <DetectionsTab swarm={swarm} />}
        {activeTab === "trust" && <TrustGraphTab swarm={swarm} />}
        {activeTab === "speakeasies" && <SpeakeasiesTab swarm={swarm} />}
        {activeTab === "invite" && (
          <div className="h-full overflow-auto px-6 py-4">
            <SwarmInvite swarmId={swarm.id} />
          </div>
        )}
        {activeTab === "settings" && <SettingsTab swarm={swarm} />}
      </div>
    </div>
  );
}

type MemberSortCol = "name" | "type" | "role" | "reputation" | "joined";

function MembersTab({ swarm }: { swarm: Swarm }) {
  const { removeMember, updateMember } = useSwarms();
  const [sortCol, setSortCol] = useState<MemberSortCol>("reputation");
  const [sortAsc, setSortAsc] = useState(false);
  const [expandedFp, setExpandedFp] = useState<string | null>(null);

  const sorted = useMemo(() => {
    const list = [...swarm.members];
    list.sort((a, b) => {
      let cmp = 0;
      switch (sortCol) {
        case "name":
          cmp = a.displayName.localeCompare(b.displayName);
          break;
        case "type":
          cmp = a.type.localeCompare(b.type);
          break;
        case "role": {
          const order: Record<SwarmRole, number> = { admin: 0, contributor: 1, observer: 2 };
          cmp = order[a.role] - order[b.role];
          break;
        }
        case "reputation":
          cmp = a.reputation.overall - b.reputation.overall;
          break;
        case "joined":
          cmp = a.joinedAt - b.joinedAt;
          break;
      }
      return sortAsc ? cmp : -cmp;
    });
    return list;
  }, [swarm.members, sortCol, sortAsc]);

  const handleSort = useCallback(
    (col: MemberSortCol) => {
      if (sortCol === col) setSortAsc((p) => !p);
      else {
        setSortCol(col);
        setSortAsc(true);
      }
    },
    [sortCol],
  );

  const handleRoleChange = useCallback(
    (fp: string, role: SwarmRole) => {
      updateMember(swarm.id, fp, { role });
    },
    [swarm.id, updateMember],
  );

  return (
    <div className="h-full overflow-auto">
      <table className="w-full min-w-[700px]">
        <thead className="sticky top-0 z-10 bg-[#0b0d13]">
          <tr className="border-b border-[#2d3240]/60">
            <MemberSortHeader label="" col="type" current={sortCol} asc={sortAsc} onSort={handleSort} className="w-10" />
            <MemberSortHeader label="Name / Fingerprint" col="name" current={sortCol} asc={sortAsc} onSort={handleSort} />
            <MemberSortHeader label="Role" col="role" current={sortCol} asc={sortAsc} onSort={handleSort} />
            <MemberSortHeader label="Reputation" col="reputation" current={sortCol} asc={sortAsc} onSort={handleSort} />
            <MemberSortHeader label="Joined" col="joined" current={sortCol} asc={sortAsc} onSort={handleSort} />
            <th className="px-3 py-2.5 text-left text-[9px] uppercase tracking-[0.08em] font-semibold text-[#6f7f9a]/50">
              Actions
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((member) => {
            const isExpanded = expandedFp === member.fingerprint;
            return (
              <MemberRow
                key={member.fingerprint}
                member={member}
                isExpanded={isExpanded}
                swarmId={swarm.id}
                onToggle={() => setExpandedFp(isExpanded ? null : member.fingerprint)}
                onRoleChange={(role) => handleRoleChange(member.fingerprint, role)}
                onRemove={() => removeMember(swarm.id, member.fingerprint)}
              />
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={6} className="py-12 text-center text-[12px] text-[#6f7f9a]/40">
                No members yet. Add sentinels or invite operators to this swarm.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function MemberSortHeader({
  label,
  col,
  current,
  asc,
  onSort,
  className,
}: {
  label: string;
  col: MemberSortCol;
  current: MemberSortCol;
  asc: boolean;
  onSort: (col: MemberSortCol) => void;
  className?: string;
}) {
  const active = current === col;
  return (
    <th
      className={cn(
        "px-3 py-2.5 text-left text-[9px] uppercase tracking-[0.08em] font-semibold select-none cursor-pointer transition-colors",
        active ? "text-[#d4a84b]" : "text-[#6f7f9a]/50 hover:text-[#6f7f9a]",
        className,
      )}
      onClick={() => onSort(col)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active && (
          <IconArrowsSort
            size={10}
            className={cn("transition-transform", !asc && "rotate-180")}
          />
        )}
      </span>
    </th>
  );
}

function MemberRow({
  member,
  isExpanded,
  swarmId,
  onToggle,
  onRoleChange,
  onRemove,
}: {
  member: SwarmMember;
  isExpanded: boolean;
  swarmId: string;
  onToggle: () => void;
  onRoleChange: (role: SwarmRole) => void;
  onRemove: () => void;
}) {
  const [showRoleMenu, setShowRoleMenu] = useState(false);
  const roleRef = useRef<HTMLDivElement>(null);

  // Close role dropdown on outside click
  useEffect(() => {
    if (!showRoleMenu) return;
    const handler = (e: MouseEvent) => {
      if (roleRef.current && !roleRef.current.contains(e.target as Node)) {
        setShowRoleMenu(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showRoleMenu]);

  return (
    <>
      <tr
        onClick={onToggle}
        className={cn(
          "border-b border-[#2d3240]/30 cursor-pointer transition-colors",
          isExpanded ? "bg-[#131721]" : "hover:bg-[#0b0d13]",
        )}
      >
        {/* Type icon */}
        <td className="px-3 py-2.5 text-center">
          {member.type === "sentinel" ? (
            <IconRobot size={14} className="text-[#55788b]/60 inline-block" stroke={1.5} />
          ) : (
            <IconUser size={14} className="text-[#d4a84b]/60 inline-block" stroke={1.5} />
          )}
        </td>

        {/* Name / fingerprint */}
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-2">
            <SigilDot fingerprint={member.fingerprint} size={16} />
            <div>
              <div className="text-[11px] text-[#ece7dc]/80">{member.displayName}</div>
              <div className="text-[9px] font-mono text-[#6f7f9a]/40">{member.fingerprint}</div>
            </div>
          </div>
        </td>

        {/* Role badge */}
        <td className="px-3 py-2.5">
          <span
            className="rounded px-1.5 py-0.5 text-[9px] font-medium uppercase"
            style={{
              backgroundColor: ROLE_COLORS[member.role] + "15",
              color: ROLE_COLORS[member.role],
            }}
          >
            {member.role === "admin" && <IconCrown size={8} className="inline mr-0.5 -mt-0.5" />}
            {member.role === "observer" && <IconEye size={8} className="inline mr-0.5 -mt-0.5" />}
            {member.role === "contributor" && <IconEdit size={8} className="inline mr-0.5 -mt-0.5" />}
            {member.role}
          </span>
        </td>

        {/* Reputation bar */}
        <td className="px-3 py-2.5">
          <div className="flex items-center gap-2">
            <div className="w-16 h-1.5 rounded-full bg-[#1a1f2e] overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${Math.round(member.reputation.overall * 100)}%`,
                  backgroundColor: reputationColor(member.reputation.overall),
                }}
              />
            </div>
            <span className="text-[10px] font-mono text-[#6f7f9a]/50 w-8 text-right">
              {Math.round(member.reputation.overall * 100)}
            </span>
          </div>
        </td>

        {/* Joined */}
        <td className="px-3 py-2.5 text-[10px] font-mono text-[#6f7f9a]/50">
          {new Date(member.joinedAt).toLocaleDateString()}
        </td>

        {/* Actions */}
        <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center gap-1">
            <div ref={roleRef} className="relative">
              <button
                onClick={() => setShowRoleMenu((v) => !v)}
                className="flex items-center gap-0.5 rounded px-1.5 py-1 text-[9px] text-[#6f7f9a]/50 border border-[#2d3240]/60 hover:border-[#2d3240] hover:text-[#6f7f9a] transition-colors"
              >
                Role
                <IconChevronDown size={9} />
              </button>
              {showRoleMenu && (
                <div className="absolute left-0 top-full z-20 mt-1 w-28 rounded border border-[#2d3240] bg-[#0b0d13] py-0.5 shadow-lg">
                  {(["admin", "contributor", "observer"] as SwarmRole[]).map((role) => (
                    <button
                      key={role}
                      onClick={() => {
                        onRoleChange(role);
                        setShowRoleMenu(false);
                      }}
                      className={cn(
                        "w-full px-2.5 py-1 text-left text-[10px] capitalize transition-colors hover:bg-[#1a1f2e]",
                        member.role === role ? "text-[#d4a84b]" : "text-[#ece7dc]/60",
                      )}
                    >
                      {role}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              onClick={onRemove}
              className="rounded p-1 text-[#6f7f9a]/30 hover:text-[#c45c5c] transition-colors"
              title="Remove member"
            >
              <IconTrash size={11} stroke={1.5} />
            </button>
          </div>
        </td>
      </tr>

      {/* Expanded detail */}
      {isExpanded && (
        <tr className="border-b border-[#2d3240]/30">
          <td colSpan={6} className="bg-[#0b0d13] px-6 py-4">
            <div className="flex gap-8">
              <div className="flex flex-col gap-2 min-w-[200px]">
                <DetailSectionLabel text="Identity" />
                <DetailRow label="Type" value={member.type} />
                <DetailRow label="Fingerprint" value={member.fingerprint} mono />
                {member.sentinelId && (
                  <DetailRow label="Sentinel ID" value={member.sentinelId} mono />
                )}
                <DetailRow label="Last seen" value={new Date(member.lastSeenAt).toLocaleString()} />
              </div>
              <div className="flex flex-col gap-2 min-w-[200px]">
                <DetailSectionLabel text="Reputation Breakdown" />
                <DetailRow label="Overall" value={`${Math.round(member.reputation.overall * 100)}%`} />
                <DetailRow label="Trust Level" value={member.reputation.trustLevel} />
                <DetailRow label="Intel contributed" value={String(member.reputation.intelContributed)} />
                <DetailRow label="True positives" value={String(member.reputation.truePositives)} />
                <DetailRow label="False positives" value={String(member.reputation.falsePositives)} />
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function DetectionsTab({ swarm }: { swarm: Swarm }) {
  if (swarm.sharedDetections.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-center">
          <IconShieldCheck size={24} className="text-[#6f7f9a]/20 mx-auto mb-3" />
          <p className="text-[12px] text-[#6f7f9a]/40">No shared detections yet</p>
          <p className="text-[10px] text-[#6f7f9a]/30 mt-1">
            Publish intel artifacts as detection rules to distribute to swarm members
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto px-6 py-4">
      <div className="flex flex-col gap-2">
        {swarm.sharedDetections.map((det) => (
          <DetectionCard key={det.intelId} detection={det} />
        ))}
      </div>
    </div>
  );
}

function DetectionCard({ detection }: { detection: DetectionRef }) {
  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconShieldCheck size={14} className="text-[#3dbf84]/60" stroke={1.5} />
          <div>
            <span className="text-[11px] font-mono text-[#ece7dc]/70">
              {detection.intelId}
            </span>
            <div className="flex items-center gap-2 mt-0.5">
              <span
                className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
                style={{ backgroundColor: "#3dbf84" + "15", color: "#3dbf84" }}
              >
                {detection.sourceFormat}
              </span>
              {detection.autoActivated && (
                <span className="text-[8px] text-[#d4a84b]/60">auto-activated</span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-[#6f7f9a]/40">
          <IconClock size={10} />
          {new Date(detection.publishedAt).toLocaleDateString()}
        </div>
      </div>
    </div>
  );
}

interface ForceNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  member: SwarmMember;
}

interface ForceEdge {
  from: string;
  to: string;
  trustLevel: TrustLevel;
  weight: number;
}

function trustLevelWeight(level: TrustLevel): number {
  switch (level) {
    case "System": return 5;
    case "High": return 4;
    case "Medium": return 3;
    case "Low": return 2;
    case "Untrusted": return 1;
    default: return 1;
  }
}

function runForceSimulation(
  members: SwarmMember[],
  edges: TrustEdge[],
  width: number,
  height: number,
): { nodes: ForceNode[]; edges: ForceEdge[] } {
  // Initialize nodes in a circle
  const nodes: ForceNode[] = members.map((m, i) => {
    const angle = (2 * Math.PI * i) / Math.max(members.length, 1);
    const radius = Math.min(width, height) * 0.3;
    return {
      id: m.fingerprint,
      x: width / 2 + Math.cos(angle) * radius,
      y: height / 2 + Math.sin(angle) * radius,
      vx: 0,
      vy: 0,
      member: m,
    };
  });

  const forceEdges: ForceEdge[] = edges.map((e) => ({
    from: e.from,
    to: e.to,
    trustLevel: e.trustLevel,
    weight: trustLevelWeight(e.trustLevel),
  }));

  const nodeMap = new Map<string, ForceNode>();
  for (const n of nodes) nodeMap.set(n.id, n);

  // Run simulation iterations
  const iterations = 100;
  const repulsion = 3000;
  const attraction = 0.005;
  const centerPull = 0.01;
  const damping = 0.9;

  for (let iter = 0; iter < iterations; iter++) {
    const temp = 1 - iter / iterations;

    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (repulsion * temp) / (dist * dist);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        a.vx -= dx;
        a.vy -= dy;
        b.vx += dx;
        b.vy += dy;
      }
    }

    // Attraction along edges
    for (const e of forceEdges) {
      const a = nodeMap.get(e.from);
      const b = nodeMap.get(e.to);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = attraction * dist * e.weight * temp;
      a.vx += (dx / dist) * force;
      a.vy += (dy / dist) * force;
      b.vx -= (dx / dist) * force;
      b.vy -= (dy / dist) * force;
    }

    // Center pull
    for (const n of nodes) {
      n.vx += (width / 2 - n.x) * centerPull * temp;
      n.vy += (height / 2 - n.y) * centerPull * temp;
    }

    // Apply velocities
    for (const n of nodes) {
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
      // Clamp to bounds
      n.x = Math.max(40, Math.min(width - 40, n.x));
      n.y = Math.max(40, Math.min(height - 40, n.y));
    }
  }

  return { nodes, edges: forceEdges };
}

function TrustGraphTab({ swarm }: { swarm: Swarm }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [containerElement, setContainerElement] = useState<HTMLDivElement | null>(null);
  const [zoom, setZoom] = useState(1);
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<ForceNode | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  const handleContainerRef = useCallback((el: HTMLDivElement | null) => {
    containerRef.current = el;
    setContainerElement(el);
  }, []);

  // Compute layout
  const layout = useMemo(() => {
    const w = 800;
    const h = 600;
    return runForceSimulation(swarm.members, swarm.trustGraph, w, h);
  }, [swarm.members, swarm.trustGraph]);

  const nodeMap = useMemo(() => {
    const m = new Map<string, ForceNode>();
    for (const n of layout.nodes) m.set(n.id, n);
    return m;
  }, [layout]);

  // Zoom refs
  const zoomRef = useRef(zoom);
  const panXRef = useRef(panX);
  const panYRef = useRef(panY);
  useEffect(() => { zoomRef.current = zoom; }, [zoom]);
  useEffect(() => { panXRef.current = panX; }, [panX]);
  useEffect(() => { panYRef.current = panY; }, [panY]);

  // Pan handlers
  const onMouseDown = useCallback((e: ReactMouseEvent) => {
    if ((e.target as HTMLElement).closest("[data-node]")) return;
    isPanningRef.current = true;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const onMouseMove = useCallback((e: ReactMouseEvent) => {
    if (!isPanningRef.current) return;
    const dx = e.clientX - lastMouseRef.current.x;
    const dy = e.clientY - lastMouseRef.current.y;
    setPanX((p) => p + dx);
    setPanY((p) => p + dy);
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const onMouseUp = useCallback(() => {
    isPanningRef.current = false;
  }, []);

  // Wheel zoom
  useEffect(() => {
    if (!containerElement) return;
    const container = containerElement;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const rect = container.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      const curZoom = zoomRef.current;
      const curPanX = panXRef.current;
      const curPanY = panYRef.current;
      const newZoom = Math.min(Math.max(curZoom * factor, 0.15), 4);
      const wx = (x - curPanX) / curZoom;
      const wy = (y - curPanY) / curZoom;
      setPanX(x - wx * newZoom);
      setPanY(y - wy * newZoom);
      setZoom(newZoom);
    };
    container.addEventListener("wheel", handler, { passive: false });
    return () => container.removeEventListener("wheel", handler);
  }, [containerElement]);

  const fitToScreen = useCallback(() => {
    setPanX(0);
    setPanY(0);
    setZoom(1);
  }, []);

  const onBackgroundClick = useCallback((e: ReactMouseEvent) => {
    if ((e.target as HTMLElement).closest("[data-node]")) return;
    setSelectedNode(null);
  }, []);

  if (swarm.members.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-center">
          <IconTopologyRing size={24} className="text-[#6f7f9a]/20 mx-auto mb-3" />
          <p className="text-[12px] text-[#6f7f9a]/40">No members to visualize</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full overflow-hidden">
      <div
        ref={handleContainerRef}
        className="relative flex-1 cursor-grab active:cursor-grabbing"
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onClick={onBackgroundClick}
      >
        {/* Toolbar */}
        <div className="absolute left-3 top-3 z-10 flex items-center gap-0.5 rounded-md border border-[#1a1f2e] bg-[#0b0d13]/95 px-1.5 py-1 backdrop-blur-sm">
          <ToolbarBtn icon={IconFocus2} label="Fit" onClick={fitToScreen} />
          <ToolbarBtn
            icon={IconZoomIn}
            label="In"
            onClick={() => setZoom((z) => Math.min(z * 1.25, 4))}
            disabled={zoom >= 4}
          />
          <ToolbarBtn
            icon={IconZoomOut}
            label="Out"
            onClick={() => setZoom((z) => Math.max(z / 1.25, 0.15))}
            disabled={zoom <= 0.15}
          />
        </div>

        {/* Zoom indicator */}
        <div className="absolute bottom-3 left-3 z-10 rounded border border-[#1a1f2e] bg-[#0b0d13]/90 px-2 py-0.5 text-[10px] tabular-nums text-[#6f7f9a]/60">
          {Math.round(zoom * 100)}%
        </div>

        <svg className="h-full w-full" style={{ background: "#05060a" }}>
          <defs>
            <pattern id="swarm-grid-dot" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="0.5" fill="#1a1f2e" />
            </pattern>
          </defs>

          <rect width="100%" height="100%" fill="url(#swarm-grid-dot)" />

          <g data-viewport="" transform={`translate(${panX},${panY}) scale(${zoom})`}>
            {/* Edges */}
            {layout.edges.map((edge, i) => {
              const fromNode = nodeMap.get(edge.from);
              const toNode = nodeMap.get(edge.to);
              if (!fromNode || !toNode) return null;

              const color = TRUST_COLORS[edge.trustLevel] ?? "#2d3240";
              const thickness = Math.max(1, edge.weight * 0.8);
              const isHighlighted =
                selectedNode &&
                (selectedNode.id === edge.from || selectedNode.id === edge.to);
              const isDimmed = selectedNode && !isHighlighted;

              return (
                <line
                  key={`${edge.from}-${edge.to}-${i}`}
                  x1={fromNode.x}
                  y1={fromNode.y}
                  x2={toNode.x}
                  y2={toNode.y}
                  stroke={isHighlighted ? "#d4a84b" : color}
                  strokeWidth={isHighlighted ? thickness + 0.5 : thickness}
                  opacity={isDimmed ? 0.1 : isHighlighted ? 1 : 0.4}
                  className="transition-opacity duration-200"
                />
              );
            })}

            {/* Nodes */}
            {layout.nodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              const isHovered = hoveredNodeId === node.id;
              const isDimmed = selectedNode && !isSelected &&
                !layout.edges.some(
                  (e) =>
                    (e.from === selectedNode.id && e.to === node.id) ||
                    (e.to === selectedNode.id && e.from === node.id),
                );

              // Node radius based on reputation
              const baseR = 18;
              const r = baseR + node.member.reputation.overall * 8;
              const repColor = reputationColor(node.member.reputation.overall);
              const isSentinel = node.member.type === "sentinel";

              return (
                <g
                  key={node.id}
                  data-node={node.id}
                  transform={`translate(${node.x},${node.y})`}
                  opacity={isDimmed ? 0.15 : 1}
                  className="cursor-pointer transition-opacity duration-200"
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                  }}
                >
                  {/* Outer glow for selected */}
                  {isSelected && (
                    <circle
                      r={r + 4}
                      fill="none"
                      stroke="#d4a84b"
                      strokeWidth={0.5}
                      opacity={0.3}
                      style={{ filter: "blur(4px)" }}
                    />
                  )}

                  {/* Reputation ring */}
                  <circle
                    r={r}
                    fill="#0f1219"
                    stroke={isSelected ? "#d4a84b" : isHovered ? "#2d3240" : repColor}
                    strokeWidth={isSelected ? 2 : 1.5}
                    opacity={isSelected ? 1 : 0.7}
                  />

                  {/* Sigil colored fill */}
                  <circle
                    r={r - 3}
                    fill={sigilColor(node.member.fingerprint)}
                    opacity={0.15}
                  />

                  {/* Icon */}
                  <foreignObject x={-8} y={-8} width={16} height={16}>
                    {isSentinel ? (
                      <IconRobot size={14} className="text-[#55788b]" stroke={1.5} />
                    ) : (
                      <IconUser size={14} className="text-[#d4a84b]" stroke={1.5} />
                    )}
                  </foreignObject>

                  {/* Label */}
                  <text
                    y={r + 12}
                    textAnchor="middle"
                    fill={isSelected ? "#ece7dc" : "#c4c9d4"}
                    fontSize={9}
                    fontFamily="'JetBrains Mono', ui-monospace, monospace"
                    fontWeight={500}
                    className="select-none"
                  >
                    {node.member.displayName.length > 12
                      ? node.member.displayName.slice(0, 11) + "\u2026"
                      : node.member.displayName}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Detail panel */}
      {selectedNode && (
        <div className="flex w-56 shrink-0 flex-col border-l border-[#1a1f2e] bg-[#0b0d13]">
          <div className="flex items-center justify-between border-b border-[#1a1f2e] px-4 py-3">
            <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
              Member
            </h2>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-[#6f7f9a]/50 transition-colors hover:text-[#ece7dc]"
            >
              <IconX size={13} />
            </button>
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-3">
            <div className="flex items-center gap-2 mb-3">
              <SigilDot fingerprint={selectedNode.member.fingerprint} size={24} />
              <div>
                <div className="text-[12px] font-semibold text-[#ece7dc]">
                  {selectedNode.member.displayName}
                </div>
                <div className="text-[9px] font-mono text-[#6f7f9a]/40">
                  {selectedNode.member.fingerprint}
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-3">
              <div>
                <span className="text-[8px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 font-semibold">
                  Info
                </span>
                <div className="flex flex-col gap-1 mt-1">
                  <MiniRow label="Type" value={selectedNode.member.type} />
                  <MiniRow label="Role" value={selectedNode.member.role} />
                  <MiniRow label="Trust" value={selectedNode.member.reputation.trustLevel} />
                </div>
              </div>

              <div>
                <span className="text-[8px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 font-semibold">
                  Reputation
                </span>
                <div className="flex flex-col gap-1 mt-1">
                  <MiniRow
                    label="Score"
                    value={`${Math.round(selectedNode.member.reputation.overall * 100)}%`}
                  />
                  <MiniRow
                    label="Intel"
                    value={String(selectedNode.member.reputation.intelContributed)}
                  />
                  <MiniRow
                    label="TP / FP"
                    value={`${selectedNode.member.reputation.truePositives} / ${selectedNode.member.reputation.falsePositives}`}
                  />
                </div>
              </div>

              <div>
                <span className="text-[8px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 font-semibold">
                  Trust Connections
                </span>
                <div className="flex flex-col gap-1 mt-1">
                  {layout.edges
                    .filter((e) => e.from === selectedNode.id || e.to === selectedNode.id)
                    .map((e, i) => {
                      const peerId = e.from === selectedNode.id ? e.to : e.from;
                      const peer = nodeMap.get(peerId);
                      return (
                        <div
                          key={i}
                          className="rounded border border-[#1a1f2e] bg-[#05060a]/50 px-2 py-1"
                        >
                          <div className="text-[9px] text-[#ece7dc]/60 truncate">
                            {peer?.member.displayName ?? peerId.slice(0, 8)}
                          </div>
                          <div
                            className="text-[8px]"
                            style={{ color: TRUST_COLORS[e.trustLevel] ?? "#6f7f9a" }}
                          >
                            {e.trustLevel}
                          </div>
                        </div>
                      );
                    })}
                  {layout.edges.filter(
                    (e) => e.from === selectedNode.id || e.to === selectedNode.id,
                  ).length === 0 && (
                    <span className="text-[9px] text-[#6f7f9a]/30">No trust edges</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SpeakeasiesTab({ swarm }: { swarm: Swarm }) {
  if (swarm.speakeasies.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-center">
          <IconMessage size={24} className="text-[#6f7f9a]/20 mx-auto mb-3" />
          <p className="text-[12px] text-[#6f7f9a]/40">No speakeasy rooms yet</p>
          <p className="text-[10px] text-[#6f7f9a]/30 mt-1">
            Private signed rooms for sensitive collaboration and intel exchange
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto px-6 py-4">
      <div className="flex flex-col gap-2">
        {swarm.speakeasies.map((ref) => (
          <SpeakeasyCard key={ref.speakeasyId} speakeasy={ref} />
        ))}
      </div>
    </div>
  );
}

function SpeakeasyCard({ speakeasy }: { speakeasy: SpeakeasyRef }) {
  const purposeColor = PURPOSE_COLORS[speakeasy.purpose] ?? "#6f7f9a";

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconMessage size={14} style={{ color: purposeColor }} stroke={1.5} />
          <div>
            <span className="text-[11px] font-mono text-[#ece7dc]/70">
              #{speakeasy.purpose}
            </span>
            <div className="flex items-center gap-2 mt-0.5">
              <span
                className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
                style={{ backgroundColor: purposeColor + "15", color: purposeColor }}
              >
                {speakeasy.purpose}
              </span>
              {speakeasy.attachedTo && (
                <span className="text-[8px] text-[#6f7f9a]/40 font-mono">
                  {speakeasy.attachedTo.slice(0, 16)}...
                </span>
              )}
            </div>
          </div>
        </div>
        <span className="text-[9px] font-mono text-[#6f7f9a]/30">
          {speakeasy.speakeasyId.slice(0, 12)}
        </span>
      </div>
    </div>
  );
}

function SettingsTab({ swarm }: { swarm: Swarm }) {
  const { updatePolicy, deleteSwarm } = useSwarms();
  const navigate = useNavigate();

  const handleToggle = useCallback(
    (key: "requireSignatures" | "autoShareDetections" | "compartmentalized") => {
      updatePolicy(swarm.id, { [key]: !swarm.policies[key] });
    },
    [swarm.id, swarm.policies, updatePolicy],
  );

  const handleMinReputation = useCallback(
    (value: number) => {
      updatePolicy(swarm.id, {
        minReputationToPublish: value > 0 ? value / 100 : null,
      });
    },
    [swarm.id, updatePolicy],
  );

  return (
    <div className="h-full overflow-auto px-6 py-6">
      <div className="max-w-lg">
        {/* Governance */}
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/60 mb-4">
          Governance Policies
        </h3>

        <div className="flex flex-col gap-3 mb-8">
          <PolicyToggle
            label="Require signatures on shared artifacts"
            description="All intel artifacts shared to this swarm must carry valid Ed25519 signatures"
            enabled={swarm.policies.requireSignatures}
            onToggle={() => handleToggle("requireSignatures")}
          />
          <PolicyToggle
            label="Auto-share confirmed detections"
            description="Automatically push confirmed detection rules to all swarm members"
            enabled={swarm.policies.autoShareDetections}
            onToggle={() => handleToggle("autoShareDetections")}
          />
          <PolicyToggle
            label="Compartmentalized (need-to-know)"
            description="Intel is compartmentalized by default; members see only what they need"
            enabled={swarm.policies.compartmentalized}
            onToggle={() => handleToggle("compartmentalized")}
          />

          {/* Min reputation */}
          <div className="flex items-center justify-between rounded-lg border border-[#2d3240]/40 bg-[#0b0d13] px-4 py-3">
            <div>
              <span className="text-[11px] text-[#ece7dc]/70">
                Minimum reputation to publish
              </span>
              <p className="text-[9px] text-[#6f7f9a]/40 mt-0.5">
                Members below this threshold cannot share intel
              </p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="range"
                min={0}
                max={100}
                value={Math.round((swarm.policies.minReputationToPublish ?? 0) * 100)}
                onChange={(e) => handleMinReputation(Number(e.target.value))}
                className="w-24 accent-[#d4a84b] h-1"
              />
              <span className="text-[10px] font-mono text-[#6f7f9a]/60 w-7 text-right">
                {Math.round((swarm.policies.minReputationToPublish ?? 0) * 100)}
              </span>
            </div>
          </div>
        </div>

        {/* Danger zone */}
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#c45c5c]/60 mb-4">
          Danger Zone
        </h3>
        <div className="flex flex-col gap-2 rounded-lg border border-[#c45c5c]/20 bg-[#c45c5c]/5 p-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[11px] text-[#ece7dc]/70">Delete swarm</span>
              <p className="text-[9px] text-[#6f7f9a]/40 mt-0.5">
                Permanently delete this swarm and all shared data
              </p>
            </div>
            <button
              onClick={() => {
                if (confirm(`Delete swarm "${swarm.name}"? This action cannot be undone.`)) {
                  deleteSwarm(swarm.id);
                  navigate("/swarms");
                }
              }}
              className="flex items-center gap-1 rounded-md border border-[#c45c5c]/30 px-3 py-1.5 text-[10px] text-[#c45c5c] transition-colors hover:bg-[#c45c5c]/10"
            >
              <IconTrash size={12} stroke={1.5} />
              Delete Swarm
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function PolicyToggle({
  label,
  description,
  enabled,
  onToggle,
}: {
  label: string;
  description?: string;
  enabled: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className="flex items-center justify-between rounded-lg border border-[#2d3240]/40 bg-[#0b0d13] px-4 py-3 group text-left w-full"
    >
      <div>
        <span className="text-[11px] text-[#ece7dc]/70 group-hover:text-[#ece7dc]/90 transition-colors">
          {label}
        </span>
        {description && (
          <p className="text-[9px] text-[#6f7f9a]/40 mt-0.5">{description}</p>
        )}
      </div>
      {enabled ? (
        <IconToggleRight size={22} className="text-[#d4a84b] shrink-0 ml-3" stroke={1.5} />
      ) : (
        <IconToggleLeft size={22} className="text-[#6f7f9a]/40 shrink-0 ml-3" stroke={1.5} />
      )}
    </button>
  );
}

function ToolbarBtn({
  icon: Icon,
  label,
  onClick,
  disabled = false,
}: {
  icon: React.ComponentType<{ size?: number; stroke?: number }>;
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      disabled={disabled}
      className={cn(
        "flex h-6 items-center gap-1 rounded px-1.5 text-[9px] transition-colors",
        disabled
          ? "text-[#6f7f9a]/30 cursor-not-allowed"
          : "text-[#6f7f9a]/60 hover:bg-[#1a1f2e] hover:text-[#ece7dc]/80",
      )}
    >
      <Icon size={13} stroke={1.5} />
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

function SigilDot({ fingerprint, size = 16 }: { fingerprint: string; size?: number }) {
  const color = sigilColor(fingerprint);
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

function sigilColor(fingerprint: string): string {
  const byte = parseInt(fingerprint.slice(0, 2), 16) || 0;
  const hue = Math.round((byte / 255) * 360);
  return `hsl(${hue}, 55%, 55%)`;
}

function reputationColor(score: number): string {
  if (score >= 0.8) return "#3dbf84";
  if (score >= 0.5) return "#d4a84b";
  if (score >= 0.25) return "#c45c5c";
  return "#6f7f9a";
}

function DetailSectionLabel({ text }: { text: string }) {
  return (
    <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-1">
      {text}
    </h4>
  );
}

function DetailRow({
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
      <span className="text-[#6f7f9a]/50 shrink-0 w-[100px]">{label}</span>
      <span className={cn("text-[#ece7dc]/70 truncate", mono && "font-mono")}>
        {value}
      </span>
    </div>
  );
}

function MiniRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between text-[9px]">
      <span className="text-[#6f7f9a]/50">{label}</span>
      <span className="text-[#ece7dc]/60 capitalize">{value}</span>
    </div>
  );
}
