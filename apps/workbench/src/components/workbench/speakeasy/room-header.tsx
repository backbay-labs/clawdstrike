import { useState, useCallback, useMemo } from "react";
import {
  IconX,
  IconMinus,
  IconSearch,
  IconTarget,
  IconAlertTriangle,
  IconSchool,
  IconMessage,
  IconChevronDown,
  IconChevronUp,
  IconLink,
  IconLock,
  IconShieldLock,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  ClawdstrikeSpeakeasy,
  SpeakeasyPurpose,
  SpeakeasyClassification,
  SpeakeasyMember,
} from "@/lib/workbench/sentinel-types";
import { deriveSigilColor } from "@/lib/workbench/sentinel-manager";


const PURPOSE_CONFIG: Record<SpeakeasyPurpose, { icon: typeof IconSearch; label: string; color: string }> = {
  finding: { icon: IconSearch, label: "Finding", color: "#c45c5c" },
  campaign: { icon: IconTarget, label: "Campaign", color: "#d4784b" },
  incident: { icon: IconAlertTriangle, label: "Incident", color: "#c45c5c" },
  coordination: { icon: IconMessage, label: "Coordination", color: "#5b8def" },
  mentoring: { icon: IconSchool, label: "Mentoring", color: "#8b7355" },
};

const CLASSIFICATION_CONFIG: Record<SpeakeasyClassification, { label: string; color: string; bg: string; border: string } | null> = {
  routine: null,
  sensitive: { label: "SENSITIVE", color: "#d4a84b", bg: "rgba(212,168,75,0.1)", border: "rgba(212,168,75,0.3)" },
  restricted: { label: "RESTRICTED", color: "#c45c5c", bg: "rgba(196,92,92,0.15)", border: "rgba(196,92,92,0.4)" },
};

const SIGIL_ICONS: Record<string, string> = {
  diamond: "\u25C7",
  eye: "\u25C9",
  wave: "\u223F",
  crown: "\u2655",
  spiral: "\u0040",
  key: "\u2767",
  star: "\u2726",
  moon: "\u263E",
};


interface RoomHeaderProps {
  room: ClawdstrikeSpeakeasy;
  onClose: () => void;
  onMinimize?: () => void;
  onAttachedClick?: (entityId: string) => void;
}


function SigilAvatar({
  member,
  size = 20,
}: {
  member: SpeakeasyMember;
  size?: number;
}) {
  const color = deriveSigilColor(member.fingerprint);
  const icon = SIGIL_ICONS[member.sigil] ?? "\u25CF";

  return (
    <div
      className="rounded-full flex items-center justify-center shrink-0"
      style={{
        width: size,
        height: size,
        backgroundColor: `${color}20`,
        border: `1px solid ${color}60`,
        color,
        fontSize: size * 0.55,
        lineHeight: 1,
      }}
      title={`${member.displayName} (${member.fingerprint.slice(0, 8)})`}
    >
      {icon}
    </div>
  );
}


export function RoomHeader({ room, onClose, onMinimize, onAttachedClick }: RoomHeaderProps) {
  const [memberListOpen, setMemberListOpen] = useState(false);

  const toggleMemberList = useCallback(() => {
    setMemberListOpen((prev) => !prev);
  }, []);

  const purposeCfg = PURPOSE_CONFIG[room.purpose];
  const classificationCfg = CLASSIFICATION_CONFIG[room.classification];

  const visibleMembers = useMemo(() => room.members.slice(0, 5), [room.members]);
  const overflowCount = Math.max(0, room.members.length - 5);

  const PurposeIcon = purposeCfg.icon;

  return (
    <div className="shrink-0 border-b border-[#2d3240]">
      {/* Main header row */}
      <div className="flex items-start gap-2.5 px-3 py-2.5">
        {/* Purpose icon */}
        <div
          className="mt-0.5 shrink-0 rounded-md flex items-center justify-center"
          style={{
            width: 28,
            height: 28,
            backgroundColor: `${purposeCfg.color}15`,
            color: purposeCfg.color,
          }}
        >
          <PurposeIcon size={16} stroke={1.5} />
        </div>

        {/* Name + meta */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-sm font-semibold text-[#ece7dc] truncate">
              #{room.name}
            </span>
            {classificationCfg && (
              <span
                className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono font-semibold uppercase tracking-wider rounded"
                style={{
                  color: classificationCfg.color,
                  backgroundColor: classificationCfg.bg,
                  border: `1px solid ${classificationCfg.border}`,
                }}
              >
                {room.classification === "restricted" ? (
                  <IconShieldLock size={9} stroke={2} />
                ) : (
                  <IconLock size={9} stroke={2} />
                )}
                {classificationCfg.label}
              </span>
            )}
          </div>

          {/* Purpose label */}
          <div className="flex items-center gap-1.5 mt-0.5">
            <span
              className="text-[10px] font-mono"
              style={{ color: purposeCfg.color }}
            >
              {purposeCfg.label}
            </span>

            {/* Attached entity link */}
            {room.attachedTo && (
              <button
                onClick={() => onAttachedClick?.(room.attachedTo!)}
                className="inline-flex items-center gap-0.5 text-[10px] font-mono text-[#5b8def] hover:text-[#7ba3f3] transition-colors truncate max-w-[180px]"
              >
                <IconLink size={10} stroke={1.5} />
                {room.attachedTo}
              </button>
            )}
          </div>
        </div>

        {/* Window controls */}
        <div className="flex items-center gap-0.5 shrink-0">
          {onMinimize && (
            <button
              onClick={onMinimize}
              className="p-1 rounded text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721] transition-colors"
              title="Minimize"
            >
              <IconMinus size={14} stroke={1.5} />
            </button>
          )}
          <button
            onClick={onClose}
            className="p-1 rounded text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
            title="Close"
          >
            <IconX size={14} stroke={1.5} />
          </button>
        </div>
      </div>

      {/* Members bar */}
      <button
        onClick={toggleMemberList}
        className="w-full flex items-center gap-1.5 px-3 py-1.5 border-t border-[#2d3240]/60 hover:bg-[#131721]/50 transition-colors"
      >
        <div className="flex items-center -space-x-1.5">
          {visibleMembers.map((member) => (
            <SigilAvatar key={member.fingerprint} member={member} size={20} />
          ))}
          {overflowCount > 0 && (
            <div className="rounded-full flex items-center justify-center text-[9px] font-mono text-[#6f7f9a] bg-[#131721] border border-[#2d3240]"
              style={{ width: 20, height: 20 }}
            >
              +{overflowCount}
            </div>
          )}
        </div>
        <span className="text-[10px] font-mono text-[#6f7f9a] ml-1">
          {room.members.length} member{room.members.length !== 1 ? "s" : ""}
        </span>
        <div className="ml-auto">
          {memberListOpen ? (
            <IconChevronUp size={12} stroke={1.5} className="text-[#6f7f9a]" />
          ) : (
            <IconChevronDown size={12} stroke={1.5} className="text-[#6f7f9a]" />
          )}
        </div>
      </button>

      {/* Expandable member list */}
      {memberListOpen && (
        <div className="border-t border-[#2d3240]/60 bg-[#05060a]/50 px-3 py-2 space-y-1.5 max-h-48 overflow-y-auto">
          {room.members.map((member) => (
            <div
              key={member.fingerprint}
              className="flex items-center gap-2 py-1"
            >
              <SigilAvatar member={member} size={22} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-xs text-[#ece7dc] truncate">
                    {member.displayName}
                  </span>
                  <span
                    className={cn(
                      "text-[9px] font-mono px-1 py-0.5 rounded",
                      member.type === "sentinel"
                        ? "text-[#5b8def] bg-[#5b8def]/10"
                        : "text-[#6f7f9a] bg-[#6f7f9a]/10",
                    )}
                  >
                    {member.type}
                  </span>
                  <span
                    className={cn(
                      "text-[9px] font-mono px-1 py-0.5 rounded",
                      member.role === "moderator"
                        ? "text-[#d4a84b] bg-[#d4a84b]/10"
                        : member.role === "participant"
                          ? "text-[#6f7f9a] bg-[#6f7f9a]/10"
                          : "text-[#6f7f9a]/50 bg-[#6f7f9a]/5",
                    )}
                  >
                    {member.role}
                  </span>
                </div>
                <div className="text-[9px] font-mono text-[#6f7f9a]/60 mt-0.5">
                  {member.fingerprint.slice(0, 4)}-{member.fingerprint.slice(4, 8)}-{member.fingerprint.slice(8, 12)}-{member.fingerprint.slice(12, 16)}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export { SigilAvatar, SIGIL_ICONS, PURPOSE_CONFIG, CLASSIFICATION_CONFIG };
