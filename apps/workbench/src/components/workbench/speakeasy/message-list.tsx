import { useEffect, useRef } from "react";
import {
  IconCheck,
  IconX,
  IconLoader2,
  IconArrowUp,
  IconArrowDown,
  IconHeartbeat,
  IconShieldCheck,
  IconTarget,
  IconRobot,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SpeakeasyMember } from "@/lib/workbench/sentinel-types";
import type { ClawdstrikeBaseMessage } from "@/lib/workbench/speakeasy-bridge";
import { SigilAvatar, SIGIL_ICONS } from "./room-header";


/**
 * Display message type for the message list.
 *
 * Uses the same base fields as ClawdstrikeBaseMessage but widens the `type`
 * discriminator to include Speakeasy's built-in message types (chat, presence,
 * sentinel_request, sentinel_response, typing). The bridge layer maps incoming
 * messages onto this shape before passing to MessageList.
 */
export interface SpeakeasyDisplayMessage extends Omit<ClawdstrikeBaseMessage, "type"> {
  /** Message type — includes both Speakeasy built-in and Clawdstrike domain types. */
  type: string;
  /** Chat message content (for type "chat" or "sentinel_response"). */
  content?: string;
  /** Sentinel request prompt (for type "sentinel_request"). */
  prompt?: string;
  /** Target sentinel name/id (for type "sentinel_request"). */
  sentinel?: string;
  /** Reply-to message ID. */
  replyTo?: string;
  /** Presence status (for type "presence"). */
  status?: string;
  /** Capsule ID (for type "sentinel_response"). */
  capsuleId?: string;
  /** Capsule URI (for type "sentinel_response"). */
  capsuleUri?: string;

  /** Clawdstrike-specific message subtype (set by the bridge layer). */
  clawdstrikeType?: "intel_share" | "finding_update" | "sentinel_status" | "reputation_vote";
  /** Intel share metadata. */
  intelShare?: {
    intelType: string;
    title: string;
    confidence: number;
  };
  /** Finding update metadata. */
  findingUpdate?: {
    findingId: string;
    status: string;
    severity?: string;
  };
  /** Sentinel status metadata. */
  sentinelStatus?: {
    sentinelId: string;
    mode: string;
    status: string;
  };
  /** Reputation vote metadata. */
  reputationVote?: {
    targetFingerprint: string;
    direction: "up" | "down";
  };
}

export type VerificationStatus = "verified" | "failed" | "pending";

interface MessageListProps {
  messages: SpeakeasyDisplayMessage[];
  /** Set of message IDs currently being verified. */
  pendingVerification: Set<string>;
  /** Set of message IDs that failed verification. */
  verificationFailed: Set<string>;
  /** Current user's public key for right-aligning own messages. */
  currentUserPublicKey: string | null;
  /** Member lookup by public key for display. */
  membersByPublicKey: Map<string, SpeakeasyMember>;
  /** Callback when a finding link is clicked. */
  onFindingClick?: (findingId: string) => void;
  /** Callback when an intel link is clicked. */
  onIntelClick?: (intelId: string) => void;
}


function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

function getVerificationStatus(
  messageId: string,
  pendingVerification: Set<string>,
  verificationFailed: Set<string>,
): VerificationStatus {
  if (pendingVerification.has(messageId)) return "pending";
  if (verificationFailed.has(messageId)) return "failed";
  return "verified";
}


function VerificationBadge({ status }: { status: VerificationStatus }) {
  switch (status) {
    case "verified":
      return (
        <span className="inline-flex items-center gap-0.5 text-[9px] font-mono text-[#3dbf84]">
          <IconCheck size={10} stroke={2} />
          Verified
        </span>
      );
    case "failed":
      return (
        <span className="inline-flex items-center gap-0.5 text-[9px] font-mono text-[#c45c5c]">
          <IconX size={10} stroke={2} />
          Failed
        </span>
      );
    case "pending":
      return (
        <span className="inline-flex items-center gap-0.5 text-[9px] font-mono text-[#6f7f9a]">
          <IconLoader2 size={10} stroke={2} className="animate-spin" />
          Verifying...
        </span>
      );
  }
}


function IntelShareCard({
  intelShare,
  onIntelClick,
}: {
  intelShare: NonNullable<SpeakeasyDisplayMessage["intelShare"]>;
  onIntelClick?: (intelId: string) => void;
}) {
  const confidencePercent = Math.round(intelShare.confidence * 100);
  const confidenceColor =
    intelShare.confidence >= 0.8
      ? "#c45c5c"
      : intelShare.confidence >= 0.6
        ? "#d4784b"
        : intelShare.confidence >= 0.3
          ? "#d4a84b"
          : "#6f7f9a";

  return (
    <div className="mt-1.5 rounded-md border border-[#2d3240] bg-[#05060a]/60 px-2.5 py-2">
      <div className="flex items-center gap-1.5">
        <IconShieldCheck size={12} stroke={1.5} className="text-[#5b8def] shrink-0" />
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#5b8def]">
          {intelShare.intelType.replace("_", " ")}
        </span>
        <span
          className="ml-auto text-[9px] font-mono"
          style={{ color: confidenceColor }}
        >
          {confidencePercent}%
        </span>
      </div>
      <p className="text-xs text-[#ece7dc] mt-1 truncate">{intelShare.title}</p>
    </div>
  );
}


function FindingUpdateCard({
  findingUpdate,
  onFindingClick,
}: {
  findingUpdate: NonNullable<SpeakeasyDisplayMessage["findingUpdate"]>;
  onFindingClick?: (findingId: string) => void;
}) {
  const statusColors: Record<string, string> = {
    emerging: "#d4a84b",
    confirmed: "#d4784b",
    promoted: "#3dbf84",
    dismissed: "#6f7f9a",
    false_positive: "#6f7f9a",
  };
  const statusColor = statusColors[findingUpdate.status] ?? "#6f7f9a";

  return (
    <button
      onClick={() => onFindingClick?.(findingUpdate.findingId)}
      className="mt-1.5 w-full rounded-md border border-[#2d3240] bg-[#05060a]/60 px-2.5 py-2 text-left hover:border-[#5b8def]/30 transition-colors"
    >
      <div className="flex items-center gap-1.5">
        <IconTarget size={12} stroke={1.5} className="text-[#d4784b] shrink-0" />
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          Finding Update
        </span>
        <span
          className="ml-auto text-[9px] font-mono font-semibold uppercase"
          style={{ color: statusColor }}
        >
          {findingUpdate.status.replace("_", " ")}
        </span>
      </div>
      <div className="flex items-center gap-1.5 mt-1">
        {findingUpdate.severity && (
          <span className="text-[9px] font-mono text-[#6f7f9a]">
            {findingUpdate.severity}
          </span>
        )}
        <span className="text-[10px] font-mono text-[#5b8def] truncate">
          {findingUpdate.findingId}
        </span>
      </div>
    </button>
  );
}


function SentinelStatusIndicator({
  sentinelStatus,
}: {
  sentinelStatus: NonNullable<SpeakeasyDisplayMessage["sentinelStatus"]>;
}) {
  const statusColor =
    sentinelStatus.status === "active"
      ? "#3dbf84"
      : sentinelStatus.status === "paused"
        ? "#d4a84b"
        : "#6f7f9a";

  return (
    <div className="mt-1.5 flex items-center gap-2 rounded-md border border-[#2d3240]/60 bg-[#05060a]/40 px-2.5 py-1.5">
      <IconHeartbeat size={12} stroke={1.5} style={{ color: statusColor }} />
      <span className="text-[10px] font-mono text-[#6f7f9a]">
        {sentinelStatus.sentinelId.slice(0, 12)}
      </span>
      <span
        className="text-[9px] font-mono uppercase"
        style={{ color: statusColor }}
      >
        {sentinelStatus.status}
      </span>
      <span className="text-[9px] font-mono text-[#6f7f9a]/60 ml-auto">
        {sentinelStatus.mode}
      </span>
    </div>
  );
}


function ReputationVoteIndicator({
  reputationVote,
}: {
  reputationVote: NonNullable<SpeakeasyDisplayMessage["reputationVote"]>;
}) {
  const isUp = reputationVote.direction === "up";
  return (
    <div className="mt-1.5 inline-flex items-center gap-1.5 rounded-md border border-[#2d3240]/60 bg-[#05060a]/40 px-2.5 py-1.5">
      {isUp ? (
        <IconArrowUp size={12} stroke={2} className="text-[#3dbf84]" />
      ) : (
        <IconArrowDown size={12} stroke={2} className="text-[#c45c5c]" />
      )}
      <span className="text-[10px] font-mono text-[#6f7f9a]">
        {reputationVote.targetFingerprint.slice(0, 8)}
      </span>
      <span
        className={cn(
          "text-[9px] font-mono font-semibold",
          isUp ? "text-[#3dbf84]" : "text-[#c45c5c]",
        )}
      >
        {isUp ? "+1" : "-1"}
      </span>
    </div>
  );
}


function SenderInfo({
  message,
  member,
}: {
  message: SpeakeasyDisplayMessage;
  member: SpeakeasyMember | undefined;
}) {
  if (member) {
    return (
      <div className="flex items-center gap-1.5">
        <SigilAvatar member={member} size={18} />
        <span className="text-xs font-medium text-[#ece7dc]">
          {member.displayName}
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/60">
          {member.fingerprint.slice(0, 8)}
        </span>
      </div>
    );
  }

    return (
    <div className="flex items-center gap-1.5">
      <div className="rounded-full flex items-center justify-center bg-[#131721] border border-[#2d3240] text-[#6f7f9a]"
        style={{ width: 18, height: 18, fontSize: 10 }}
      >
        ?
      </div>
      <span className="text-[9px] font-mono text-[#6f7f9a]">
        {message.sender.slice(0, 16)}...
      </span>
    </div>
  );
}


function MessageBubble({
  message,
  isOwnMessage,
  verificationStatus,
  member,
  onFindingClick,
  onIntelClick,
}: {
  message: SpeakeasyDisplayMessage;
  isOwnMessage: boolean;
  verificationStatus: VerificationStatus;
  member: SpeakeasyMember | undefined;
  onFindingClick?: (findingId: string) => void;
  onIntelClick?: (intelId: string) => void;
}) {
  const isSentinelRequest = message.type === "sentinel_request";
  const isSentinelResponse = message.type === "sentinel_response";
  const isSystemMessage = message.type === "presence";

  // System messages (presence) render as centered thin text
  if (isSystemMessage) {
    return (
      <div className="flex justify-center py-1">
        <span className="text-[9px] font-mono text-[#6f7f9a]/50 italic">
          {message.status === "online" ? "joined" : "left"} the room
          <span className="mx-1">&middot;</span>
          {formatRelativeTime(message.timestamp)}
        </span>
      </div>
    );
  }

  // Skip typing indicators in the message list
  if (message.type === "typing") return null;

  return (
    <div
      className={cn(
        "flex flex-col gap-0.5 max-w-[85%]",
        isOwnMessage ? "ml-auto items-end" : "mr-auto items-start",
      )}
    >
      {/* Sender info (not shown for own messages unless sentinel request/response) */}
      {(!isOwnMessage || isSentinelRequest || isSentinelResponse) && (
        <SenderInfo message={message} member={member} />
      )}

      {/* Message card */}
      <div
        className={cn(
          "rounded-lg px-3 py-2 text-xs leading-relaxed",
          isSentinelRequest
            ? "border border-[#d4a84b]/30 bg-[#d4a84b]/5"
            : isSentinelResponse
              ? "border border-[#3dbf84]/30 bg-[#3dbf84]/5"
              : isOwnMessage
                ? "bg-[#131721] border border-[#2d3240]"
                : "bg-[#0b0d13] border border-[#2d3240]/60",
        )}
      >
        {/* Sentinel request header */}
        {isSentinelRequest && (
          <div className="flex items-center gap-1.5 mb-1.5 pb-1.5 border-b border-[#d4a84b]/20">
            <IconRobot size={12} stroke={1.5} className="text-[#d4a84b]" />
            <span className="text-[9px] font-mono font-semibold uppercase tracking-wider text-[#d4a84b]">
              Sentinel Request
            </span>
            <span className="text-[9px] font-mono text-[#6f7f9a] ml-auto">
              {message.sentinel}
            </span>
          </div>
        )}

        {/* Sentinel response header */}
        {isSentinelResponse && (
          <div className="flex items-center gap-1.5 mb-1.5 pb-1.5 border-b border-[#3dbf84]/20">
            <IconRobot size={12} stroke={1.5} className="text-[#3dbf84]" />
            <span className="text-[9px] font-mono font-semibold uppercase tracking-wider text-[#3dbf84]">
              Sentinel Response
            </span>
          </div>
        )}

        {/* Message content */}
        <p className="text-[#ece7dc] whitespace-pre-wrap break-words">
          {isSentinelRequest
            ? message.prompt
            : message.content}
        </p>

        {/* Clawdstrike-specific message cards */}
        {message.clawdstrikeType === "intel_share" && message.intelShare && (
          <IntelShareCard intelShare={message.intelShare} onIntelClick={onIntelClick} />
        )}
        {message.clawdstrikeType === "finding_update" && message.findingUpdate && (
          <FindingUpdateCard findingUpdate={message.findingUpdate} onFindingClick={onFindingClick} />
        )}
        {message.clawdstrikeType === "sentinel_status" && message.sentinelStatus && (
          <SentinelStatusIndicator sentinelStatus={message.sentinelStatus} />
        )}
        {message.clawdstrikeType === "reputation_vote" && message.reputationVote && (
          <ReputationVoteIndicator reputationVote={message.reputationVote} />
        )}
      </div>

      {/* Timestamp + verification row */}
      <div className="flex items-center gap-2 px-1">
        <span className="text-[9px] font-mono text-[#6f7f9a]/50">
          {formatRelativeTime(message.timestamp)}
        </span>
        <VerificationBadge status={verificationStatus} />
      </div>
    </div>
  );
}


export function MessageList({
  messages,
  pendingVerification,
  verificationFailed,
  currentUserPublicKey,
  membersByPublicKey,
  onFindingClick,
  onIntelClick,
}: MessageListProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length]);

  if (messages.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center px-4">
        <div className="text-center">
          <div className="text-[#6f7f9a]/30 text-3xl mb-2">
            {SIGIL_ICONS.key}
          </div>
          <p className="text-xs text-[#6f7f9a]/50 font-mono">
            No messages yet.
          </p>
          <p className="text-[10px] text-[#6f7f9a]/30 font-mono mt-1">
            All messages are Ed25519-signed and verified.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={scrollRef}
      className="flex-1 overflow-y-auto px-3 py-3 space-y-3"
    >
      {messages.map((message) => {
        const isOwnMessage = currentUserPublicKey !== null && message.sender === currentUserPublicKey;
        const verificationStatus = getVerificationStatus(
          message.id,
          pendingVerification,
          verificationFailed,
        );
        const member = membersByPublicKey.get(message.sender);

        return (
          <MessageBubble
            key={message.id}
            message={message}
            isOwnMessage={isOwnMessage}
            verificationStatus={verificationStatus}
            member={member}
            onFindingClick={onFindingClick}
            onIntelClick={onIntelClick}
          />
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
