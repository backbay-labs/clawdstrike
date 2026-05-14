import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import {
  IconSend,
  IconRobot,
  IconLink,
  IconX,
  IconLock,
  IconShieldLock,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  ClawdstrikeSpeakeasy,
  SpeakeasyMember,
  SpeakeasyClassification,
} from "@/lib/workbench/sentinel-types";
import { RoomHeader, CLASSIFICATION_CONFIG } from "./room-header";
import { MessageList, type SpeakeasyDisplayMessage } from "./message-list";
import { usePresenceStore } from "@/features/presence/stores/presence-store";
import { usePaneStore, getActivePane } from "@/features/panes/pane-store";
import { getPaneActiveView } from "@/features/panes/pane-tree";
import { toPresencePath } from "@/features/presence/presence-paths";


interface SpeakeasyPanelProps {
  /** The room to display, or null when no room is open. */
  room: ClawdstrikeSpeakeasy | null;
  /** Whether the panel is open. */
  isOpen: boolean;
  /** Close the panel. */
  onClose: () => void;
  /** Messages to display (provided by the bridge layer, not fetched here). */
  messages?: SpeakeasyDisplayMessage[];
  /** Message IDs pending signature verification. */
  pendingVerification?: Set<string>;
  /** Message IDs that failed signature verification. */
  verificationFailed?: Set<string>;
  /** Current user's Ed25519 public key (hex). */
  currentUserPublicKey?: string | null;
  /** Callback to send a chat message. Returns when the signed message has been published. */
  onSendMessage?: (content: string) => Promise<void>;
  /** Callback to send a sentinel request. */
  onSendSentinelRequest?: (sentinelFingerprint: string, prompt: string) => Promise<void>;
  /** Callback when a finding link is clicked. */
  onFindingClick?: (findingId: string) => void;
  /** Callback when an intel link is clicked. */
  onIntelClick?: (intelId: string) => void;
  /** Callback when the attached entity link is clicked. */
  onAttachedClick?: (entityId: string) => void;
  /**
   * When true, renders as an inline flex-column child (for embedding in a
   * sidebar container) instead of a fixed overlay with backdrop.
   */
  inline?: boolean;
}


function ClassificationFooter({ classification }: { classification: SpeakeasyClassification }) {
  const cfg = CLASSIFICATION_CONFIG[classification];
  if (!cfg) {
    return (
      <div className="shrink-0 flex items-center justify-center px-3 py-1.5 border-t border-[#2d3240]/60">
        <span className="text-[9px] font-mono text-[#6f7f9a]/30 uppercase tracking-wider">
          Routine
        </span>
      </div>
    );
  }

  return (
    <div
      className="shrink-0 flex items-center justify-center gap-1.5 px-3 py-1.5 border-t"
      style={{ borderColor: cfg.border, backgroundColor: cfg.bg }}
    >
      {classification === "restricted" ? (
        <IconShieldLock size={10} stroke={2} style={{ color: cfg.color }} />
      ) : (
        <IconLock size={10} stroke={2} style={{ color: cfg.color }} />
      )}
      <span
        className="text-[9px] font-mono font-semibold uppercase tracking-wider"
        style={{ color: cfg.color }}
      >
        {cfg.label}
      </span>
    </div>
  );
}


interface SentinelRequestFormProps {
  sentinels: SpeakeasyMember[];
  onSubmit: (sentinelFingerprint: string, prompt: string) => void;
  onCancel: () => void;
}

function SentinelRequestForm({ sentinels, onSubmit, onCancel }: SentinelRequestFormProps) {
  const [selectedSentinel, setSelectedSentinel] = useState(
    sentinels.length > 0 ? sentinels[0].fingerprint : "",
  );
  const [prompt, setPrompt] = useState("");
  const promptRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    promptRef.current?.focus();
  }, []);

  const handleSubmit = useCallback(() => {
    if (!selectedSentinel || !prompt.trim()) return;
    onSubmit(selectedSentinel, prompt.trim());
    setPrompt("");
  }, [selectedSentinel, prompt, onSubmit]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        handleSubmit();
      }
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel();
      }
    },
    [handleSubmit, onCancel],
  );

  if (sentinels.length === 0) {
    return (
      <div className="px-3 py-2 border-t border-[#d4a84b]/20 bg-[#d4a84b]/5">
        <p className="text-[10px] font-mono text-[#d4a84b]/60">
          No sentinels in this room.
        </p>
        <button
          onClick={onCancel}
          className="mt-1 text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc]"
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <div className="border-t border-[#d4a84b]/20 bg-[#d4a84b]/5 px-3 py-2 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-[#d4a84b]">
          Sentinel Request
        </span>
        <button
          onClick={onCancel}
          className="p-0.5 rounded text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
        >
          <IconX size={12} stroke={1.5} />
        </button>
      </div>

      {/* Sentinel selector */}
      <select
        value={selectedSentinel}
        onChange={(e) => setSelectedSentinel(e.target.value)}
        className="w-full h-7 rounded-md border border-[#2d3240] bg-[#131721] px-2 text-[10px] font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b]/50"
      >
        {sentinels.map((s) => (
          <option key={s.fingerprint} value={s.fingerprint}>
            {s.displayName} ({s.fingerprint.slice(0, 8)})
          </option>
        ))}
      </select>

      {/* Prompt input */}
      <textarea
        ref={promptRef}
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="What should the sentinel investigate?"
        rows={2}
        className="w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-1.5 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/40 outline-none focus:border-[#d4a84b]/50 resize-none"
      />

      {/* Submit */}
      <div className="flex items-center justify-between">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          Cmd+Enter to send
        </span>
        <button
          onClick={handleSubmit}
          disabled={!prompt.trim() || !selectedSentinel}
          className={cn(
            "px-3 py-1 text-[10px] font-medium rounded-md border transition-colors",
            prompt.trim() && selectedSentinel
              ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10 hover:bg-[#d4a84b]/20"
              : "text-[#6f7f9a]/30 border-[#2d3240]/50 bg-transparent cursor-not-allowed",
          )}
        >
          Send Request
        </button>
      </div>
    </div>
  );
}


export function SpeakeasyPanel({
  room,
  isOpen,
  onClose,
  messages = [],
  pendingVerification = new Set(),
  verificationFailed = new Set(),
  currentUserPublicKey = null,
  onSendMessage,
  onSendSentinelRequest,
  onFindingClick,
  onIntelClick,
  onAttachedClick,
  inline = false,
}: SpeakeasyPanelProps) {
  const [composeText, setComposeText] = useState("");
  const [sending, setSending] = useState(false);
  const [showSentinelForm, setShowSentinelForm] = useState(false);
  const composeRef = useRef<HTMLTextAreaElement>(null);
  const backdropRef = useRef<HTMLDivElement>(null);

  // Presence context: how many analysts are viewing the currently active file
  const paneRoot = usePaneStore((s) => s.root);
  const activePaneId = usePaneStore((s) => s.activePaneId);
  const activeFileRoute = useMemo(() => {
    const pane = getActivePane(paneRoot, activePaneId);
    const view = pane ? getPaneActiveView(pane) : null;
    const rawPath = view?.route?.startsWith("/file/") ? view.route.slice("/file/".length) : null;
    return rawPath ? toPresencePath(rawPath) : null;
  }, [paneRoot, activePaneId]);

  const fileViewerCount = usePresenceStore((s) => {
    if (!activeFileRoute) return 0;
    const viewers = s.viewersByFile.get(activeFileRoute);
    if (!viewers) return 0;
    // Exclude local analyst
    const localId = s.localAnalystId;
    let count = viewers.size;
    if (localId && viewers.has(localId)) count--;
    return count;
  });

  // Build member lookup map
  const membersByPublicKey = useMemo(() => {
    const map = new Map<string, SpeakeasyMember>();
    if (room) {
      // Note: SpeakeasyMember uses fingerprint, not publicKey. The bridge layer
      // should populate this map using the full public key from identity resolution.
      // For now, we pass it through as-is.
      for (const member of room.members) {
        // The map is keyed by public key, but we only have fingerprints on SpeakeasyMember.
        // The bridge layer is responsible for expanding fingerprints to public keys.
        // This is a placeholder mapping using fingerprint as key.
        map.set(member.fingerprint, member);
      }
    }
    return map;
  }, [room]);

  // Filter sentinel members for the request form
  const sentinelMembers = useMemo(() => {
    if (!room) return [];
    return room.members.filter((m) => m.type === "sentinel");
  }, [room]);

  // Attached-to entity display
  const attachedDisplay = useMemo(() => {
    if (!room?.attachedTo) return null;
    const id = room.attachedTo;
    if (id.startsWith("fnd_")) return { label: "Finding", id };
    if (id.startsWith("int_")) return { label: "Intel", id };
    if (id.startsWith("sen_")) return { label: "Sentinel", id };
    return { label: "Entity", id };
  }, [room]);

  // Send a chat message
  const handleSend = useCallback(async () => {
    if (!composeText.trim() || !onSendMessage || sending) return;
    const text = composeText.trim();
    setComposeText("");
    setSending(true);
    try {
      await onSendMessage(text);
    } catch (err) {
      // Restore text on failure
      setComposeText(text);
      console.error("[speakeasy-panel] send failed:", err);
    } finally {
      setSending(false);
    }
  }, [composeText, onSendMessage, sending]);

  // Keyboard handler for compose area
  const handleComposeKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend],
  );

  // Send sentinel request
  const handleSentinelRequest = useCallback(
    async (sentinelFingerprint: string, prompt: string) => {
      if (!onSendSentinelRequest) return;
      setShowSentinelForm(false);
      try {
        await onSendSentinelRequest(sentinelFingerprint, prompt);
      } catch (err) {
        console.error("[speakeasy-panel] sentinel request failed:", err);
      }
    },
    [onSendSentinelRequest],
  );

  // Click-outside-to-close via backdrop
  const handleBackdropClick = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === backdropRef.current) {
        onClose();
      }
    },
    [onClose],
  );

  // Focus compose input when panel opens
  useEffect(() => {
    if (isOpen && room && !showSentinelForm) {
      // Small delay to let animation start
      const timer = setTimeout(() => composeRef.current?.focus(), 200);
      return () => clearTimeout(timer);
    }
  }, [isOpen, room, showSentinelForm]);

  // Reset state when room changes
  useEffect(() => {
    setComposeText("");
    setShowSentinelForm(false);
    setSending(false);
  }, [room?.id]);

  // Don't render at all if not open
  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop (click to close) -- hidden in inline mode */}
      {!inline && (
        <div
          ref={backdropRef}
          onClick={handleBackdropClick}
          className={cn(
            "fixed inset-0 z-40 transition-opacity duration-200",
            "bg-black/20 opacity-100",
          )}
        />
      )}

      {/* Panel */}
      <div
        className={cn(
          inline
            ? "flex-1 min-h-0 flex flex-col bg-zinc-950"
            : cn(
                "fixed top-0 right-0 bottom-0 z-50 w-96 flex flex-col",
                "bg-zinc-950 border-l border-[#2d3240] shadow-2xl shadow-black/50",
                "transition-transform duration-300 ease-out",
                "translate-x-0",
              ),
        )}
      >
        {!room ? (
          // No room selected state
          <div className="flex-1 flex flex-col items-center justify-center px-6">
            <p className="text-sm text-[#6f7f9a]/50 font-mono text-center">
              No room selected.
            </p>
            <p className="text-xs text-[#6f7f9a]/30 font-mono text-center mt-1">
              Open a room from a finding, swarm, or the overview page.
            </p>
            <button
              onClick={onClose}
              className="mt-4 px-3 py-1.5 text-xs font-mono text-[#6f7f9a] border border-[#2d3240] rounded-md hover:text-[#ece7dc] hover:border-[#d4a84b]/40 transition-colors"
            >
              Close Panel
            </button>
          </div>
        ) : (
          <>
            {/* Room header */}
            <RoomHeader
              room={room}
              onClose={onClose}
              onAttachedClick={onAttachedClick}
            />

            {/* Attached entity indicator */}
            {attachedDisplay && (
              <button
                onClick={() => onAttachedClick?.(attachedDisplay.id)}
                className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 border-b border-[#2d3240]/60 bg-[#05060a]/50 hover:bg-[#131721]/30 transition-colors"
              >
                <IconLink size={11} stroke={1.5} className="text-[#5b8def] shrink-0" />
                <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                  {attachedDisplay.label}
                </span>
                <span className="text-[10px] font-mono text-[#5b8def] truncate">
                  {attachedDisplay.id}
                </span>
              </button>
            )}

            {/* Message list */}
            <MessageList
              messages={messages}
              pendingVerification={pendingVerification}
              verificationFailed={verificationFailed}
              currentUserPublicKey={currentUserPublicKey}
              membersByPublicKey={membersByPublicKey}
              onFindingClick={onFindingClick}
              onIntelClick={onIntelClick}
            />

            {/* Sentinel request form (replaces compose when active) */}
            {showSentinelForm ? (
              <SentinelRequestForm
                sentinels={sentinelMembers}
                onSubmit={handleSentinelRequest}
                onCancel={() => setShowSentinelForm(false)}
              />
            ) : (
              /* Compose area */
              <div className="shrink-0 border-t border-[#2d3240] bg-zinc-950 px-3 py-2.5">
                {fileViewerCount > 0 && (
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <span className="inline-block w-[5px] h-[5px] rounded-full bg-[#3dbf84]/60" />
                    <span className="text-[10px] font-mono text-[#6f7f9a]/50">
                      {fileViewerCount} analyst{fileViewerCount !== 1 ? "s" : ""} viewing this file
                    </span>
                  </div>
                )}
                <div className="flex items-end gap-2">
                  <textarea
                    ref={composeRef}
                    value={composeText}
                    onChange={(e) => setComposeText(e.target.value)}
                    onKeyDown={handleComposeKeyDown}
                    placeholder="Type a message..."
                    rows={1}
                    className={cn(
                      "flex-1 rounded-md border border-[#2d3240] bg-[#131721] px-3 py-2",
                      "text-xs text-[#ece7dc] placeholder:text-[#6f7f9a]/40",
                      "outline-none focus:border-[#d4a84b]/50 transition-colors resize-none",
                      "min-h-[36px] max-h-[96px]",
                    )}
                    style={{
                      height: "auto",
                      overflow: "hidden",
                    }}
                    onInput={(e) => {
                      const target = e.target as HTMLTextAreaElement;
                      target.style.height = "auto";
                      target.style.height = `${Math.min(target.scrollHeight, 96)}px`;
                    }}
                  />
                  <button
                    onClick={handleSend}
                    disabled={!composeText.trim() || sending}
                    className={cn(
                      "shrink-0 p-2 rounded-md border transition-colors",
                      composeText.trim() && !sending
                        ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10 hover:bg-[#d4a84b]/20"
                        : "text-[#6f7f9a]/30 border-[#2d3240]/50 bg-transparent cursor-not-allowed",
                    )}
                    title="Send (Cmd+Enter)"
                  >
                    <IconSend size={14} stroke={1.5} />
                  </button>
                </div>

                {/* Action row */}
                <div className="flex items-center gap-2 mt-1.5">
                  {onSendSentinelRequest && sentinelMembers.length > 0 && (
                    <button
                      onClick={() => setShowSentinelForm(true)}
                      className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-[#d4a84b]/70 hover:text-[#d4a84b] rounded border border-transparent hover:border-[#d4a84b]/20 transition-colors"
                    >
                      <IconRobot size={11} stroke={1.5} />
                      Ask Sentinel
                    </button>
                  )}
                  <span className="ml-auto text-[9px] font-mono text-[#6f7f9a]/30">
                    Cmd+Enter to send
                  </span>
                </div>
              </div>
            )}

            {/* Classification footer */}
            <ClassificationFooter classification={room.classification} />
          </>
        )}
      </div>
    </>
  );
}
