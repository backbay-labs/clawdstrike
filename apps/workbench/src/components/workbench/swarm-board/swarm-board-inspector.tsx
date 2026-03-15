/**
 * SwarmBoardInspector — right-side detail drawer for the selected node.
 *
 * Dense monospace layout. Metrics as inline text, not cards.
 * Action hierarchy: one primary button, rest as text links.
 */

import { useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  IconX,
  IconTerminal2,
  IconCertificate,
  IconGitCommit,
  IconFile,
  IconNote,
  IconSubtask,
  IconCheck,
  IconAlertTriangle,
  IconShieldOff,
  IconFileCode,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/lib/workbench/swarm-board-store";
import type { SwarmBoardNodeData, SwarmNodeType } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Constants — restrained palette matching node components
// ---------------------------------------------------------------------------

const INSPECTOR_WIDTH = 340;

const NODE_TYPE_META: Record<
  SwarmNodeType,
  { icon: typeof IconTerminal2; label: string; color: string }
> = {
  agentSession: { icon: IconTerminal2, label: "session", color: "#c49a3c" },
  terminalTask: { icon: IconSubtask, label: "task", color: "#5580cc" },
  artifact: { icon: IconFile, label: "artifact", color: "#38a876" },
  diff: { icon: IconGitCommit, label: "diff", color: "#7c5cbf" },
  note: { icon: IconNote, label: "note", color: "#a08a60" },
  receipt: { icon: IconCertificate, label: "receipt", color: "#7c5cbf" },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SwarmBoardInspector() {
  const { state, selectNode, selectedNode } = useSwarmBoard();
  const open = state.inspectorOpen && selectedNode != null;

  const handleClose = useCallback(() => {
    selectNode(null);
  }, [selectNode]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, handleClose]);

  return (
    <AnimatePresence>
      {open && selectedNode && (
        <motion.aside
          initial={{ x: INSPECTOR_WIDTH, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: INSPECTOR_WIDTH, opacity: 0 }}
          transition={{ type: "spring", damping: 30, stiffness: 280 }}
          className="fixed top-0 right-0 h-full z-50 flex flex-col border-l border-[#14181f]"
          style={{ backgroundColor: "#08090e", width: INSPECTOR_WIDTH }}
          aria-label="Node inspector"
          role="complementary"
        >
          <InspectorContent
            data={selectedNode.data as SwarmBoardNodeData}
            onClose={handleClose}
          />
        </motion.aside>
      )}
    </AnimatePresence>
  );
}

// ---------------------------------------------------------------------------
// Inspector content
// ---------------------------------------------------------------------------

function InspectorContent({
  data,
  onClose,
}: {
  data: SwarmBoardNodeData;
  onClose: () => void;
}) {
  const nodeType = data.nodeType ?? "agentSession";
  const meta = NODE_TYPE_META[nodeType];
  const TypeIcon = meta.icon;

  return (
    <>
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#0e1018] shrink-0">
        <TypeIcon size={12} stroke={1.5} style={{ color: meta.color }} className="shrink-0" />
        <div className="flex-1 min-w-0">
          <span className="text-[12px] font-mono font-medium text-[#ece7dc] truncate block tracking-tight">
            {data.title}
          </span>
        </div>
        <span
          className="text-[7px] font-mono text-[#2a2f3a] uppercase mr-1"
          style={{ letterSpacing: '0.14em' }}
        >
          {meta.label}
        </span>
        <button
          onClick={onClose}
          className="shrink-0 p-0.5 text-[#2a2f3a] hover:text-[#5c6a80] transition-colors"
          aria-label="Close inspector"
        >
          <IconX size={13} stroke={1.5} />
        </button>
      </div>

      {/* Body (scrollable) */}
      <div className="flex-1 overflow-y-auto px-4 py-3 flex flex-col gap-4">
        {nodeType === "agentSession" && <AgentSessionDetail data={data} />}
        {nodeType === "terminalTask" && <TerminalTaskDetail data={data} />}
        {nodeType === "receipt" && <ReceiptDetail data={data} />}
        {nodeType === "diff" && <DiffDetail data={data} />}
        {nodeType === "artifact" && <ArtifactDetail data={data} />}
        {nodeType === "note" && <NoteDetail data={data} />}
      </div>

      {/* Footer actions — hierarchy: one primary, rest as text links */}
      <InspectorFooter nodeType={nodeType} />
    </>
  );
}

// ---------------------------------------------------------------------------
// Footer with action hierarchy
// ---------------------------------------------------------------------------

function InspectorFooter({ nodeType }: { nodeType: SwarmNodeType }) {
  switch (nodeType) {
    case "agentSession":
      return (
        <div className="flex items-center gap-3 px-4 py-2.5 border-t border-[#0e1018] shrink-0">
          <button
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-[9px] font-mono font-semibold bg-[#c49a3c] text-[#050609] hover:bg-[#d4aa50] transition-colors"
            aria-label="Open Terminal"
          >
            <IconTerminal2 size={10} stroke={1.5} />
            Terminal
          </button>
          <TextAction label="Receipts" />
          <TextAction label="Diff" />
        </div>
      );
    case "receipt":
      return (
        <div className="flex items-center gap-3 px-4 py-2.5 border-t border-[#0e1018] shrink-0">
          <button
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-[9px] font-mono font-semibold bg-[#7c5cbf] text-[#050609] hover:bg-[#8e6ed0] transition-colors"
            aria-label="Verify Signature"
          >
            <IconCertificate size={10} stroke={1.5} />
            Verify
          </button>
          <TextAction label="Full Receipt" />
        </div>
      );
    case "diff":
      return (
        <div className="flex items-center gap-3 px-4 py-2.5 border-t border-[#0e1018] shrink-0">
          <TextAction label="Open Diff View" />
        </div>
      );
    case "artifact":
      return (
        <div className="flex items-center gap-3 px-4 py-2.5 border-t border-[#0e1018] shrink-0">
          <TextAction label="Open File" />
        </div>
      );
    default:
      return null;
  }
}

function TextAction({ label }: { label: string }) {
  return (
    <button
      className="text-[9px] font-mono text-[#4a5568] hover:text-[#ece7dc] transition-colors"
      aria-label={label}
    >
      {label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Sections per node type
// ---------------------------------------------------------------------------

function AgentSessionDetail({ data }: { data: SwarmBoardNodeData }) {
  const files = data.changedFilesCount ?? 0;
  const receipts = data.receiptCount ?? 0;
  const blocked = data.blockedActionCount ?? 0;
  const events = data.toolBoundaryEvents;
  const confidence = data.confidence;

  return (
    <>
      {/* Dense inline metrics — single monospace line, dot-separated */}
      <div
        className="text-[9px] font-mono text-[#4a5568] leading-relaxed"
        style={{ fontVariantNumeric: 'tabular-nums' }}
      >
        <span className={files > 0 ? "text-[#5580cc]" : ""}>{files} files</span>
        <Dot />
        <span className={receipts > 0 ? "text-[#7c5cbf]" : ""}>{receipts} receipts</span>
        {blocked > 0 && (
          <>
            <Dot />
            <span className="text-[#b85450]">{blocked} blocked</span>
          </>
        )}
        {events != null && (
          <>
            <Dot />
            <span>{events} events</span>
          </>
        )}
        {confidence != null && (
          <>
            <Dot />
            <span className={confidence >= 80 ? "text-[#38a876]" : confidence >= 50 ? "text-[#c49a3c]" : "text-[#b85450]"}>
              {confidence}% conf
            </span>
          </>
        )}
      </div>

      {/* Session info */}
      <Section title="session">
        <InfoRow label="branch" value={data.branch} />
        <InfoRow label="worktree" value={data.worktreePath} />
        <InfoRow label="model" value={data.agentModel} />
        <InfoRow label="policy" value={data.policyMode} />
        <InfoRow label="id" value={data.sessionId} />
      </Section>

      {/* Files touched */}
      {data.filesTouched && data.filesTouched.length > 0 && (
        <Section title="files">
          <div className="flex flex-col">
            {data.filesTouched.map((file, i) => (
              <div key={i} className="flex items-center gap-1.5 py-px">
                <IconFileCode size={9} stroke={1.5} className="text-[#2a2f3a] shrink-0" />
                <span className="text-[9px] text-[#5c6a80] font-mono truncate">{file}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Terminal output */}
      <Section title="output">
        <div
          className="rounded-sm p-2 font-mono text-[9px] leading-[1.7] overflow-x-auto"
          style={{ backgroundColor: "#050609" }}
        >
          {(data.previewLines ?? []).map((line, i) => (
            <div
              key={i}
              className={cn(
                "whitespace-pre",
                line.startsWith("$")
                  ? "text-[#c49a3c]"
                  : line.includes("FAILED") || line.includes("error")
                    ? "text-[#b85450]"
                    : line.includes("ok") || line.includes("passed")
                      ? "text-[#38a876]"
                      : "text-[#5c6a80]",
              )}
            >
              {line}
            </div>
          ))}
          {(!data.previewLines || data.previewLines.length === 0) && (
            <span className="text-[#1a1e28]">no output yet</span>
          )}
        </div>
      </Section>
    </>
  );
}

function TerminalTaskDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <>
      <Section title="task">
        <InfoRow label="status" value={data.status} />
        <InfoRow label="session" value={data.sessionId} />
      </Section>
      <Section title="prompt">
        <p className="text-[10px] text-[#5c6a80] font-mono leading-[1.6] whitespace-pre-wrap">
          {data.taskPrompt ?? "No task description provided."}
        </p>
      </Section>
    </>
  );
}

function ReceiptDetail({ data }: { data: SwarmBoardNodeData }) {
  const guards = data.guardResults ?? [];
  const passed = guards.filter((g) => g.allowed).length;
  const totalMs = guards.reduce((s, g) => s + (g.duration_ms ?? 0), 0);

  return (
    <>
      {/* Verdict + summary in one line */}
      <div className="flex items-center gap-2">
        <VerdictBadge verdict={data.verdict ?? "allow"} />
        <span
          className="text-[9px] font-mono text-[#4a5568]"
          style={{ fontVariantNumeric: 'tabular-nums' }}
        >
          {passed}/{guards.length} passed
          <Dot />
          {totalMs}ms
        </span>
      </div>

      <Section title="guards">
        <div className="flex flex-col gap-0.5">
          {guards.map((gr, i) => (
            <div key={i} className="flex items-center gap-2 py-0.5">
              <span
                className="w-1 h-1 rounded-full shrink-0"
                style={{ backgroundColor: gr.allowed ? "#38a876" : "#b85450" }}
              />
              <span className="text-[9px] text-[#ece7dc] font-mono flex-1 truncate">
                {gr.guard}
              </span>
              {gr.duration_ms != null && (
                <span
                  className="text-[8px] text-[#2a2f3a] font-mono shrink-0"
                  style={{ fontVariantNumeric: 'tabular-nums' }}
                >
                  {gr.duration_ms}ms
                </span>
              )}
            </div>
          ))}
          {guards.length === 0 && (
            <span className="text-[9px] text-[#1a1e28] font-mono">no guard results</span>
          )}
        </div>
      </Section>

      <Section title="signature">
        <div
          className="font-mono text-[8px] text-[#2a2f3a] break-all leading-[1.5]"
          style={{ fontVariantNumeric: 'tabular-nums' }}
        >
          {data.sessionId
            ? `ed25519:${data.sessionId.replace(/[^a-f0-9]/gi, "").padEnd(64, "0").slice(0, 64)}`
            : "no signature available"}
        </div>
      </Section>
    </>
  );
}

function DiffDetail({ data }: { data: SwarmBoardNodeData }) {
  const summary = data.diffSummary;
  return (
    <>
      {/* Compact diff stat — matching diff node's split treatment */}
      <div
        className="flex items-baseline gap-3 font-mono"
        style={{ fontVariantNumeric: 'tabular-nums' }}
      >
        <span className="text-[18px] font-bold text-[#38a876] tracking-tight">
          +{summary?.added ?? 0}
        </span>
        <span className="text-[18px] font-bold text-[#b85450] tracking-tight">
          -{summary?.removed ?? 0}
        </span>
      </div>

      <Section title="changed files">
        <div className="flex flex-col">
          {(summary?.files ?? []).map((file, i) => (
            <div key={i} className="flex items-center gap-1.5 py-px">
              <IconFileCode size={9} stroke={1.5} className="text-[#2a2f3a] shrink-0" />
              <span className="text-[9px] text-[#5c6a80] font-mono truncate">{file}</span>
            </div>
          ))}
          {(!summary?.files || summary.files.length === 0) && (
            <span className="text-[9px] text-[#1a1e28] font-mono">no files changed</span>
          )}
        </div>
      </Section>
    </>
  );
}

function ArtifactDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <>
      <Section title="file">
        <InfoRow label="path" value={data.filePath} />
        <InfoRow label="type" value={data.fileType} />
      </Section>
      <Section title="preview">
        <div
          className="rounded-sm p-2 font-mono text-[8px] text-[#1a1e28] leading-[1.7]"
          style={{ backgroundColor: "#050609", minHeight: 48 }}
        >
          preview available when connected to PTY backend
        </div>
      </Section>
    </>
  );
}

function NoteDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <Section title="content">
      <div className="text-[10px] text-[#9a8e78] leading-[1.7] whitespace-pre-wrap min-h-[48px]">
        {data.content || (
          <span className="text-[#3d3528]">empty</span>
        )}
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div
        className="text-[7px] font-mono uppercase text-[#2a2f3a] mb-1.5"
        style={{ letterSpacing: '0.15em' }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function InfoRow({
  label,
  value,
}: {
  label: string;
  value?: string;
}) {
  if (!value) return null;
  return (
    <div className="flex items-baseline gap-2 py-px font-mono">
      <span className="text-[8px] text-[#2a2f3a] w-14 shrink-0">{label}</span>
      <span className="text-[9px] text-[#5c6a80] truncate">{value}</span>
    </div>
  );
}

function Dot() {
  return <span className="text-[#1a1e28] mx-1">&middot;</span>;
}

function VerdictBadge({ verdict }: { verdict: "allow" | "deny" | "warn" }) {
  const config = {
    allow: { text: "#38a876", bg: "#38a87612", label: "ALLOW", icon: IconCheck },
    deny: { text: "#b85450", bg: "#b8545012", label: "DENY", icon: IconShieldOff },
    warn: { text: "#c49a3c", bg: "#c49a3c12", label: "WARN", icon: IconAlertTriangle },
  }[verdict];
  const VIcon = config.icon;

  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[9px] font-mono font-semibold"
      style={{ backgroundColor: config.bg, color: config.text }}
    >
      <VIcon size={10} stroke={2} />
      {config.label}
    </span>
  );
}
