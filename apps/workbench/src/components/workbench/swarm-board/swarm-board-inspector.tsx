/**
 * SwarmBoardInspector — right-side detail drawer for the selected node.
 *
 * Shows full details based on node type: terminal output, guard results,
 * diff view, artifact preview, etc.
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
  IconFolder,
  IconGitBranch,
  IconReceipt,
  IconExternalLink,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/lib/workbench/swarm-board-store";
import type { SwarmBoardNodeData, SwarmNodeType } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Node type metadata
// ---------------------------------------------------------------------------

const NODE_TYPE_META: Record<
  SwarmNodeType,
  { icon: typeof IconTerminal2; label: string; color: string }
> = {
  agentSession: { icon: IconTerminal2, label: "Agent Session", color: "#d4a84b" },
  terminalTask: { icon: IconSubtask, label: "Terminal Task", color: "#5b8def" },
  artifact: { icon: IconFile, label: "Artifact", color: "#3dbf84" },
  diff: { icon: IconGitCommit, label: "Diff", color: "#8b5cf6" },
  note: { icon: IconNote, label: "Note", color: "#d4a84b" },
  receipt: { icon: IconCertificate, label: "Receipt", color: "#8b5cf6" },
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

  // Close on Escape key
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
          initial={{ x: 360, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 360, opacity: 0 }}
          transition={{ type: "spring", damping: 28, stiffness: 300 }}
          className="fixed top-0 right-0 h-full w-[360px] z-50 flex flex-col border-l border-[#2d3240]"
          style={{ backgroundColor: "#0a0c12" }}
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
      <div className="flex items-center gap-2.5 px-4 py-3 border-b border-[#2d324060] shrink-0">
        <div
          className="shrink-0 flex items-center justify-center w-7 h-7 rounded-md"
          style={{
            backgroundColor: `${meta.color}12`,
            border: `1px solid ${meta.color}20`,
          }}
        >
          <TypeIcon size={14} stroke={1.5} style={{ color: meta.color }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[13px] font-syne font-semibold text-[#ece7dc] truncate">
            {data.title}
          </div>
          <div className="text-[10px] text-[#6f7f9a] uppercase tracking-wider">
            {meta.label}
          </div>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 p-1 rounded hover:bg-[#131721] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          aria-label="Close inspector"
        >
          <IconX size={16} stroke={1.5} />
        </button>
      </div>

      {/* Body (scrollable) */}
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        {nodeType === "agentSession" && <AgentSessionDetail data={data} />}
        {nodeType === "terminalTask" && <TerminalTaskDetail data={data} />}
        {nodeType === "receipt" && <ReceiptDetail data={data} />}
        {nodeType === "diff" && <DiffDetail data={data} />}
        {nodeType === "artifact" && <ArtifactDetail data={data} />}
        {nodeType === "note" && <NoteDetail data={data} />}
      </div>

      {/* Footer actions */}
      <div className="flex items-center gap-2 px-4 py-3 border-t border-[#2d324060] shrink-0">
        {nodeType === "agentSession" && (
          <>
            <ActionButton icon={IconTerminal2} label="Open Terminal" />
            <ActionButton icon={IconReceipt} label="View Receipts" />
            <ActionButton icon={IconGitCommit} label="Show Diff" />
          </>
        )}
        {nodeType === "receipt" && (
          <>
            <ActionButton icon={IconCertificate} label="Verify Signature" />
            <ActionButton icon={IconExternalLink} label="Full Receipt" />
          </>
        )}
        {nodeType === "diff" && (
          <ActionButton icon={IconExternalLink} label="Open Diff View" />
        )}
        {nodeType === "artifact" && (
          <ActionButton icon={IconExternalLink} label="Open File" />
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Sections per node type
// ---------------------------------------------------------------------------

function AgentSessionDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <>
      {/* Session info */}
      <Section title="Session">
        <InfoRow icon={IconGitBranch} label="Branch" value={data.branch} />
        <InfoRow icon={IconFolder} label="Worktree" value={data.worktreePath} mono />
        <InfoRow label="Model" value={data.agentModel} />
        <InfoRow label="Policy" value={data.policyMode} />
        <InfoRow label="Session ID" value={data.sessionId} mono />
      </Section>

      {/* Metrics */}
      <Section title="Metrics">
        <div className="grid grid-cols-3 gap-2">
          <MetricCard label="Files Changed" value={data.changedFilesCount ?? 0} color="#5b8def" />
          <MetricCard label="Receipts" value={data.receiptCount ?? 0} color="#8b5cf6" />
          <MetricCard label="Blocked" value={data.blockedActionCount ?? 0} color={data.blockedActionCount ? "#e74c3c" : "#6f7f9a"} />
        </div>
        {(data.toolBoundaryEvents != null || data.confidence != null) && (
          <div className="grid grid-cols-2 gap-2 mt-2">
            {data.toolBoundaryEvents != null && (
              <MetricCard label="Tool Events" value={data.toolBoundaryEvents} color="#d4a84b" />
            )}
            {data.confidence != null && (
              <MetricCard label="Confidence" value={data.confidence} color={data.confidence >= 80 ? "#3dbf84" : data.confidence >= 50 ? "#d4a84b" : "#e74c3c"} />
            )}
          </div>
        )}
      </Section>

      {/* Files touched */}
      {data.filesTouched && data.filesTouched.length > 0 && (
        <Section title="Files Touched">
          <div className="flex flex-col gap-0.5">
            {data.filesTouched.map((file, i) => (
              <div key={i} className="flex items-center gap-2">
                <IconFileCode size={11} stroke={1.5} className="text-[#5b8def] shrink-0" />
                <span className="text-[10px] text-[#8a96ab] font-mono truncate">{file}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Terminal output */}
      <Section title="Terminal Output">
        <div
          className="rounded-md p-3 font-mono text-[10px] leading-[1.7] overflow-x-auto"
          style={{ backgroundColor: "#05060a", border: "1px solid #1a1f2e" }}
        >
          {(data.previewLines ?? []).map((line, i) => (
            <div
              key={i}
              className={cn(
                "whitespace-pre",
                line.startsWith("$")
                  ? "text-[#d4a84b]"
                  : line.includes("FAILED") || line.includes("error")
                    ? "text-[#e74c3c]"
                    : line.includes("ok") || line.includes("passed")
                      ? "text-[#3dbf84]"
                      : "text-[#8a96ab]",
              )}
            >
              {line}
            </div>
          ))}
          {(!data.previewLines || data.previewLines.length === 0) && (
            <span className="text-[#3d4250] italic">No terminal output yet</span>
          )}
        </div>
      </Section>
    </>
  );
}

function TerminalTaskDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <>
      <Section title="Task">
        <InfoRow label="Status" value={data.status} />
        <InfoRow label="Session" value={data.sessionId} mono />
      </Section>
      <Section title="Prompt">
        <p className="text-[11px] text-[#8a96ab] leading-[1.6] whitespace-pre-wrap">
          {data.taskPrompt ?? "No task description provided."}
        </p>
      </Section>
    </>
  );
}

function ReceiptDetail({ data }: { data: SwarmBoardNodeData }) {
  const guards = data.guardResults ?? [];
  const passed = guards.filter((g) => g.allowed).length;
  const failed = guards.filter((g) => !g.allowed).length;

  return (
    <>
      <Section title="Verdict">
        <div className="flex items-center gap-3">
          <VerdictBadgeLarge verdict={data.verdict ?? "allow"} />
          <div>
            <div className="text-[11px] text-[#8a96ab]">
              {passed} passed / {failed} failed
            </div>
            <div className="text-[10px] text-[#3d4250] mt-0.5">
              Total duration: {guards.reduce((s, g) => s + (g.duration_ms ?? 0), 0)}ms
            </div>
          </div>
        </div>
      </Section>

      <Section title="Guard Results">
        <div className="flex flex-col gap-1.5">
          {guards.map((gr, i) => (
            <div
              key={i}
              className="flex items-center gap-2 px-2.5 py-1.5 rounded-md"
              style={{ backgroundColor: "#0b0d13", border: "1px solid #1a1f2e" }}
            >
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: gr.allowed ? "#3dbf84" : "#e74c3c" }}
              />
              <span className="text-[11px] text-[#ece7dc] font-mono flex-1 truncate">
                {gr.guard}
              </span>
              {gr.allowed ? (
                <IconCheck size={12} stroke={2} className="text-[#3dbf84] shrink-0" />
              ) : (
                <IconShieldOff size={12} stroke={2} className="text-[#e74c3c] shrink-0" />
              )}
              {gr.duration_ms != null && (
                <span className="text-[9px] text-[#3d4250] font-mono shrink-0 w-8 text-right">
                  {gr.duration_ms}ms
                </span>
              )}
            </div>
          ))}
          {guards.length === 0 && (
            <span className="text-[10px] text-[#3d4250] italic">No guard results</span>
          )}
        </div>
      </Section>

      <Section title="Signature">
        <div
          className="rounded-md p-2.5 font-mono text-[9px] text-[#3d4250] break-all"
          style={{ backgroundColor: "#05060a", border: "1px solid #1a1f2e" }}
        >
          {data.sessionId
            ? `ed25519:${data.sessionId.replace(/[^a-f0-9]/gi, "").padEnd(64, "0").slice(0, 64)}`
            : "No signature available"}
        </div>
      </Section>
    </>
  );
}

function DiffDetail({ data }: { data: SwarmBoardNodeData }) {
  const summary = data.diffSummary;
  return (
    <>
      <Section title="Summary">
        <div className="flex items-center gap-4 mb-2">
          <span className="text-[18px] font-bold text-[#3dbf84]">+{summary?.added ?? 0}</span>
          <span className="text-[18px] font-bold text-[#e74c3c]">-{summary?.removed ?? 0}</span>
        </div>
      </Section>
      <Section title="Changed Files">
        <div className="flex flex-col gap-1">
          {(summary?.files ?? []).map((file, i) => (
            <div key={i} className="flex items-center gap-2">
              <IconFileCode size={12} stroke={1.5} className="text-[#5b8def] shrink-0" />
              <span className="text-[11px] text-[#8a96ab] font-mono truncate">{file}</span>
            </div>
          ))}
          {(!summary?.files || summary.files.length === 0) && (
            <span className="text-[10px] text-[#3d4250] italic">No files changed</span>
          )}
        </div>
      </Section>
    </>
  );
}

function ArtifactDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <>
      <Section title="File Info">
        <InfoRow label="Path" value={data.filePath} mono />
        <InfoRow label="Type" value={data.fileType} />
      </Section>
      <Section title="Preview">
        <div
          className="rounded-md p-3 font-mono text-[10px] text-[#3d4250] leading-[1.7]"
          style={{ backgroundColor: "#05060a", border: "1px solid #1a1f2e", minHeight: 80 }}
        >
          <span className="italic">File preview will be available when connected to a PTY backend.</span>
        </div>
      </Section>
    </>
  );
}

function NoteDetail({ data }: { data: SwarmBoardNodeData }) {
  return (
    <Section title="Content">
      <div className="text-[12px] text-[#8a96ab] leading-[1.7] whitespace-pre-wrap min-h-[80px]">
        {data.content || (
          <span className="text-[#3d4250] italic">No content</span>
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
      <h3 className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a] mb-2">
        {title}
      </h3>
      {children}
    </div>
  );
}

function InfoRow({
  icon: Icon,
  label,
  value,
  mono = false,
}: {
  icon?: typeof IconGitBranch;
  label: string;
  value?: string;
  mono?: boolean;
}) {
  if (!value) return null;
  return (
    <div className="flex items-center gap-2 py-0.5">
      {Icon && <Icon size={11} stroke={1.5} className="text-[#3d4250] shrink-0" />}
      <span className="text-[10px] text-[#6f7f9a] w-16 shrink-0">{label}</span>
      <span
        className={cn(
          "text-[11px] text-[#ece7dc] truncate",
          mono && "font-mono text-[10px]",
        )}
      >
        {value}
      </span>
    </div>
  );
}

function MetricCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div
      className="flex flex-col items-center gap-0.5 rounded-md py-2 px-1"
      style={{ backgroundColor: `${color}08`, border: `1px solid ${color}15` }}
    >
      <span className="text-[16px] font-bold" style={{ color }}>
        {value}
      </span>
      <span className="text-[8px] text-[#6f7f9a] uppercase tracking-wider text-center">
        {label}
      </span>
    </div>
  );
}

function VerdictBadgeLarge({ verdict }: { verdict: "allow" | "deny" | "warn" }) {
  const config = {
    allow: { bg: "#3dbf8418", text: "#3dbf84", border: "#3dbf8430", label: "ALLOW", icon: IconCheck },
    deny: { bg: "#e74c3c18", text: "#e74c3c", border: "#e74c3c30", label: "DENY", icon: IconShieldOff },
    warn: { bg: "#d4a84b18", text: "#d4a84b", border: "#d4a84b30", label: "WARN", icon: IconAlertTriangle },
  }[verdict];
  const VIcon = config.icon;

  return (
    <div
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-bold uppercase tracking-wide"
      style={{
        backgroundColor: config.bg,
        color: config.text,
        border: `1px solid ${config.border}`,
      }}
    >
      <VIcon size={14} stroke={2} />
      {config.label}
    </div>
  );
}

function ActionButton({
  icon: Icon,
  label,
  onClick,
}: {
  icon: typeof IconTerminal2;
  label: string;
  onClick?: () => void;
}) {
  return (
    <button
      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721] transition-colors uppercase tracking-wide border border-[#2d324060] disabled:opacity-40 disabled:pointer-events-none"
      title={label}
      aria-label={label}
      onClick={onClick}
      disabled={!onClick}
    >
      <Icon size={12} stroke={1.5} />
      <span>{label}</span>
    </button>
  );
}
