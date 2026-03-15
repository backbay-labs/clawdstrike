import { useState, useCallback } from "react";
import { IconTerminal, IconCopy, IconCheck, IconX } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useHintSettingsSafe, type HintId, DEFAULT_HINTS } from "@/lib/workbench/use-hint-settings";

interface ClaudeCodeHintProps {
  hintId?: HintId;
  hint?: string;
  prompt?: string;
  className?: string;
}

// Secondary prompt suggestions by context
const CONTEXT_PROMPTS: Partial<Record<HintId, Array<{ label: string; prompt: string }>>> = {
  "editor.validate": [
    {
      label: "Validate & tighten",
      prompt: DEFAULT_HINTS["editor.validate"].prompt,
    },
    {
      label: "Generate test scenarios",
      prompt: DEFAULT_HINTS["simulator.scenarios"].prompt,
    },
    {
      label: "Check compliance scores",
      prompt: DEFAULT_HINTS["compliance.check"].prompt,
    },
  ],
  "home.audit": [
    {
      label: "Full security audit",
      prompt: DEFAULT_HINTS["home.audit"].prompt,
    },
    {
      label: "Assess risk posture",
      prompt: DEFAULT_HINTS["risk.assess"].prompt,
    },
    {
      label: "Harden policy",
      prompt: DEFAULT_HINTS["library.harden"].prompt,
    },
  ],
  "simulator.scenarios": [
    {
      label: "Generate attack scenarios",
      prompt: DEFAULT_HINTS["simulator.scenarios"].prompt,
    },
    {
      label: "Validate & tighten",
      prompt: DEFAULT_HINTS["editor.validate"].prompt,
    },
    {
      label: "Build test suite",
      prompt: DEFAULT_HINTS["library.testSuite"].prompt,
    },
  ],
  "library.audit": [
    {
      label: "Audit my policy",
      prompt: DEFAULT_HINTS["library.audit"].prompt,
    },
    {
      label: "Build test suite",
      prompt: DEFAULT_HINTS["library.testSuite"].prompt,
    },
    {
      label: "Compare versions",
      prompt: DEFAULT_HINTS["library.compare"].prompt,
    },
  ],
};

// Fallback prompts when no context-specific set exists
const FALLBACK_PROMPTS = [
  { label: "Validate & tighten", prompt: DEFAULT_HINTS["editor.validate"].prompt },
  { label: "Generate scenarios", prompt: DEFAULT_HINTS["simulator.scenarios"].prompt },
  { label: "Harden policy", prompt: DEFAULT_HINTS["library.harden"].prompt },
];

export function ClaudeCodeHint({ hintId, hint, prompt, className }: ClaudeCodeHintProps) {
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const ctx = useHintSettingsSafe();

  // Resolve visibility
  if (hintId && ctx && !ctx.showHints) return null;
  if (dismissed) return null;

  // Resolve prompts list
  const prompts = hintId && CONTEXT_PROMPTS[hintId]
    ? CONTEXT_PROMPTS[hintId]
    : prompt
      ? [{ label: hint || "Copy prompt", prompt }]
      : FALLBACK_PROMPTS;

  if (!prompts || prompts.length === 0) return null;

  const handleCopy = async (idx: number) => {
    try {
      await navigator.clipboard.writeText(prompts[idx].prompt);
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 2000);
    } catch {
      // Clipboard API may fail if document is not focused
    }
  };

  return (
    <div
      className={cn(
        "absolute bottom-4 left-4 z-30 w-[260px] rounded border border-[#8b5cf6]/12 bg-[#0a0c12]/95 backdrop-blur-sm shadow-lg",
        className,
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#1a1d28]">
        <div className="flex items-center gap-1.5">
          <IconTerminal size={11} stroke={1.5} className="text-[#8b5cf6]/60" />
          <span className="text-[9px] font-mono text-[#8b5cf6]/60 uppercase tracking-wider">
            Claude Code
          </span>
        </div>
        <button
          type="button"
          onClick={() => setDismissed(true)}
          className="text-[#6f7f9a]/30 hover:text-[#6f7f9a]/60 transition-colors"
          title="Dismiss"
        >
          <IconX size={10} stroke={1.5} />
        </button>
      </div>

      {/* Prompt rows */}
      <div className="py-1">
        {prompts.map((p, idx) => {
          const isCopied = copiedIdx === idx;
          return (
            <button
              key={p.label}
              type="button"
              onClick={() => void handleCopy(idx)}
              className="group flex items-center gap-2 w-full px-3 py-1.5 text-left hover:bg-[#8b5cf6]/[0.04] transition-colors"
            >
              <span className="text-[10px] text-[#6f7f9a]/70 group-hover:text-[#ece7dc]/70 transition-colors truncate flex-1">
                {p.label}
              </span>
              {isCopied ? (
                <IconCheck size={10} stroke={2} className="shrink-0 text-[#3dbf84]" />
              ) : (
                <IconCopy size={10} stroke={1.5} className="shrink-0 text-[#6f7f9a]/0 group-hover:text-[#8b5cf6]/50 transition-colors" />
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
