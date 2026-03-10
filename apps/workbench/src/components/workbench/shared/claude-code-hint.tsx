import { useState, useCallback } from "react";
import { IconTerminal, IconCopy, IconCheck } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface ClaudeCodeHintProps {
  hint: string;
  prompt: string;
  className?: string;
}

export function ClaudeCodeHint({ hint, prompt, className }: ClaudeCodeHintProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may fail if document is not focused
    }
  }, [prompt]);

  return (
    <div
      className={cn(
        "flex items-center gap-2.5 px-3 py-2 rounded-lg border border-[#8b5cf6]/15 bg-[#8b5cf6]/[0.04] transition-colors hover:border-[#8b5cf6]/25 hover:bg-[#8b5cf6]/[0.06]",
        className,
      )}
    >
      <IconTerminal
        size={13}
        stroke={1.5}
        className="text-[#8b5cf6]/70 shrink-0"
      />
      <span className="text-[11px] text-[#6f7f9a] truncate min-w-0">
        {hint}
      </span>
      <button
        onClick={handleCopy}
        className={cn(
          "ml-auto shrink-0 flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono transition-colors",
          copied
            ? "text-[#3dbf84] bg-[#3dbf84]/10"
            : "text-[#8b5cf6]/70 hover:text-[#8b5cf6] hover:bg-[#8b5cf6]/10",
        )}
        title={copied ? "Copied!" : "Copy prompt to clipboard"}
      >
        {copied ? (
          <>
            <IconCheck size={10} stroke={2} />
            <span>Copied</span>
          </>
        ) : (
          <>
            <IconCopy size={10} stroke={1.5} />
            <span>Copy prompt</span>
          </>
        )}
      </button>
    </div>
  );
}
