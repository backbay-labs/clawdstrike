import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { readTextFileFromDisk } from "@/lib/tauri-bridge";
import {
  normalizeUnifiedDiffContent,
  parseUnifiedDiffLines,
  type ParsedDiffLine,
} from "./diff-preview";

type DiffPreviewState =
  | { status: "idle" | "loading"; content: string; error: null }
  | { status: "ready"; content: string; error: null }
  | { status: "error"; content: string; error: string };

export function DiffPreviewPane({
  diffContent,
  diffPath,
  refreshToken,
  maxLines,
  maxHeight,
  showLineNumbers = false,
  emptyMessage = "No diff preview available",
}: {
  diffContent?: string;
  diffPath?: string;
  refreshToken?: number;
  maxLines?: number;
  maxHeight?: number;
  showLineNumbers?: boolean;
  emptyMessage?: string;
}) {
  const [state, setState] = useState<DiffPreviewState>({
    status: "idle",
    content: "",
    error: null,
  });

  useEffect(() => {
    const inlineContent = diffContent?.trim();
    if (inlineContent) {
      setState({
        status: "ready",
        content: normalizeUnifiedDiffContent(inlineContent),
        error: null,
      });
      return;
    }

    if (!diffPath) {
      setState({ status: "idle", content: "", error: null });
      return;
    }

    let cancelled = false;
    setState({ status: "loading", content: "", error: null });

    void readTextFileFromDisk(diffPath).then((loaded) => {
      if (cancelled) {
        return;
      }

      const nextContent = loaded?.trim();
      if (!nextContent) {
        setState({
          status: "error",
          content: "",
          error: "Diff source unavailable",
        });
        return;
      }

      setState({
        status: "ready",
        content: normalizeUnifiedDiffContent(nextContent),
        error: null,
      });
    });

    return () => {
      cancelled = true;
    };
  }, [diffContent, diffPath, refreshToken]);

  const parsedLines = useMemo(
    () => (state.status === "ready" ? parseUnifiedDiffLines(state.content) : []),
    [state.content, state.status],
  );
  const visibleLines =
    typeof maxLines === "number" ? parsedLines.slice(0, maxLines) : parsedLines;
  const hiddenLineCount = Math.max(parsedLines.length - visibleLines.length, 0);
  const previewContent = visibleLines.map((line) => line.content).join("\n");

  if (state.status === "loading") {
    return (
      <div
        className="rounded-sm border border-[#14181f] bg-[#050609] px-2 py-2 text-[9px] font-mono text-[#4a5568]"
        data-testid="diff-preview-loading"
      >
        loading diff...
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div
        className="rounded-sm border border-[#2a1414] bg-[#090506] px-2 py-2 text-[9px] font-mono text-[#b85450]"
        data-testid="diff-preview-error"
      >
        {state.error}
      </div>
    );
  }

  if (state.status !== "ready" || previewContent.length === 0) {
    return (
      <div
        className="rounded-sm border border-[#14181f] bg-[#050609] px-2 py-2 text-[9px] font-mono text-[#4a5568]"
        data-testid="diff-preview-empty"
      >
        {emptyMessage}
      </div>
    );
  }

  return (
    <div
      className="rounded-sm border border-[#14181f] bg-[#050609] overflow-hidden"
      data-testid="diff-preview-pane"
    >
      <div
        className="overflow-auto font-mono text-[11px] leading-[1.6]"
        style={{ maxHeight: maxHeight ? `${maxHeight}px` : undefined }}
      >
        {visibleLines.map((line, index) => (
          <div key={`${index}-${line.content}`} className="flex">
            {showLineNumbers && (
              <span className="shrink-0 select-none border-r border-[#14181f] px-2 py-0.5 text-[#4a5568]">
                {index + 1}
              </span>
            )}
            <span
              className="block flex-1 whitespace-pre px-2 py-0.5"
              style={buildDiffLineStyle(line)}
            >
              {line.content || " "}
            </span>
          </div>
        ))}
      </div>
      {hiddenLineCount > 0 && (
        <div className="border-t border-[#14181f] px-2 py-1 text-[8px] font-mono text-[#4a5568]">
          +{hiddenLineCount} more line{hiddenLineCount === 1 ? "" : "s"}
        </div>
      )}
    </div>
  );
}

function buildDiffLineStyle(line: ParsedDiffLine | undefined): CSSProperties {
  switch (line?.kind) {
    case "add":
      return {
        backgroundColor: "rgba(56, 168, 118, 0.12)",
        color: "#8bd4ab",
      };
    case "remove":
      return {
        backgroundColor: "rgba(184, 84, 80, 0.12)",
        color: "#e3a19e",
      };
    case "hunk":
      return {
        backgroundColor: "rgba(85, 128, 204, 0.12)",
        color: "#8fb2ff",
      };
    case "meta":
      return {
        color: "#7b8496",
      };
    default:
      return {
        color: "#c7ccd6",
      };
  }
}
