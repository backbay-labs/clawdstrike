import { type ReactNode, useEffect, useMemo, useState } from "react";
import { StyleModule } from "style-mod";
import { readTextFileFromDisk } from "@/lib/tauri-bridge";
import {
  normalizeUnifiedDiffContent,
  parseUnifiedDiffLines,
  type DiffLineKind,
  type ParsedDiffLine,
} from "./diff-preview";
import {
  resolveParser,
  highlightLine,
  extractDiffFilePath,
  type HighlightedToken,
} from "./diff-highlight";
import { diffHighlightStyle } from "./codemirror-theme";

type DiffPreviewState =
  | { status: "idle" | "loading"; content: string; error: null }
  | { status: "ready"; content: string; error: null }
  | { status: "error"; content: string; error: string };

// ---------------------------------------------------------------------------
// Diff-line style helpers (split from the old buildDiffLineStyle)
// ---------------------------------------------------------------------------

export function getDiffLineBg(kind: DiffLineKind): string | undefined {
  switch (kind) {
    case "add":
      return "rgba(56, 168, 118, 0.12)";
    case "remove":
      return "rgba(184, 84, 80, 0.12)";
    case "hunk":
      return "rgba(85, 128, 204, 0.12)";
    default:
      return undefined;
  }
}

export function getDiffLineFallbackColor(kind: DiffLineKind): string {
  switch (kind) {
    case "add":
      return "#8bd4ab";
    case "remove":
      return "#e3a19e";
    case "hunk":
      return "#8fb2ff";
    case "meta":
      return "#7b8496";
    default:
      return "#c7ccd6";
  }
}

// ---------------------------------------------------------------------------
// Token rendering helper
// ---------------------------------------------------------------------------

function renderHighlightedTokens(
  tokens: HighlightedToken[],
  fallbackColor: string,
): ReactNode {
  return tokens.map((token, i) => (
    <span
      key={i}
      style={{ color: token.className ? undefined : fallbackColor }}
      className={token.className || undefined}
    >
      {token.text}
    </span>
  ));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

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

  const [tokensByLine, setTokensByLine] = useState<Map<number, HighlightedToken[]> | null>(null);

  // Mount the StyleModule CSS classes so syntax class names resolve in the DOM
  useEffect(() => {
    if (diffHighlightStyle.module) {
      StyleModule.mount(document, diffHighlightStyle.module);
    }
  }, []);

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

  // Syntax highlighting effect: resolve parser and tokenize visible lines
  useEffect(() => {
    if (state.status !== "ready" || visibleLines.length === 0) {
      setTokensByLine(null);
      return;
    }

    const filePath = extractDiffFilePath(parsedLines);
    if (!filePath) {
      setTokensByLine(null);
      return;
    }

    let cancelled = false;

    void resolveParser(filePath).then((parser) => {
      if (cancelled || !parser) return;

      const map = new Map<number, HighlightedToken[]>();
      visibleLines.forEach((line, index) => {
        if (line.kind === "add" || line.kind === "remove" || line.kind === "context") {
          map.set(index, highlightLine(line.content, parser, diffHighlightStyle));
        }
      });
      setTokensByLine(map);
    });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.status, state.content, parsedLines.length]);

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
              style={{ backgroundColor: getDiffLineBg(line.kind) }}
            >
              {tokensByLine?.get(index)
                ? renderHighlightedTokens(tokensByLine.get(index)!, getDiffLineFallbackColor(line.kind))
                : <span style={{ color: getDiffLineFallbackColor(line.kind) }}>{line.content || " "}</span>
              }
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
