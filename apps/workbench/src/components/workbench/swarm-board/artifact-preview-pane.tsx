import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { EditorState, type Extension } from "@codemirror/state";
import { json as jsonLanguage } from "@codemirror/lang-json";
import { javascript } from "@codemirror/lang-javascript";
import { yaml as yamlLanguage } from "@codemirror/lang-yaml";
import {
  HighlightStyle,
  bracketMatching,
  foldGutter,
  syntaxHighlighting,
} from "@codemirror/language";
import { tags } from "@lezer/highlight";
import {
  EditorView,
  drawSelection,
  highlightActiveLine,
  highlightActiveLineGutter,
  lineNumbers,
} from "@codemirror/view";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

const TAURI_FS_SPECIFIER = "@tauri-apps/plugin-fs";

function isDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function readArtifactTextFile(filePath: string): Promise<string | null> {
  if (!isDesktop()) {
    return null;
  }

  try {
    const { readTextFile } = await import(/* @vite-ignore */ TAURI_FS_SPECIFIER);
    return await readTextFile(filePath);
  } catch (err) {
    console.error("[artifact-preview-pane] Failed to read file:", filePath, err);
    return null;
  }
}

const previewTheme = EditorView.theme({
  "&": {
    backgroundColor: "#050609",
    color: "#ece7dc",
    height: "100%",
    fontFamily:
      "'JetBrains Mono', ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
    fontSize: "11px",
  },
  "&.cm-focused": {
    outline: "none",
  },
  ".cm-scroller": {
    overflow: "auto",
    lineHeight: "1.65",
  },
  ".cm-content": {
    padding: "8px 0",
  },
  ".cm-gutters": {
    backgroundColor: "#050609",
    color: "#4a5568",
    borderRight: "1px solid #14181f",
  },
  ".cm-activeLine": {
    backgroundColor: "#0d1119",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "#0d1119",
  },
  ".cm-selectionBackground": {
    backgroundColor: "#202735 !important",
  },
});

const previewHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: tags.keyword, color: "#7c9aef" },
    { tag: tags.string, color: "#38a876" },
    { tag: tags.number, color: "#d4a84b" },
    { tag: tags.comment, color: "#4a5568", fontStyle: "italic" },
    { tag: tags.bool, color: "#c49a3c" },
    { tag: tags.null, color: "#b85450" },
    { tag: [tags.propertyName, tags.attributeName], color: "#9aa7bd" },
    { tag: [tags.function(tags.variableName), tags.className], color: "#d7c7a2" },
  ]),
);

type ArtifactPreviewState =
  | { status: "idle" | "loading"; content: string; error: null }
  | { status: "ready"; content: string; error: null }
  | { status: "error"; content: string; error: string };

export function isMarkdownArtifact(filePath?: string, fileType?: string): boolean {
  return /\.md$/i.test(filePath ?? "") || fileType === "markdown";
}

function isYamlFile(filePath?: string, fileType?: string): boolean {
  return (
    /\.ya?ml$/i.test(filePath ?? "") ||
    fileType === "clawdstrike_policy" ||
    fileType === "sigma_rule"
  );
}

function isJsonFile(filePath?: string, fileType?: string): boolean {
  return /\.json$/i.test(filePath ?? "") || fileType === "ocsf_event";
}

function sortPreviewValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortPreviewValue);
  }

  if (value && typeof value === "object") {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((sorted, key) => {
        sorted[key] = sortPreviewValue((value as Record<string, unknown>)[key]);
        return sorted;
      }, {});
  }

  return value;
}

function resolveLanguageExtensions(
  filePath?: string,
  fileType?: string,
): Extension[] {
  const lowerPath = filePath?.toLowerCase() ?? "";
  if (isYamlFile(filePath, fileType)) {
    return [yamlLanguage()];
  }
  if (isJsonFile(filePath, fileType)) {
    return [jsonLanguage()];
  }
  if (/\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/i.test(lowerPath)) {
    return [
      javascript({
        typescript: /\.(ts|tsx|mts|cts)$/i.test(lowerPath),
        jsx: /\.(tsx|jsx)$/i.test(lowerPath),
      }),
    ];
  }
  return [];
}

export function normalizeArtifactPreviewContent(
  content: string,
  filePath?: string,
  fileType?: string,
): string {
  if (isYamlFile(filePath, fileType)) {
    try {
      return stringifyYaml(sortPreviewValue(parseYaml(content))).trimEnd();
    } catch {
      return content;
    }
  }

  if (isJsonFile(filePath, fileType)) {
    try {
      return JSON.stringify(JSON.parse(content), null, 2);
    } catch {
      return content;
    }
  }

  return content;
}

function renderInlineMarkdown(text: string): ReactNode[] {
  const parts: ReactNode[] = [];
  const tokenPattern = /(`[^`]+`|\*\*[^*]+\*\*)/;
  let remaining = text;
  let key = 0;

  while (remaining.length > 0) {
    const match = remaining.match(tokenPattern);
    if (!match || match.index == null) {
      parts.push(remaining);
      break;
    }

    if (match.index > 0) {
      parts.push(remaining.slice(0, match.index));
    }

    const token = match[0];
    if (token.startsWith("`")) {
      parts.push(
        <code
          key={`code-${key++}`}
          className="px-1 py-0.5 rounded-sm bg-[#0d1119] text-[#d4a84b]"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      parts.push(
        <strong key={`strong-${key++}`} className="text-[#ece7dc] font-semibold">
          {token.slice(2, -2)}
        </strong>,
      );
    }

    remaining = remaining.slice(match.index + token.length);
  }

  return parts;
}

function MarkdownPreview({ content }: { content: string }) {
  const lines = content.split(/\r?\n/);
  const blocks: React.ReactNode[] = [];
  let index = 0;
  let key = 0;

  while (index < lines.length) {
    const line = lines[index];

    if (line.trim().length === 0) {
      index += 1;
      continue;
    }

    if (line.startsWith("```")) {
      const language = line.slice(3).trim();
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      index += 1;
      blocks.push(
        <div
          key={`codeblock-${key++}`}
          className="rounded-sm border border-[#14181f] bg-[#050609] overflow-hidden"
        >
          {language && (
            <div className="px-2 py-1 text-[8px] font-mono uppercase tracking-[0.12em] text-[#4a5568] border-b border-[#14181f]">
              {language}
            </div>
          )}
          <pre className="m-0 p-2 text-[9px] font-mono text-[#9aa7bd] overflow-x-auto">
            <code>{codeLines.join("\n")}</code>
          </pre>
        </div>,
      );
      continue;
    }

    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      const depth = headingMatch[1].length;
      const sizeClass =
        depth === 1 ? "text-[14px]" : depth === 2 ? "text-[12px]" : "text-[11px]";
      blocks.push(
        <div
          key={`heading-${key++}`}
          className={`${sizeClass} font-semibold text-[#ece7dc] tracking-tight`}
        >
          {renderInlineMarkdown(headingMatch[2])}
        </div>,
      );
      index += 1;
      continue;
    }

    if (/^[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^[-*]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^[-*]\s+/, ""));
        index += 1;
      }
      blocks.push(
        <ul
          key={`list-${key++}`}
          className="m-0 pl-4 flex flex-col gap-1 list-disc text-[10px] text-[#9aa7bd]"
        >
          {items.map((item, itemIndex) => (
            <li key={`item-${itemIndex}`}>{renderInlineMarkdown(item)}</li>
          ))}
        </ul>,
      );
      continue;
    }

    if (line.startsWith("> ")) {
      const quoteLines: string[] = [];
      while (index < lines.length && lines[index].startsWith("> ")) {
        quoteLines.push(lines[index].slice(2));
        index += 1;
      }
      blocks.push(
        <blockquote
          key={`quote-${key++}`}
          className="m-0 border-l-2 border-[#2d3240] pl-3 text-[10px] text-[#9aa7bd]"
        >
          {quoteLines.map((quoteLine, quoteIndex) => (
            <p key={`quote-line-${quoteIndex}`} className="m-0">
              {renderInlineMarkdown(quoteLine)}
            </p>
          ))}
        </blockquote>,
      );
      continue;
    }

    const paragraphLines: string[] = [];
    while (
      index < lines.length &&
      lines[index].trim().length > 0 &&
      !lines[index].startsWith("```") &&
      !/^#{1,6}\s+/.test(lines[index]) &&
      !/^[-*]\s+/.test(lines[index]) &&
      !lines[index].startsWith("> ")
    ) {
      paragraphLines.push(lines[index]);
      index += 1;
    }

    blocks.push(
      <p key={`paragraph-${key++}`} className="m-0 text-[10px] leading-[1.7] text-[#9aa7bd]">
        {renderInlineMarkdown(paragraphLines.join(" "))}
      </p>,
    );
  }

  return <div className="flex flex-col gap-3">{blocks}</div>;
}

function CodeMirrorPreview({
  content,
  filePath,
  fileType,
}: {
  content: string;
  filePath?: string;
  fileType?: FileType;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);

  const extensions = useMemo<Extension[]>(
    () => [
      lineNumbers(),
      foldGutter(),
      drawSelection(),
      highlightActiveLine(),
      highlightActiveLineGutter(),
      bracketMatching(),
      EditorView.editable.of(false),
      EditorState.readOnly.of(true),
      previewTheme,
      previewHighlight,
      ...resolveLanguageExtensions(filePath, fileType),
    ],
    [filePath, fileType],
  );

  useEffect(() => {
    const parent = containerRef.current;
    if (!parent) {
      return;
    }

    parent.innerHTML = "";
    const view = new EditorView({
      state: EditorState.create({
        doc: content,
        extensions,
      }),
      parent,
    });

    return () => {
      view.destroy();
    };
  }, [content, extensions]);

  return <div ref={containerRef} className="h-full min-h-[180px]" />;
}

export function ArtifactPreviewPane({
  filePath,
  fileType,
  refreshToken,
}: {
  filePath?: string;
  fileType?: FileType;
  refreshToken?: number;
}) {
  const [state, setState] = useState<ArtifactPreviewState>({
    status: filePath ? "loading" : "idle",
    content: "",
    error: null,
  });

  useEffect(() => {
    if (!filePath) {
      setState({
        status: "idle",
        content: "",
        error: null,
      });
      return;
    }

    let cancelled = false;
    setState({
      status: "loading",
      content: "",
      error: null,
    });

    void readArtifactTextFile(filePath).then((content) => {
      if (cancelled) {
        return;
      }

      if (content == null) {
        setState({
          status: "error",
          content: "",
          error: "Preview requires desktop file access and a readable artifact path.",
        });
        return;
      }

      setState({
        status: "ready",
        content,
        error: null,
      });
    });

    return () => {
      cancelled = true;
    };
  }, [filePath, refreshToken]);

  const normalizedContent = useMemo(
    () => normalizeArtifactPreviewContent(state.content, filePath, fileType),
    [state.content, filePath, fileType],
  );

  if (!filePath) {
    return (
      <div
        className="rounded-sm p-2 font-mono text-[8px] text-[#1a1e28] leading-[1.7]"
        style={{ backgroundColor: "#050609", minHeight: 96 }}
      >
        no artifact file path available
      </div>
    );
  }

  if (state.status === "loading") {
    return (
      <div
        className="rounded-sm p-2 font-mono text-[8px] text-[#4a5568] leading-[1.7]"
        style={{ backgroundColor: "#050609", minHeight: 96 }}
      >
        loading artifact preview...
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div
        className="rounded-sm p-2 font-mono text-[8px] text-[#b85450] leading-[1.7]"
        style={{ backgroundColor: "#050609", minHeight: 96 }}
      >
        {state.error}
      </div>
    );
  }

  if (isMarkdownArtifact(filePath, fileType)) {
    return (
      <div
        className="rounded-sm p-3 overflow-auto"
        style={{ backgroundColor: "#050609", minHeight: 180 }}
      >
        <MarkdownPreview content={normalizedContent} />
      </div>
    );
  }

  return (
    <div
      className="rounded-sm overflow-hidden"
      style={{ backgroundColor: "#050609", minHeight: 180 }}
    >
      <CodeMirrorPreview
        content={normalizedContent}
        filePath={filePath}
        fileType={fileType}
      />
    </div>
  );
}
