import { useRef, useEffect, useMemo } from "react";
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightSpecialChars, drawSelection, rectangularSelection, highlightActiveLineGutter, type ViewUpdate } from "@codemirror/view";
import { EditorState, type Extension } from "@codemirror/state";
import { yaml } from "@codemirror/lang-yaml";
import { json } from "@codemirror/lang-json";
import { syntaxHighlighting, HighlightStyle, foldGutter, bracketMatching, indentOnInput, foldKeymap } from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { defaultKeymap, historyKeymap, history } from "@codemirror/commands";
import { lintGutter, type Diagnostic, setDiagnostics } from "@codemirror/lint";
import { autocompletion, closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
import { cn } from "@/lib/utils";
import { policyYamlCompletionSource } from "@/lib/workbench/yaml-schema";
import { sigmaYamlCompletionSource } from "@/lib/workbench/sigma-schema";
import { ocsfJsonCompletionSource } from "@/lib/workbench/ocsf-schema";
import { yaraLanguage } from "@/lib/workbench/yara-language";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { useGeneralSettings, type FontSize } from "@/lib/workbench/use-general-settings";

// ---- Types ----

export interface YamlEditorError {
  line?: number;
  message: string;
}

export interface YamlEditorProps {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  errors?: YamlEditorError[];
  className?: string;
  fileType?: FileType;
}

// ---- ClawdStrike brand theme ----

const FONT_SIZE_MAP: Record<FontSize, string> = {
  small: "11.5px",
  medium: "12.5px",
  large: "14px",
};

function createClawdTheme(fontSize: FontSize) {
  return EditorView.theme(
  {
    "&": {
      backgroundColor: "#0b0d13",
      color: "#ece7dc",
      fontSize: FONT_SIZE_MAP[fontSize],
      fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
      height: "100%",
    },
    "&.cm-focused": {
      outline: "none",
    },
    ".cm-scroller": {
      overflow: "auto",
      lineHeight: "1.6",
    },
    ".cm-content": {
      caretColor: "#d4a84b",
      padding: "8px 0",
    },
    ".cm-cursor, .cm-dropCursor": {
      borderLeftColor: "#d4a84b",
      borderLeftWidth: "2px",
    },
    ".cm-selectionBackground": {
      backgroundColor: "#2d324060 !important",
    },
    "&.cm-focused .cm-selectionBackground": {
      backgroundColor: "#2d324080 !important",
    },
    ".cm-activeLine": {
      backgroundColor: "#131721",
    },
    ".cm-activeLineGutter": {
      backgroundColor: "#131721",
    },
    ".cm-gutters": {
      backgroundColor: "#0b0d13",
      color: "#6f7f9a",
      border: "none",
      borderRight: "1px solid #2d3240",
    },
    ".cm-lineNumbers .cm-gutterElement": {
      padding: "0 8px 0 16px",
      minWidth: "40px",
      fontSize: "11px",
    },
    ".cm-foldGutter .cm-gutterElement": {
      padding: "0 4px",
      cursor: "pointer",
      color: "#6f7f9a",
      fontSize: "11px",
    },
    ".cm-foldGutter .cm-gutterElement:hover": {
      color: "#d4a84b",
    },
    // Lint gutter (error dots)
    ".cm-lint-marker-error": {
      content: '""',
      width: "8px",
      height: "8px",
      borderRadius: "50%",
      backgroundColor: "#c45c5c",
      display: "inline-block",
    },
    ".cm-lint-marker-warning": {
      content: '""',
      width: "8px",
      height: "8px",
      borderRadius: "50%",
      backgroundColor: "#d4a84b",
      display: "inline-block",
    },
    // Diagnostic tooltips
    ".cm-tooltip": {
      backgroundColor: "#131721",
      border: "1px solid #2d3240",
      color: "#ece7dc",
      borderRadius: "4px",
      fontSize: "11px",
    },
    ".cm-tooltip-lint": {
      backgroundColor: "#131721",
    },
    ".cm-diagnostic-error": {
      borderLeft: "3px solid #c45c5c",
      padding: "4px 8px",
      color: "#ece7dc",
    },
    ".cm-diagnostic-warning": {
      borderLeft: "3px solid #d4a84b",
      padding: "4px 8px",
      color: "#ece7dc",
    },
    // Search panel
    ".cm-panels": {
      backgroundColor: "#131721",
      color: "#ece7dc",
      borderBottom: "1px solid #2d3240",
    },
    ".cm-searchMatch": {
      backgroundColor: "#d4a84b30",
      outline: "1px solid #d4a84b50",
    },
    ".cm-searchMatch.cm-searchMatch-selected": {
      backgroundColor: "#d4a84b50",
    },
    ".cm-panel input": {
      backgroundColor: "#0b0d13",
      color: "#ece7dc",
      border: "1px solid #2d3240",
      borderRadius: "3px",
      padding: "2px 6px",
      fontSize: "12px",
      outline: "none",
    },
    ".cm-panel input:focus": {
      borderColor: "#d4a84b",
    },
    ".cm-panel button": {
      backgroundColor: "#2d3240",
      color: "#ece7dc",
      border: "none",
      borderRadius: "3px",
      padding: "2px 8px",
      cursor: "pointer",
      fontSize: "11px",
    },
    ".cm-panel button:hover": {
      backgroundColor: "#3d4250",
    },
    ".cm-panel label": {
      fontSize: "11px",
      color: "#6f7f9a",
    },
    // Matching brackets
    ".cm-matchingBracket": {
      backgroundColor: "#d4a84b20",
      outline: "1px solid #d4a84b40",
      color: "#d4a84b",
    },
    // Autocomplete tooltip
    ".cm-tooltip-autocomplete": {
      backgroundColor: "#131721",
      border: "1px solid #2d3240",
      borderRadius: "4px",
      overflow: "hidden",
    },
    ".cm-tooltip-autocomplete ul": {
      fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
      fontSize: "12px",
    },
    ".cm-tooltip-autocomplete ul li": {
      padding: "2px 8px",
      color: "#ece7dc",
    },
    ".cm-tooltip-autocomplete ul li[aria-selected]": {
      backgroundColor: "#2d3240",
      color: "#ece7dc",
    },
    ".cm-completionLabel": {
      color: "#d4a84b",
    },
    ".cm-completionDetail": {
      color: "#6f7f9a",
      fontStyle: "italic",
      marginLeft: "8px",
    },
    ".cm-completionMatchedText": {
      textDecoration: "none",
      color: "#3dbf84",
      fontWeight: "bold",
    },
    ".cm-completionIcon": {
      padding: "0 4px 0 0",
      opacity: "0.7",
    },
    // Scrollbar styling
    ".cm-scroller::-webkit-scrollbar": {
      width: "8px",
      height: "8px",
    },
    ".cm-scroller::-webkit-scrollbar-track": {
      backgroundColor: "#0b0d13",
    },
    ".cm-scroller::-webkit-scrollbar-thumb": {
      backgroundColor: "#2d3240",
      borderRadius: "4px",
      border: "2px solid #0b0d13",
    },
    ".cm-scroller::-webkit-scrollbar-thumb:hover": {
      backgroundColor: "#3d4250",
    },
    ".cm-scroller::-webkit-scrollbar-corner": {
      backgroundColor: "#0b0d13",
    },
  },
  { dark: true }
  );
}

// Syntax highlighting colors
const clawdHighlightStyle = HighlightStyle.define([
  // YAML keys (property names) - gold
  { tag: tags.propertyName, color: "#d4a84b" },
  { tag: tags.definition(tags.propertyName), color: "#d4a84b" },
  // Strings - green
  { tag: tags.string, color: "#3dbf84" },
  // Numbers - steel
  { tag: tags.number, color: "#6f7f9a" },
  { tag: tags.integer, color: "#6f7f9a" },
  { tag: tags.float, color: "#6f7f9a" },
  // Booleans and null - muted gold
  { tag: tags.bool, color: "#d4a84b", fontStyle: "italic" },
  { tag: tags.null, color: "#6f7f9a", fontStyle: "italic" },
  // Comments - steel with transparency
  { tag: tags.comment, color: "#6f7f9a80", fontStyle: "italic" },
  { tag: tags.lineComment, color: "#6f7f9a80", fontStyle: "italic" },
  { tag: tags.blockComment, color: "#6f7f9a80", fontStyle: "italic" },
  // Keywords
  { tag: tags.keyword, color: "#d4a84b" },
  // Operators (: and -)
  { tag: tags.operator, color: "#6f7f9a" },
  { tag: tags.punctuation, color: "#6f7f9a" },
  // Atoms (true/false/null in some contexts)
  { tag: tags.atom, color: "#d4a84b", fontStyle: "italic" },
  // Meta / document markers (---)
  { tag: tags.meta, color: "#6f7f9a" },
]);

// ---- Language & completion helpers ----

function getLanguageExtension(fileType?: FileType): Extension {
  switch (fileType) {
    case "yara_rule":
      return yaraLanguage;
    case "ocsf_event":
      return json();
    case "sigma_rule":
      // Sigma is YAML - same language, different completions (Phase 1)
      return yaml();
    case "clawdstrike_policy":
    default:
      return yaml();
  }
}

function getCompletionSource(fileType?: FileType): Extension {
  switch (fileType) {
    case "sigma_rule":
      return autocompletion({
        override: [sigmaYamlCompletionSource],
        icons: false,
      });
    case "yara_rule":
      // Phase 3 TODO: yaraCompletionSource
      return autocompletion({ override: [] });
    case "ocsf_event":
      return autocompletion({
        override: [ocsfJsonCompletionSource],
        icons: false,
      });
    case "clawdstrike_policy":
    default:
      return autocompletion({
        override: [policyYamlCompletionSource],
        icons: false,
      });
  }
}

// ---- Component ----

export function YamlEditor({
  value,
  onChange,
  readOnly = false,
  errors = [],
  className,
  fileType,
}: YamlEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  // Keep a ref to the latest onChange so we don't have to reconfigure on every render
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  // Read general settings for editor customization
  const { settings: generalSettings } = useGeneralSettings();
  const { fontSize, showLineNumbers } = generalSettings;

  // Build the list of extensions (rebuilds when readOnly, fontSize, or showLineNumbers changes)
  const extensions = useMemo<Extension[]>(() => {
    const base: Extension[] = [
      getLanguageExtension(fileType),
      createClawdTheme(fontSize),
      syntaxHighlighting(clawdHighlightStyle),
      highlightActiveLine(),
      highlightSpecialChars(),
      drawSelection(),
      rectangularSelection(),
      bracketMatching(),
      indentOnInput(),
      highlightSelectionMatches(),
      foldGutter({
        openText: "\u25BE",
        closedText: "\u25B8",
      }),
      lintGutter(),
      history(),
      getCompletionSource(fileType),
      closeBrackets(),
      keymap.of([
        ...defaultKeymap,
        ...historyKeymap,
        ...foldKeymap,
        ...searchKeymap,
        ...closeBracketsKeymap,
      ]),
    ];

    if (showLineNumbers) {
      base.push(lineNumbers());
      base.push(highlightActiveLineGutter());
    }

    if (readOnly) {
      base.push(EditorState.readOnly.of(true));
      base.push(EditorView.editable.of(false));
    } else {
      // Emit changes
      base.push(
        EditorView.updateListener.of((update: ViewUpdate) => {
          if (update.docChanged) {
            onChangeRef.current(update.state.doc.toString());
          }
        })
      );
    }

    return base;
  }, [readOnly, fontSize, showLineNumbers, fileType]);

  // Create / destroy the editor view
  useEffect(() => {
    if (!containerRef.current) return;

    const state = EditorState.create({
      doc: value,
      extensions,
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // We intentionally only create the view once per readOnly change.
    // Value syncing is handled separately below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [extensions]);

  // Sync external value changes into the editor (e.g. when visual panel edits arrive)
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;

    const currentDoc = view.state.doc.toString();
    if (currentDoc !== value) {
      view.dispatch({
        changes: {
          from: 0,
          to: currentDoc.length,
          insert: value,
        },
        // Don't move the cursor if the user is actively editing
        selection: view.hasFocus ? undefined : { anchor: 0 },
      });
    }
  }, [value]);

  // Sync error diagnostics into the editor
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;

    const diagnostics: Diagnostic[] = [];
    for (const err of errors) {
      if (err.line != null && err.line >= 1) {
        // Map line number to document position
        const lineCount = view.state.doc.lines;
        const lineNum = Math.min(err.line, lineCount);
        const line = view.state.doc.line(lineNum);
        diagnostics.push({
          from: line.from,
          to: line.to,
          severity: "error",
          message: err.message,
        });
      } else {
        // No line number - attach to line 1
        const line = view.state.doc.line(1);
        diagnostics.push({
          from: line.from,
          to: line.to,
          severity: "error",
          message: err.message,
        });
      }
    }

    view.dispatch(setDiagnostics(view.state, diagnostics));
  }, [errors]);

  return (
    <div
      ref={containerRef}
      className={cn("h-full w-full overflow-hidden", className)}
    />
  );
}
