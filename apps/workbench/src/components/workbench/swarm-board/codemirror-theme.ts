import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";

/**
 * Shared syntax-color palette for the workbench dark theme.
 * Consumed by both artifact-preview-pane (EditorView extension) and
 * diff-highlight (Lezer highlightCode tokenization).
 */
export const SYNTAX_COLORS = {
  keyword: "#7c9aef",
  string: "#38a876",
  number: "#d4a84b",
  comment: "#4a5568",
  bool: "#c49a3c",
  null_: "#b85450",
  property: "#9aa7bd",
  function_: "#d7c7a2",
} as const;

/**
 * Raw HighlightStyle instance -- usable with Lezer's `highlightCode` for
 * standalone tokenization (no EditorView required).
 */
export const diffHighlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: SYNTAX_COLORS.keyword },
  { tag: tags.string, color: SYNTAX_COLORS.string },
  { tag: tags.number, color: SYNTAX_COLORS.number },
  { tag: tags.comment, color: SYNTAX_COLORS.comment, fontStyle: "italic" },
  { tag: tags.bool, color: SYNTAX_COLORS.bool },
  { tag: tags.null, color: SYNTAX_COLORS.null_ },
  { tag: [tags.propertyName, tags.attributeName], color: SYNTAX_COLORS.property },
  { tag: [tags.function(tags.variableName), tags.className], color: SYNTAX_COLORS.function_ },
]);

/**
 * EditorView extension wrapping the shared style -- drop-in replacement for the
 * inline `previewHighlight` that was previously defined inside artifact-preview-pane.
 */
export const previewHighlightExtension = syntaxHighlighting(diffHighlightStyle);
