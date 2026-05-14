"use client";

import { useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { Section, FieldLabel, TextInput, TextArea } from "./detection-panel-kit";
import type { DetectionVisualPanelProps } from "@/lib/workbench/detection-workflow/shared-types";
import { registerVisualPanel } from "@/lib/workbench/detection-workflow/visual-panels";
import {
  parseSplPipeChain,
  type SplCommand,
} from "@/lib/workbench/detection-workflow/spl-parser";
import { IconTerminal, IconFilter } from "@tabler/icons-react";


/** Default accent color for SPL panels (Splunk green). */
const DEFAULT_ACCENT = "#65a637";


interface SplCommentMeta {
  title: string;
  author: string;
  description: string;
  rawBlock: string;
}

/**
 * Extract metadata from leading comment lines (lines starting with `//` or `#`).
 */
function parseCommentBlock(source: string): SplCommentMeta {
  const lines = source.split(/\r?\n/);
  const commentLines: string[] = [];

  for (const line of lines) {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("//") || trimmed.startsWith("#")) {
      commentLines.push(line);
    } else if (trimmed === "") {
      // Allow blank lines at the top
      commentLines.push(line);
    } else {
      break;
    }
  }

  let title = "";
  let author = "";
  let description = "";

  for (const line of commentLines) {
    const stripped = line.replace(/^\s*(?:\/\/|#)\s*/, "");

    const titleMatch = stripped.match(/^(?:Detection|Title):\s*(.+)/i);
    if (titleMatch) {
      title = titleMatch[1].trim();
      continue;
    }

    const authorMatch = stripped.match(/^Author:\s*(.+)/i);
    if (authorMatch) {
      author = authorMatch[1].trim();
      continue;
    }

    const descMatch = stripped.match(/^Description:\s*(.+)/i);
    if (descMatch) {
      description = descMatch[1].trim();
      continue;
    }
  }

  return {
    title,
    author,
    description,
    rawBlock: commentLines.join("\n"),
  };
}

/**
 * Rebuild the comment block with updated metadata values.
 */
function rebuildCommentBlock(meta: SplCommentMeta): string {
  const parts: string[] = [];
  if (meta.title) parts.push(`// Detection: ${meta.title}`);
  if (meta.author) parts.push(`// Author: ${meta.author}`);
  if (meta.description) parts.push(`// Description: ${meta.description}`);
  return parts.join("\n");
}


interface FieldValuePair {
  field: string;
  value: string;
  /** Original text fragment for this pair (for replacement). */
  originalFragment: string;
}

/**
 * Parse `field=value` or `field="value"` pairs from command args text.
 */
function parseFieldValuePairs(args: string): FieldValuePair[] {
  const pairs: FieldValuePair[] = [];
  const re = /(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(args)) !== null) {
    const field = m[1];
    let value = m[2];

    // Skip SPL keywords that look like field=value
    const lower = field.toLowerCase();
    if (
      lower === "index" ||
      lower === "sourcetype" ||
      lower === "source" ||
      lower === "host" ||
      lower === "eventtype"
    ) {
      continue;
    }

    // Remove surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    pairs.push({
      field,
      value,
      originalFragment: m[0],
    });
  }
  return pairs;
}


/**
 * Strip comment lines from source to get the query portion.
 */
function getQueryPortion(source: string): string {
  const lines = source.split(/\r?\n/);
  const nonComment: string[] = [];
  let passedComments = false;

  for (const line of lines) {
    const trimmed = line.trimStart();
    if (!passedComments && (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed === "")) {
      continue;
    }
    passedComments = true;
    nonComment.push(line);
  }
  return nonComment.join("\n");
}

/**
 * Reconstruct SPL source from commands and a comment block.
 */
function reconstructSplFromCommands(
  commands: SplCommand[],
  commentBlock: string,
): string {
  if (commands.length === 0) {
    return commentBlock;
  }

  const queryParts: string[] = [];
  for (let i = 0; i < commands.length; i++) {
    if (i === 0) {
      queryParts.push(commands[i].rawText);
    } else {
      queryParts.push(`| ${commands[i].rawText}`);
    }
  }

  const queryStr = queryParts.join("\n");
  if (commentBlock.trim()) {
    return `${commentBlock}\n${queryStr}`;
  }
  return queryStr;
}


function EditableFieldRow({
  field,
  value,
  readOnly,
  accentColor,
  onChange,
}: {
  field: string;
  value: string;
  readOnly?: boolean;
  accentColor: string;
  onChange: (newValue: string) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[#6f7f9a] font-mono text-xs w-32 shrink-0 truncate" title={field}>
        {field}
      </span>
      <TextInput
        label=""
        value={value}
        onChange={onChange}
        readOnly={readOnly}
        mono
        accentColor={accentColor}
      />
    </div>
  );
}


function CommandCard({
  command,
  commandIndex,
  accentColor,
  readOnly,
  onUpdateCommand,
}: {
  command: SplCommand;
  commandIndex: number;
  accentColor: string;
  readOnly?: boolean;
  onUpdateCommand: (index: number, updatedRawText: string) => void;
}) {
  const isEditable = command.command === "search" || command.command === "where";
  const fieldPairs = useMemo(
    () => (isEditable ? parseFieldValuePairs(command.args) : []),
    [isEditable, command.args],
  );

  const handleFieldChange = useCallback(
    (pairIndex: number, newValue: string) => {
      const pair = fieldPairs[pairIndex];
      if (!pair) return;

      // Reconstruct the field=value with proper quoting
      const needsQuotes = newValue.includes(" ") || newValue.includes("*") || newValue.includes('"');
      const quotedValue = needsQuotes ? `"${newValue.replace(/"/g, '\\"')}"` : `"${newValue}"`;
      const newFragment = `${pair.field}=${quotedValue}`;

      // Replace the original fragment in rawText
      const updatedRaw = command.rawText.replace(pair.originalFragment, newFragment);
      onUpdateCommand(commandIndex, updatedRaw);
    },
    [command.rawText, commandIndex, fieldPairs, onUpdateCommand],
  );

  return (
    <div
      className="bg-[#252538] border-l-2 rounded-r-md px-3 py-2 mb-1"
      style={{ borderLeftColor: accentColor }}
    >
      {/* Command name header */}
      <div className="flex items-center gap-2 mb-1">
        <span
          className="text-xs font-bold font-mono uppercase tracking-wider"
          style={{ color: accentColor }}
        >
          {command.command}
        </span>
      </div>

      {/* Editable field-value pairs for search/where */}
      {isEditable && fieldPairs.length > 0 ? (
        <div className="flex flex-col gap-1.5 mt-1">
          {fieldPairs.map((pair, i) => (
            <EditableFieldRow
              key={`${pair.field}-${i}`}
              field={pair.field}
              value={pair.value}
              readOnly={readOnly}
              accentColor={accentColor}
              onChange={(newVal) => handleFieldChange(i, newVal)}
            />
          ))}
          {/* Show any remaining args text that was not parsed as field=value */}
        </div>
      ) : (
        /* Non-editable: show args as monospace text */
        <div className="text-[11px] font-mono text-[#ece7dc]/70 whitespace-pre-wrap break-all">
          {command.args || "(no arguments)"}
        </div>
      )}
    </div>
  );
}


function PipeConnector() {
  return (
    <div className="text-[#6f7f9a] text-xs font-mono text-center py-0.5 opacity-50">
      |
    </div>
  );
}


export function SplVisualPanel(props: DetectionVisualPanelProps) {
  const { source, onSourceChange, readOnly, accentColor } = props;
  const ACCENT = accentColor ?? DEFAULT_ACCENT;

  // Parse comment metadata
  const meta = useMemo(() => parseCommentBlock(source), [source]);

  // Parse pipe chain
  const commands = useMemo(() => parseSplPipeChain(source), [source]);

  // Get the comment block for reconstruction
  const commentBlock = useMemo(() => meta.rawBlock, [meta.rawBlock]);

  // Update comment metadata
  const updateMeta = useCallback(
    (field: keyof SplCommentMeta, value: string) => {
      const updated = { ...meta, [field]: value };
      const newCommentBlock = rebuildCommentBlock(updated);
      const queryPortion = getQueryPortion(source);
      if (queryPortion.trim()) {
        onSourceChange(`${newCommentBlock}\n${queryPortion}`);
      } else {
        onSourceChange(newCommentBlock);
      }
    },
    [meta, source, onSourceChange],
  );

  // Handle command update from editable cards
  const handleUpdateCommand = useCallback(
    (index: number, updatedRawText: string) => {
      const updatedCommands = commands.map((cmd, i) =>
        i === index ? { ...cmd, rawText: updatedRawText } : cmd,
      );
      const rebuilt = reconstructSplFromCommands(updatedCommands, commentBlock);
      onSourceChange(rebuilt);
    },
    [commands, commentBlock, onSourceChange],
  );

  // Empty state
  if (!source.trim() || commands.length === 0) {
    return (
      <ScrollArea className="h-full">
        <div className="flex flex-col pb-6">
          <div className="flex items-center gap-2 px-4 pt-3 pb-1">
            <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>
              SPL
            </span>
            <span className="text-[10px] font-mono text-[#6f7f9a]">Splunk SPL Query</span>
          </div>
          <div className="mx-4 mt-6 text-[11px] font-mono text-[#6f7f9a]/50 italic text-center py-8">
            Enter SPL query to see the pipe chain visualization.
          </div>
        </div>
      </ScrollArea>
    );
  }

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col pb-6">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>
            SPL
          </span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">Splunk SPL Query</span>
        </div>

        {/* Command count badge */}
        <div className="flex items-center gap-2 px-4 pt-2 pb-0">
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
            style={{
              color: ACCENT,
              borderColor: `${ACCENT}30`,
              backgroundColor: `${ACCENT}08`,
            }}
          >
            {commands.length} command{commands.length !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Section 1: Header metadata (from comments) */}
        {(meta.title || meta.author || meta.description) && (
          <Section title="Header" icon={IconTerminal} accentColor={ACCENT}>
            <TextInput
              label="Title"
              value={meta.title}
              onChange={(v) => updateMeta("title", v)}
              readOnly={readOnly}
              accentColor={ACCENT}
            />
            <TextInput
              label="Author"
              value={meta.author}
              onChange={(v) => updateMeta("author", v)}
              readOnly={readOnly}
              accentColor={ACCENT}
            />
            {meta.description && (
              <TextArea
                label="Description"
                value={meta.description}
                onChange={(v) => updateMeta("description", v)}
                readOnly={readOnly}
                accentColor={ACCENT}
              />
            )}
          </Section>
        )}

        {/* Section 2: Pipe Chain */}
        <Section title="Pipe Chain" icon={IconFilter} accentColor={ACCENT} defaultOpen>
          <div className="flex flex-col">
            {commands.map((cmd, i) => (
              <div key={i}>
                {i > 0 && <PipeConnector />}
                <CommandCard
                  command={cmd}
                  commandIndex={i}
                  accentColor={ACCENT}
                  readOnly={readOnly}
                  onUpdateCommand={handleUpdateCommand}
                />
              </div>
            ))}
          </div>
        </Section>
      </div>
    </ScrollArea>
  );
}

registerVisualPanel("splunk_spl", SplVisualPanel);
