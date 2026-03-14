import { useState, useRef, useEffect } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { isDesktop, pickSavePath } from "@/lib/tauri-bridge";
import { exportPolicyFileNative } from "@/lib/tauri-commands";
import { policyToFormat, formatExtension, formatMimeType, type ExportFormat } from "@/lib/workbench/yaml-utils";
import { emitAuditEvent } from "@/lib/workbench/local-audit";
import {
  IconFilePlus,
  IconFolderOpen,
  IconDeviceFloppy,
  IconFileExport,
  IconArrowBackUp,
  IconArrowForwardUp,
} from "@tabler/icons-react";

const btnBase =
  "px-3 py-1.5 text-xs font-medium text-[#ece7dc]/90 bg-[#131721] border border-[#2d3240]/70 rounded-md hover:border-[#2d3240] hover:bg-[#1a1f2e] hover:text-[#ece7dc] transition-all duration-150 inline-flex items-center gap-1.5";

const btnIcon =
  "p-1.5 text-[#ece7dc]/70 bg-[#131721] border border-[#2d3240]/70 rounded-md hover:border-[#2d3240] hover:bg-[#1a1f2e] hover:text-[#ece7dc] transition-all duration-150 inline-flex items-center justify-center disabled:opacity-25 disabled:pointer-events-none";

const FORMAT_OPTIONS: { value: ExportFormat; label: string }[] = [
  { value: "yaml", label: "YAML" },
  { value: "json", label: "JSON" },
  { value: "toml", label: "TOML" },
];

export function WorkbenchTopbar() {
  const {
    state,
    dispatch,
    saveCurrentPolicy,
    exportYaml,
    copyYaml,
    openFile,
    saveFile,
    saveFileAs,
    newPolicy,
    undo,
    redo,
    canUndo,
    canRedo,
  } = useWorkbench();
  const { toast } = useToast();
  const { activePolicy, validation } = state;

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(activePolicy.name);
  const [exportFormat, setExportFormat] = useState<ExportFormat>("yaml");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editing]);

  // Keep draft in sync when policy name changes externally
  useEffect(() => {
    if (!editing) {
      setDraft(activePolicy.name);
    }
  }, [activePolicy.name, editing]);

  function commitName() {
    const trimmed = draft.trim();
    if (trimmed && trimmed !== activePolicy.name) {
      dispatch({ type: "UPDATE_META", name: trimmed });
    } else {
      setDraft(activePolicy.name);
    }
    setEditing(false);
  }

    const errorCount = validation.errors.length;
  const warningCount = validation.warnings.length;

  let statusLabel: string;
  let statusColor: string;
  if (errorCount > 0) {
    statusLabel = `${errorCount} error${errorCount > 1 ? "s" : ""}`;
    statusColor = "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20";
  } else if (warningCount > 0) {
    statusLabel = `${warningCount} warning${warningCount > 1 ? "s" : ""}`;
    statusColor = "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20";
  } else {
    statusLabel = "Valid";
    statusColor = "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20";
  }

  // Emit audit event when validation state changes (debounced to avoid spamming)
  const prevValidationRef = useRef<string | null>(null);
  useEffect(() => {
    const key = `${errorCount}:${warningCount}:${activePolicy.name}`;
    const isFirstRender = prevValidationRef.current === null;
    if (prevValidationRef.current === key) return;
    prevValidationRef.current = key;
    // Skip the initial render — only emit on subsequent changes
    if (isFirstRender) return;
    const timer = setTimeout(() => {
      if (errorCount > 0) {
        emitAuditEvent({
          eventType: "policy.validation.failure",
          source: "editor",
          summary: `Policy "${activePolicy.name}" has ${errorCount} error(s)`,
          details: { policyName: activePolicy.name, errors: errorCount, warnings: warningCount },
        });
      } else if (warningCount > 0) {
        emitAuditEvent({
          eventType: "policy.validation.warnings",
          source: "editor",
          summary: `Policy "${activePolicy.name}" valid with ${warningCount} warning(s)`,
          details: { policyName: activePolicy.name, warnings: warningCount },
        });
      } else {
        emitAuditEvent({
          eventType: "policy.validation.success",
          source: "editor",
          summary: `Policy "${activePolicy.name}" is valid`,
          details: { policyName: activePolicy.name },
        });
      }
    }, 1500);
    return () => clearTimeout(timer);
  }, [errorCount, warningCount, activePolicy.name]);

  const desktop = isDesktop();

  /** Export in the selected format (browser download or native dialog). */
  async function handleExport() {
    if (desktop) {
      if (exportFormat === "yaml") {
        await saveFileAs();
        return;
      }

      const content = policyToFormat(state.activePolicy, exportFormat);
      const ext = formatExtension(exportFormat);
      // Pick a save path first (dialog only, no write yet)
      const targetPath = await pickSavePath(ext);
      if (targetPath) {
        // Try native validate-then-write (validates before writing to disk)
        const nativeResult = await exportPolicyFileNative(content, targetPath, exportFormat);
        if (nativeResult) {
          if (nativeResult.success) {
            toast({ type: "success", title: `${exportFormat.toUpperCase()} exported` });
            emitAuditEvent({
              eventType: "policy.export",
              source: "editor",
              summary: `Exported "${activePolicy.name}" as ${exportFormat.toUpperCase()} to ${nativeResult.path}`,
              details: { format: exportFormat, path: nativeResult.path, policyName: activePolicy.name },
            });
          } else {
            toast({ type: "error", title: "Validation failed", description: nativeResult.message });
          }
        } else {
          toast({
            type: "error",
            title: "Export failed",
            description: "Native export command unavailable.",
          });
        }
      }
    } else {
      if (exportFormat === "yaml") {
        exportYaml();
      } else {
        const content = policyToFormat(state.activePolicy, exportFormat);
        const ext = formatExtension(exportFormat);
        const mime = formatMimeType(exportFormat);
        const blob = new Blob([content], { type: mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${activePolicy.name || "policy"}.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
      }
      const label = exportFormat.toUpperCase();
      toast({ type: "success", title: `${label} exported` });
      emitAuditEvent({
        eventType: "policy.export",
        source: "editor",
        summary: `Exported "${activePolicy.name}" as ${label}`,
        details: { format: exportFormat, policyName: activePolicy.name },
      });
    }
  }

  return (
    <header className="flex items-center justify-between h-14 px-4 bg-[#05060a] border-b border-[#2d3240]/60 shrink-0">
      {/* Left: policy name + badges */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Editable policy name */}
        {editing ? (
          <input
            ref={inputRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={commitName}
            onKeyDown={(e) => {
              if (e.key === "Enter") commitName();
              if (e.key === "Escape") {
                setDraft(activePolicy.name);
                setEditing(false);
              }
            }}
            className="font-syne font-semibold text-sm text-[#ece7dc] bg-[#131721] border border-[#2d3240] rounded px-2 py-1 outline-none focus:border-[#d4a84b] min-w-[120px]"
          />
        ) : (
          <button
            onClick={() => setEditing(true)}
            className="font-syne font-semibold text-sm text-[#ece7dc] hover:text-[#d4a84b] transition-colors truncate max-w-[200px]"
            title="Click to rename"
          >
            {activePolicy.name}
          </button>
        )}

        {/* Schema version badge */}
        <span className="shrink-0 px-2 py-0.5 text-[10px] font-mono text-[#6f7f9a] border border-[#2d3240] rounded-md bg-[#131721]">
          v{activePolicy.version}
        </span>

        {/* Validation status pill */}
        <span
          className={cn(
            "shrink-0 px-2 py-0.5 text-[10px] font-mono uppercase border rounded-md",
            statusColor
          )}
        >
          {statusLabel}
        </span>
      </div>

      {/* Right: action buttons */}
      <div className="flex items-center gap-2">
        {/* Undo / Redo */}
        <div className="flex items-center gap-0.5 mr-1">
          <button
            onClick={undo}
            disabled={!canUndo}
            className={btnIcon}
            title="Undo (Cmd+Z)"
          >
            <IconArrowBackUp size={14} />
          </button>
          <button
            onClick={redo}
            disabled={!canRedo}
            className={btnIcon}
            title="Redo (Cmd+Shift+Z)"
          >
            <IconArrowForwardUp size={14} />
          </button>
        </div>

        {/* New Policy */}
        <button
          onClick={newPolicy}
          className={btnBase}
          title="New policy"
        >
          <IconFilePlus size={14} />
          New
        </button>

        {/* Open (desktop only) */}
        {desktop && (
          <button
            onClick={openFile}
            className={btnBase}
            title="Open policy file"
          >
            <IconFolderOpen size={14} />
            Open
          </button>
        )}

        {/* Save */}
        <button
          onClick={async () => {
            if (desktop) {
              await saveFile();
            } else {
              saveCurrentPolicy();
            }
            toast({ type: "success", title: "Policy saved" });
          }}
          className={btnBase}
          title={desktop && state.filePath ? `Save to ${state.filePath}` : "Save policy"}
        >
          <IconDeviceFloppy size={14} />
          Save
        </button>

        {/* Export / Save As with format selector */}
        <div className="flex items-center gap-1.5">
          <Select value={exportFormat} onValueChange={(v) => { if (v !== null) setExportFormat(v as ExportFormat); }}>
            <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc]" title="Export format">
              <SelectValue placeholder="Format" />
            </SelectTrigger>
            <SelectContent className="bg-[#131721] border-[#2d3240]">
              {FORMAT_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value} className="text-xs text-[#ece7dc]">
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <button
            onClick={handleExport}
            className="h-[30px] px-3 py-1.5 text-xs font-medium text-[#ece7dc]/90 bg-[#131721] border border-[#2d3240]/70 rounded-md hover:border-[#2d3240] hover:bg-[#1a1f2e] hover:text-[#ece7dc] transition-all duration-150 inline-flex items-center gap-1.5"
            title={desktop ? "Save As..." : `Export ${exportFormat.toUpperCase()} file`}
          >
            <IconFileExport size={14} />
            {desktop ? "Save As" : "Export"}
          </button>
        </div>

        {/* Copy */}
        <button
          onClick={() => {
            copyYaml();
            toast({ type: "info", title: "YAML copied to clipboard" });
          }}
          className={btnBase}
        >
          Copy
        </button>
      </div>
    </header>
  );
}
