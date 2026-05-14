import { useCallback, useRef, useState } from "react";
import { useWorkbenchState } from "@/features/policy/hooks/use-policy-actions";
import { useToast } from "@/components/ui/toast";
import { yamlToPolicy, policyToFormat, formatExtension, formatMimeType, type ExportFormat } from "@/features/policy/yaml-utils";
import { emitAuditEvent } from "@/lib/workbench/local-audit";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { IconUpload, IconDownload, IconClipboard } from "@tabler/icons-react";

const FORMAT_OPTIONS: { value: ExportFormat; label: string }[] = [
  { value: "yaml", label: "YAML" },
  { value: "json", label: "JSON" },
  { value: "toml", label: "TOML" },
];

export function ImportExport() {
  const { state, loadPolicy, exportYaml } = useWorkbenchState();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [pasteYaml, setPasteYaml] = useState("");
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [pasteDialogOpen, setPasteDialogOpen] = useState(false);
  const [exportFormat, setExportFormat] = useState<ExportFormat>("yaml");

  const handleFileUpload = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (evt) => {
        const text = evt.target?.result as string;
        const [policy, errors] = yamlToPolicy(text);
        if (policy && errors.length === 0) {
          loadPolicy(policy);
          toast({ type: "success", title: "Policy imported", description: policy.name });
          emitAuditEvent({
            eventType: "policy.import.file",
            source: "editor",
            summary: `Imported policy "${policy.name}" from file`,
            details: { policyName: policy.name, version: policy.version },
          });
        } else {
          toast({
            type: "error",
            title: "Import failed",
            description: errors.join("; ") || "Invalid YAML",
          });
        }
      };
      reader.readAsText(file);

      // Reset file input so the same file can be re-selected
      e.target.value = "";
    },
    [loadPolicy, toast],
  );

  const handlePasteImport = useCallback(() => {
    setPasteError(null);
    const [policy, errors] = yamlToPolicy(pasteYaml);
    if (policy && errors.length === 0) {
      loadPolicy(policy);
      setPasteYaml("");
      setPasteDialogOpen(false);
      toast({ type: "success", title: "Policy imported", description: policy.name });
      emitAuditEvent({
        eventType: "policy.import.paste",
        source: "editor",
        summary: `Imported policy "${policy.name}" from paste`,
        details: { policyName: policy.name, version: policy.version },
      });
    } else {
      const msg = errors.join("; ") || "Invalid YAML";
      setPasteError(msg);
      toast({ type: "error", title: "Import failed", description: msg });
    }
  }, [pasteYaml, loadPolicy, toast]);

  const handleExport = useCallback(() => {
    if (exportFormat === "yaml") {
      // Use the existing YAML export path
      exportYaml();
    } else {
      const content = policyToFormat(state.activePolicy, exportFormat);
      const ext = formatExtension(exportFormat);
      const mime = formatMimeType(exportFormat);
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${state.activePolicy.name || "policy"}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    }
    const label = exportFormat.toUpperCase();
    toast({ type: "success", title: `${label} exported` });
    emitAuditEvent({
      eventType: "policy.export",
      source: "editor",
      summary: `Exported "${state.activePolicy.name}" as ${label}`,
      details: { format: exportFormat, policyName: state.activePolicy.name },
    });
  }, [exportFormat, exportYaml, state.activePolicy, toast]);

  return (
    <div className="flex items-center gap-2 shrink-0">
      {/* File upload */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".yaml,.yml"
        onChange={handleFileUpload}
        className="hidden"
      />
      <button
        onClick={() => fileInputRef.current?.click()}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#131721] border border-[#2d3240] text-[#6f7f9a] text-xs font-medium hover:text-[#ece7dc] transition-colors"
      >
        <IconUpload size={14} stroke={1.5} />
        Import File
      </button>

      {/* Paste YAML dialog */}
      <Dialog open={pasteDialogOpen} onOpenChange={setPasteDialogOpen}>
        <DialogTrigger
          render={
            <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#131721] border border-[#2d3240] text-[#6f7f9a] text-xs font-medium hover:text-[#ece7dc] transition-colors" />
          }
        >
          <IconClipboard size={14} stroke={1.5} />
          Paste YAML
        </DialogTrigger>
        <DialogContent className="bg-[#0b0d13] border border-[#2d3240] sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-[#ece7dc]">Import YAML</DialogTitle>
            <DialogDescription className="text-[#6f7f9a]">
              Paste a Clawdstrike policy YAML document below.
            </DialogDescription>
          </DialogHeader>
          <Textarea
            value={pasteYaml}
            onChange={(e) => {
              setPasteYaml(e.target.value);
              setPasteError(null);
            }}
            placeholder="version: '1.2.0'\nname: ...\nguards:\n  ..."
            rows={12}
            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs"
          />
          {pasteError && (
            <p className="text-xs text-[#c45c5c]">{pasteError}</p>
          )}
          <DialogFooter>
            <DialogClose render={<Button variant="ghost" className="text-[#6f7f9a]" />}>
              Cancel
            </DialogClose>
            <Button
              onClick={handlePasteImport}
              className="bg-[#d4a84b]/10 text-[#d4a84b] hover:bg-[#d4a84b]/20 border-[#d4a84b]/20"
            >
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Export format selector + export button */}
      <div className="flex items-center gap-1.5">
        <Select value={exportFormat} onValueChange={(v) => { if (v !== null) setExportFormat(v as ExportFormat); }}>
          <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc]">
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
          className="flex items-center gap-1.5 h-[30px] px-3 py-1.5 rounded-md bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-xs font-medium hover:bg-[#d4a84b]/20 transition-colors"
        >
          <IconDownload size={14} stroke={1.5} />
          Export
        </button>
      </div>
    </div>
  );
}
