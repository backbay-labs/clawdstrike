import { useCallback, useMemo, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { IconCopy, IconCheck } from "@tabler/icons-react";
import { yamlToPolicy, policyToJson, policyToToml, type ExportFormat } from "@/features/policy/yaml-utils";
import { cn } from "@/lib/utils";

interface YamlViewDialogProps {
  open: boolean;
  onClose: () => void;
  name: string;
  yaml: string;
}

const FORMAT_TABS: { value: ExportFormat; label: string }[] = [
  { value: "yaml", label: "YAML" },
  { value: "json", label: "JSON" },
  { value: "toml", label: "TOML" },
];

export function YamlViewDialog({ open, onClose, name, yaml }: YamlViewDialogProps) {
  const [copied, setCopied] = useState(false);
  const [activeFormat, setActiveFormat] = useState<ExportFormat>("yaml");

  // Convert YAML to JSON/TOML on demand
  const formattedContent = useMemo(() => {
    if (activeFormat === "yaml") return yaml;

    const [policy] = yamlToPolicy(yaml);
    if (!policy) return `// Failed to parse YAML for ${activeFormat.toUpperCase()} conversion`;

    if (activeFormat === "json") return policyToJson(policy);
    if (activeFormat === "toml") return policyToToml(policy);
    return yaml;
  }, [yaml, activeFormat]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(formattedContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [formattedContent]);

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="bg-[#0b0d13] border border-[#2d3240] sm:max-w-2xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="text-[#ece7dc] flex items-center justify-between">
            <span>{name}</span>
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={handleCopy}
              className="text-[#6f7f9a] hover:text-[#ece7dc]"
            >
              {copied ? (
                <IconCheck size={14} stroke={1.5} className="text-[#3dbf84]" />
              ) : (
                <IconCopy size={14} stroke={1.5} />
              )}
            </Button>
          </DialogTitle>
        </DialogHeader>

        {/* Format tabs */}
        <div className="flex items-center gap-1 border-b border-[#2d3240] pb-2">
          {FORMAT_TABS.map((tab) => (
            <button
              key={tab.value}
              onClick={() => setActiveFormat(tab.value)}
              className={cn(
                "px-3 py-1 text-xs font-medium rounded-md transition-colors",
                activeFormat === tab.value
                  ? "bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent"
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <pre className="flex-1 overflow-auto text-xs font-mono text-[#ece7dc]/80 bg-[#131721] border border-[#2d3240] rounded-lg p-4 whitespace-pre-wrap">
          {formattedContent}
        </pre>
      </DialogContent>
    </Dialog>
  );
}
