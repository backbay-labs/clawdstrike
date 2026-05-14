import { useState, useCallback } from "react";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { getDescriptor } from "@/lib/workbench/file-type-registry";
import type { TranslationResult } from "@/lib/workbench/detection-workflow/shared-types";
import { FieldMappingTable } from "./detection-panel-kit";
import { IconX, IconCopy, IconCheck } from "@tabler/icons-react";


interface TranslationResultsPanelProps {
  result: TranslationResult;
  sourceFileType: FileType;
  targetFileType: FileType;
  onClose: () => void;
}


function DiagnosticIcon({ severity }: { severity: "error" | "warning" | "info" }) {
  if (severity === "error") {
    return (
      <span className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full bg-[#ef4444]/20 flex-shrink-0">
        <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
      </span>
    );
  }
  if (severity === "warning") {
    return (
      <span className="inline-flex items-center justify-center w-3.5 h-3.5 flex-shrink-0">
        <span className="text-[#eab308] text-[10px] leading-none font-bold">&#x26A0;</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full bg-[#3b82f6]/20 flex-shrink-0">
      <span className="w-1.5 h-1.5 rounded-full bg-[#3b82f6]" />
    </span>
  );
}


function FormatDot({ fileType }: { fileType: FileType }) {
  try {
    const desc = getDescriptor(fileType);
    return (
      <span className="inline-flex items-center gap-1.5">
        <span
          className="inline-block w-2 h-2 rounded-full flex-shrink-0"
          style={{ backgroundColor: desc.iconColor }}
        />
        <span className="text-[10px] font-mono text-[#ece7dc]">{desc.shortLabel}</span>
      </span>
    );
  } catch {
    return <span className="text-[10px] font-mono text-[#6f7f9a]">{fileType}</span>;
  }
}


export function TranslationResultsPanel({
  result,
  sourceFileType,
  targetFileType,
  onClose,
}: TranslationResultsPanelProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    if (result.output) {
      navigator.clipboard.writeText(result.output).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  }, [result.output]);

  const hasFieldMappings = result.fieldMappings.length > 0;
  const hasDiagnostics = result.diagnostics.length > 0;
  const hasUntranslatable = result.untranslatableFeatures.length > 0;

  // Determine target label for field mapping table
  let targetLabel: string;
  try {
    const desc = getDescriptor(targetFileType);
    targetLabel = desc.shortLabel;
  } catch {
    targetLabel = targetFileType;
  }

  return (
    <div className="bg-[#0b0d13] text-[#ece7dc]">
      {/* Header bar */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#2d3240]">
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
            Translation
          </span>
          <FormatDot fileType={sourceFileType} />
          <span className="text-[10px] font-mono text-[#6f7f9a]">&rarr;</span>
          <FormatDot fileType={targetFileType} />
          {result.success ? (
            <span className="text-[9px] font-mono text-[#22c55e] bg-[#22c55e]/10 px-1.5 py-0.5 rounded">
              OK
            </span>
          ) : (
            <span className="text-[9px] font-mono text-[#ef4444] bg-[#ef4444]/10 px-1.5 py-0.5 rounded">
              FAILED
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1 rounded text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240] transition-colors"
          title="Close translation results"
        >
          <IconX size={14} />
        </button>
      </div>

      <div className="flex flex-col gap-0">
        {/* Output section */}
        {result.output && (
          <div className="px-3 py-2">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
                Output
              </span>
              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono rounded border border-[#2d3240] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#4a5568] transition-colors"
              >
                {copied ? <IconCheck size={10} /> : <IconCopy size={10} />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="bg-[#131721] border border-[#2d3240] rounded p-3 text-[11px] font-mono text-[#ece7dc]/90 whitespace-pre-wrap leading-relaxed max-h-[200px] overflow-y-auto">
              {result.output}
            </pre>
          </div>
        )}

        {/* Field mappings section */}
        {hasFieldMappings && (
          <div className="px-3 py-2 border-t border-[#2d3240]/50">
            <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a] block mb-1.5">
              Field Mappings
            </span>
            <FieldMappingTable
              entries={result.fieldMappings}
              targetLabel={targetLabel}
              accentColor="#d4a84b"
            />
          </div>
        )}

        {/* Diagnostics section */}
        {hasDiagnostics && (
          <div className="px-3 py-2 border-t border-[#2d3240]/50">
            <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a] block mb-1.5">
              Diagnostics
            </span>
            <div className="flex flex-col gap-1">
              {result.diagnostics.map((d, i) => (
                <div key={i} className="flex items-start gap-1.5">
                  <DiagnosticIcon severity={d.severity} />
                  <span className="text-[11px] font-mono text-[#ece7dc]/80 leading-tight">
                    {d.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Untranslatable features section */}
        {hasUntranslatable && (
          <div className="px-3 py-2 border-t border-[#2d3240]/50">
            <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#eab308]/80 block mb-1.5">
              Untranslatable Features
            </span>
            <div className="flex flex-col gap-1">
              {result.untranslatableFeatures.map((feature, i) => (
                <div key={i} className="flex items-start gap-1.5">
                  <span className="text-[#eab308] text-[10px] leading-none font-bold mt-0.5 flex-shrink-0">&#x26A0;</span>
                  <span className="text-[11px] font-mono text-[#ece7dc]/70 leading-tight">
                    {feature}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
