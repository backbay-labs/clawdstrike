/**
 * LabFormatHeader — Format-aware header for the Lab shell.
 *
 * Shows the current document's file type (with color from FILE_TYPE_REGISTRY),
 * adapter availability status, and a summary of the last run if available.
 */

import type { FileType } from "@/lib/workbench/file-type-registry";
import { FILE_TYPE_REGISTRY } from "@/lib/workbench/file-type-registry";
import { hasAdapter } from "@/lib/workbench/detection-workflow/adapters";
import type { LabRun } from "@/lib/workbench/detection-workflow/shared-types";
import {
  IconCircle,
  IconCircleCheck,
  IconCircleX,
  IconFlask,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface LabFormatHeaderProps {
  fileType: FileType | undefined;
  lastRun: LabRun | null;
  isRunning: boolean;
}

export function LabFormatHeader({
  fileType,
  lastRun,
  isRunning,
}: LabFormatHeaderProps) {
  if (!fileType) return null;

  const descriptor = FILE_TYPE_REGISTRY[fileType];
  const adapterAvailable = hasAdapter(fileType);

  return (
    <div className="flex items-center gap-3 px-4 py-2 border-b border-[#2d3240]/40 bg-[#0b0d13]/40">
      {/* File type badge */}
      <div className="flex items-center gap-1.5">
        <div
          className="w-2 h-2 rounded-full shrink-0"
          style={{ backgroundColor: descriptor.iconColor }}
        />
        <span
          className="text-[10px] font-mono font-semibold uppercase tracking-wider"
          style={{ color: descriptor.iconColor }}
        >
          {descriptor.shortLabel}
        </span>
      </div>

      {/* Separator */}
      <div className="w-px h-3 bg-[#2d3240]" />

      {/* Adapter status */}
      {adapterAvailable ? (
        <div className="flex items-center gap-1.5">
          <IconCircle
            size={6}
            stroke={0}
            fill="#3dbf84"
            className="animate-pulse"
          />
          {isRunning ? (
            <span className="text-[10px] font-mono text-[#d4a84b]/80 animate-pulse">
              Running...
            </span>
          ) : lastRun ? (
            <LastRunSummary run={lastRun} />
          ) : (
            <span className="text-[10px] font-mono text-[#3dbf84]/70">
              Ready to run
            </span>
          )}
        </div>
      ) : (
        <div className="flex items-center gap-1.5">
          <IconFlask size={11} stroke={1.5} className="text-[#6f7f9a]/50" />
          <span className="text-[10px] font-mono text-[#6f7f9a]/60">
            Lab execution is not yet available for {descriptor.label} files
          </span>
        </div>
      )}
    </div>
  );
}

function LastRunSummary({ run }: { run: LabRun }) {
  const { passed, failed, totalCases } = run.summary;
  const allPassed = failed === 0 && totalCases > 0;

  return (
    <div className="flex items-center gap-1.5">
      {allPassed ? (
        <IconCircleCheck size={11} stroke={1.5} className="text-[#3dbf84]" />
      ) : (
        <IconCircleX size={11} stroke={1.5} className="text-[#c45c5c]" />
      )}
      <span
        className={cn(
          "text-[10px] font-mono",
          allPassed ? "text-[#3dbf84]/80" : "text-[#c45c5c]/80",
        )}
      >
        Last run: {passed} passed / {failed} failed
      </span>
      <span className="text-[9px] font-mono text-[#6f7f9a]/40">
        {new Date(run.completedAt).toLocaleTimeString()}
      </span>
    </div>
  );
}
