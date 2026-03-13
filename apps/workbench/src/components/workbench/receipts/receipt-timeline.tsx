import { useState } from "react";
import type { Receipt } from "@/lib/workbench/types";
import type { FleetConnection } from "@/lib/workbench/fleet-client";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { ReceiptDetail } from "./receipt-detail";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface ReceiptTimelineProps {
  receipts: Receipt[];
  /** Set of receipt IDs that have been synced to fleet. Undefined when fleet is disconnected. */
  syncedIds?: Set<string>;
  /** Fleet connection for server-side verification. Undefined when disconnected. */
  fleetConnection?: FleetConnection;
}

const verdictDotColor: Record<string, string> = {
  allow: "#3dbf84",
  deny: "#c45c5c",
  warn: "#d4a84b",
};

export function ReceiptTimeline({ receipts, syncedIds, fleetConnection }: ReceiptTimelineProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (receipts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full py-16 text-center px-6">
        <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-5">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="empty-state-icon text-[#6f7f9a]">
            <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            <rect x="4" y="3" width="16" height="18" rx="2" stroke="currentColor" strokeWidth="1.5"/>
            <path d="M4 9h16" stroke="currentColor" strokeWidth="1.5"/>
          </svg>
        </div>
        <p className="text-[13px] font-medium text-[#6f7f9a] mb-1.5">
          No receipts yet
        </p>
        <p className="text-[11px] text-[#6f7f9a]/60 max-w-[280px] leading-relaxed">
          Import a receipt JSON above, generate a test receipt, or sign one using the Rust engine
        </p>
      </div>
    );
  }

  // Newest first
  const sorted = [...receipts].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <ScrollArea className="h-full">
      <div className="relative pl-8 pr-4 py-4">
        {/* Vertical timeline line */}
        <div className="absolute left-[19px] top-4 bottom-4 w-px bg-[#2d3240]" />

        <div className="space-y-3">
          {sorted.map((receipt) => {
            const isExpanded = expandedId === receipt.id;
            const dotColor = verdictDotColor[receipt.verdict] ?? "#6f7f9a";

            return (
              <div key={receipt.id} className="relative">
                {/* Timeline dot */}
                <div
                  className="absolute -left-[18px] top-3 w-3 h-3 rounded-full border-2 border-[#0b0d13]"
                  style={{ backgroundColor: dotColor }}
                />

                {isExpanded ? (
                  <div className="space-y-2">
                    <button
                      onClick={() => setExpandedId(null)}
                      className="text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                    >
                      Collapse
                    </button>
                    <ReceiptDetail receipt={receipt} fleetConnection={fleetConnection} />
                  </div>
                ) : (
                  <button
                    onClick={() => setExpandedId(receipt.id)}
                    className={cn(
                      "w-full text-left flex items-center gap-3 px-3 py-2.5 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]",
                      "hover:border-[#2d3240] hover:bg-[#0d0f17] transition-all duration-150 guard-card-hover"
                    )}
                  >
                    <span className="text-[10px] font-mono text-[#6f7f9a] shrink-0 w-[140px]">
                      {new Date(receipt.timestamp).toLocaleString()}
                    </span>
                    <VerdictBadge verdict={receipt.verdict} />
                    <span className="text-xs font-mono text-[#ece7dc] truncate">
                      {receipt.guard}
                    </span>
                    <span className="text-[10px] text-[#6f7f9a] truncate flex-1 text-right">
                      {receipt.action.type} &rarr; {receipt.action.target}
                    </span>
                    {syncedIds && (
                      <span
                        className={cn(
                          "shrink-0 w-1.5 h-1.5 rounded-full",
                          syncedIds.has(receipt.id)
                            ? "bg-[#3dbf84]"
                            : "bg-[#6f7f9a]/30",
                        )}
                        title={syncedIds.has(receipt.id) ? "Synced to fleet" : "Local only"}
                      />
                    )}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </ScrollArea>
  );
}
