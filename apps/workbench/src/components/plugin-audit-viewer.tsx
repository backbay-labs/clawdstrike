import { useState, useMemo } from "react";
import { usePluginReceipts } from "@/lib/plugins/bridge/receipt-store";
import type { PluginActionReceipt } from "@/lib/plugins/bridge/receipt-types";

const RESULT_CLASSES: Record<string, string> = {
  allowed: "text-green-500",
  denied: "text-red-500 font-semibold",
  error: "text-amber-500",
};

const TH =
  "px-3 py-2.5 text-left text-[9px] uppercase tracking-[0.08em] font-semibold text-[#6f7f9a]/80";

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function PluginAuditViewer() {
  const { receipts, clearReceipts } = usePluginReceipts();

  const [pluginFilter, setPluginFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [resultFilter, setResultFilter] = useState<
    "" | "allowed" | "denied" | "error"
  >("");

  const filteredReceipts = useMemo(() => {
    let result: PluginActionReceipt[] = receipts;

    if (pluginFilter) {
      const lower = pluginFilter.toLowerCase();
      result = result.filter((r) =>
        r.content.plugin.id.toLowerCase().includes(lower),
      );
    }

    if (actionFilter) {
      const lower = actionFilter.toLowerCase();
      result = result.filter((r) =>
        r.content.action.type.toLowerCase().includes(lower),
      );
    }

    if (resultFilter) {
      result = result.filter(
        (r) => r.content.action.result === resultFilter,
      );
    }

    return result;
  }, [receipts, pluginFilter, actionFilter, resultFilter]);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      <div className="shrink-0 border-b border-[#2d3240]/60 px-4 py-2 flex items-center gap-3">
        <input
          type="text"
          placeholder="Filter by plugin..."
          value={pluginFilter}
          onChange={(e) => setPluginFilter(e.target.value)}
          className="h-7 rounded-md border border-[#2d3240] bg-[#0b0d13] px-2 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/50 focus:border-[#d4a84b]/40 focus:outline-none w-[160px] font-mono"
        />
        <input
          type="text"
          placeholder="Filter by action..."
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="h-7 rounded-md border border-[#2d3240] bg-[#0b0d13] px-2 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/50 focus:border-[#d4a84b]/40 focus:outline-none w-[160px] font-mono"
        />
        <select
          value={resultFilter}
          onChange={(e) =>
            setResultFilter(
              e.target.value as "" | "allowed" | "denied" | "error",
            )
          }
          className="h-7 rounded-md border border-[#2d3240] bg-[#0b0d13] px-2 text-[11px] text-[#ece7dc] focus:border-[#d4a84b]/40 focus:outline-none"
        >
          <option value="">All Results</option>
          <option value="allowed">Allowed</option>
          <option value="denied">Denied</option>
          <option value="error">Error</option>
        </select>
        <button
          onClick={clearReceipts}
          className="ml-auto flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] text-[#6f7f9a] hover:text-[#c45c5c] hover:border-[#c45c5c]/30 transition-colors"
        >
          Clear Receipts
        </button>
      </div>

      <div className="flex-1 overflow-auto">
        {filteredReceipts.length === 0 ? (
          <div className="flex h-full items-center justify-center">
            <span className="text-[12px] text-[#6f7f9a]/40">
              No plugin audit receipts
            </span>
          </div>
        ) : (
          <table className="w-full min-w-[700px]">
            <thead className="sticky top-0 z-10 bg-[#0b0d13]/60">
              <tr className="border-b border-[#2d3240]/60">
                <th className={TH}>Time</th>
                <th className={TH}>Plugin</th>
                <th className={TH}>Action</th>
                <th className={TH}>Result</th>
                <th className={TH}>Permission</th>
                <th className={TH}>Duration</th>
              </tr>
            </thead>
            <tbody>
              {filteredReceipts.map((receipt) => (
                <ReceiptRow
                  key={receipt.content.receipt_id}
                  receipt={receipt}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ReceiptRow({ receipt }: { receipt: PluginActionReceipt }) {
  const { content } = receipt;
  const resultClass = RESULT_CLASSES[content.action.result] ?? "";

  return (
    <tr className="border-b border-[#2d3240]/30 hover:bg-[#131721]">
      <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/50 whitespace-nowrap">
        {formatTime(content.timestamp)}
      </td>
      <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/70">
        {content.plugin.id}
      </td>
      <td className="px-3 py-2">
        <span className="rounded border border-[#2d3240] bg-[#0b0d13] px-1.5 py-0.5 font-mono text-[9px] text-[#ece7dc]/60">
          {content.action.type}
        </span>
      </td>
      <td className="px-3 py-2">
        <span className={`text-[10px] font-mono uppercase ${resultClass}`}>
          {content.action.result}
        </span>
      </td>
      <td className="px-3 py-2 font-mono text-[10px] text-[#6f7f9a]/60">
        {content.action.permission_checked}
      </td>
      <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/50">
        {content.action.duration_ms}ms
      </td>
    </tr>
  );
}
