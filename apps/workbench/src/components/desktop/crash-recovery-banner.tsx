import { IconAlertTriangle, IconRestore, IconX } from "@tabler/icons-react";
import type { AutosaveEntry } from "@/lib/workbench/use-auto-save";

interface CrashRecoveryBannerProps {
  entries: AutosaveEntry[];
  onRestore: () => void;
  onDismiss: () => void;
}

export function CrashRecoveryBanner({
  entries,
  onRestore,
  onDismiss,
}: CrashRecoveryBannerProps) {
  if (entries.length === 0) {
    return null;
  }

  const latestTimestamp = Math.max(...entries.map((entry) => entry.timestamp));
  const normalizedPolicyName = (name: string) => name.trim();
  const policyNames = Array.from(
    new Set(
      entries
        .map((entry) => normalizedPolicyName(entry.policyName))
        .filter((name) => name.length > 0),
    ),
  );
  const allEntriesNamed = entries.every(
    (entry) => normalizedPolicyName(entry.policyName).length > 0,
  );
  const listedPolicyNames =
    policyNames.slice(0, 3).join(", ") + (policyNames.length > 3 ? ", ..." : "");
  const summaryLabel =
    entries.length === 1
      ? policyNames[0] || "an unnamed tab"
      : `${entries.length} tabs`;
  const policySummary =
    entries.length > 1 && policyNames.length > 0
      ? allEntriesNamed
        ? policyNames.length === 1
          ? `all named ${policyNames[0]}`
          : `named ${listedPolicyNames}`
        : `including ${listedPolicyNames}`
      : null;
  const omittedSensitiveFields = entries.some(
    (entry) => entry.sensitiveFieldsStripped,
  );

  const formattedTime = formatTimestamp(latestTimestamp);

  return (
    <div className="shrink-0 flex items-center gap-3 px-4 py-2 bg-[#0f1118] border-b border-[#2d3240]">
      {/* Icon */}
      <IconAlertTriangle size={16} stroke={2} className="shrink-0 text-[#d4a84b]" />

      {/* Message */}
      <span className="text-xs text-[#6f7f9a] leading-tight min-w-0">
        Recovered unsaved changes from{" "}
        <span className="text-[#ece7dc] font-medium">{summaryLabel}</span>
        {policySummary ? (
          <>
            {" "}
            <span className="text-[#6f7f9a]/70">
              ({policySummary})
            </span>
          </>
        ) : null}
        {" "}
        <span className="text-[#6f7f9a]/70">({formattedTime})</span>
        {omittedSensitiveFields ? (
          <>
            {" "}
            <span className="text-[#d4a84b]/80">
              Sensitive fields were omitted from recovery and must be re-entered.
            </span>
          </>
        ) : null}
      </span>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Restore */}
      <button
        onClick={onRestore}
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-[#d4a84b]/15 text-[#d4a84b] hover:bg-[#d4a84b]/25 transition-colors"
      >
        <IconRestore size={13} stroke={2} />
        Restore
      </button>

      {/* Discard */}
      <button
        onClick={onDismiss}
        className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#1a1d2a] transition-colors"
      >
        <IconX size={13} stroke={2} />
        Discard
      </button>
    </div>
  );
}

function formatTimestamp(ts: number): string {
  try {
    const date = new Date(ts);
    const now = new Date();

    // Same day — show time only
    if (
      date.getFullYear() === now.getFullYear() &&
      date.getMonth() === now.getMonth() &&
      date.getDate() === now.getDate()
    ) {
      return date.toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
      });
    }

    // Different day — show date and time
    return date.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "unknown time";
  }
}
