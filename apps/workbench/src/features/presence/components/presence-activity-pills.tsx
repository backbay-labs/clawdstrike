// PresenceActivityPills — colored 8px circles in the activity bar showing
// online remote analysts. Max 5 pills visible with +N overflow.

import { useMemo } from "react";
import { usePresenceStore } from "../stores/presence-store";

const MAX_VISIBLE_PILLS = 5;

export function PresenceActivityPills() {
  const analysts = usePresenceStore((s) => s.analysts);
  const localAnalystId = usePresenceStore((s) => s.localAnalystId);

  const remoteAnalysts = useMemo(
    () =>
      [...analysts.values()].filter(
        (a) => a.fingerprint !== localAnalystId,
      ),
    [analysts, localAnalystId],
  );

  if (remoteAnalysts.length === 0) return null;

  const visiblePills = remoteAnalysts.slice(0, MAX_VISIBLE_PILLS);
  const overflow = Math.max(0, remoteAnalysts.length - MAX_VISIBLE_PILLS);

  return (
    <div className="flex flex-col items-center gap-1.5 py-1.5">
      {visiblePills.map((analyst) => (
        <span
          key={analyst.fingerprint}
          className="w-2 h-2 rounded-full shrink-0"
          style={{ backgroundColor: analyst.color }}
          title={analyst.displayName}
        />
      ))}
      {overflow > 0 && (
        <span className="text-[8px] font-mono text-[#6f7f9a]/50 leading-none">
          +{overflow}
        </span>
      )}
    </div>
  );
}
