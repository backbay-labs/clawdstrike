export function SpiritSuggestionChips({
  title,
  items,
  onSelect,
  activeValue,
}: {
  title: string;
  items: Array<{ id: string; label: string; tone?: string }>;
  onSelect?: (id: string) => void;
  activeValue?: string | null;
}) {
  return (
    <div className="rounded-[20px] border px-4 py-3" style={{ borderColor: "rgba(212, 168, 75, 0.12)", background: "rgba(255,255,255,0.02)" }}>
      <div
        className="font-mono text-[11px] uppercase tracking-[0.14em]"
        style={{ color: "rgba(212, 168, 75, 0.72)" }}
      >
        {title}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {items.map((item) => {
          const active = item.id === activeValue;
          const interactive = Boolean(onSelect);
          return (
            <button
              key={item.id}
              type="button"
              disabled={!interactive}
              onClick={() => onSelect?.(item.id)}
              className="rounded-full border px-3 py-1.5 text-[12px] transition-all"
              style={{
                borderColor: active ? "rgba(212, 168, 75, 0.72)" : "rgba(171, 177, 191, 0.18)",
                background: active ? "rgba(212, 168, 75, 0.14)" : "rgba(255,255,255,0.02)",
                color: active ? "rgba(244, 222, 152, 0.96)" : "rgba(222, 226, 235, 0.74)",
                cursor: interactive ? "pointer" : "default",
              }}
            >
              {item.label}
              {item.tone ? (
                <span style={{ color: "rgba(171, 177, 191, 0.66)" }}> · {item.tone}</span>
              ) : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}
