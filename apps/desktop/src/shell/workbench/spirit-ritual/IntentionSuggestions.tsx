import type { CSSProperties } from "react";
import type { SpiritRitualSuggestion } from "./state/types";

function chipStyle(selected: boolean, disabled: boolean): CSSProperties {
  return {
    border: `1px solid ${selected ? "rgba(212,168,75,0.18)" : "rgba(182,183,193,0.08)"}`,
    background: selected ? "rgba(212,168,75,0.05)" : "rgba(255,255,255,0.01)",
    color: disabled
      ? "rgba(182,183,193,0.38)"
      : selected
        ? "rgba(244,225,177,0.92)"
        : "rgba(236,233,225,0.82)",
    opacity: disabled ? 0.66 : 1,
  };
}

export function IntentionSuggestions({
  suggestions,
  selectedSuggestionIds,
  onToggleSuggestion,
  onApplySuggestion,
  title = "Field lines",
  disabled = false,
}: {
  suggestions: SpiritRitualSuggestion[];
  selectedSuggestionIds: string[];
  onToggleSuggestion: (suggestionId: string) => void;
  onApplySuggestion?: (suggestion: SpiritRitualSuggestion) => void;
  title?: string;
  disabled?: boolean;
}) {
  if (suggestions.length === 0) {
    return null;
  }

  const selected = new Set(selectedSuggestionIds);

  return (
    <section
      aria-label={title || "Intention suggestions"}
      className="px-1"
      data-testid="spirit-ritual-intention-suggestions"
    >
      {title ? (
        <header className="mb-2">
          <div
            className="font-mono text-[10px] uppercase tracking-[0.18em]"
            style={{ color: "rgba(212,168,75,0.68)" }}
          >
            {title}
          </div>
        </header>
      ) : null}

      <div className="flex flex-col gap-1.5">
        {suggestions.map((suggestion) => {
          const isSelected = selected.has(suggestion.id);
          return (
            <div
              key={suggestion.id}
              className="rounded-[12px] px-2.5 py-2 transition-colors"
              style={chipStyle(isSelected, disabled)}
            >
              <div className="flex items-start justify-between gap-3">
                <button
                  type="button"
                  className="min-w-0 flex-1 text-left"
                  onClick={() => onToggleSuggestion(suggestion.id)}
                  disabled={disabled}
                  aria-pressed={isSelected}
                  data-testid={`ritual-suggestion-toggle-${suggestion.id}`}
                >
                  <div className="font-mono text-[10px] uppercase tracking-[0.14em]">
                    {suggestion.label}
                  </div>
                  <div className="mt-1 text-[11px]" style={{ lineHeight: 1.45, color: "rgba(236,233,225,0.68)" }}>
                    {suggestion.detail}
                  </div>
                  <div
                    className="mt-1.5 text-[9px] font-mono uppercase tracking-[0.14em]"
                    style={{ color: isSelected ? "rgba(244,225,177,0.72)" : "rgba(182,183,193,0.5)" }}
                  >
                    Pulls toward {suggestion.focusSurfaces.slice(0, 3).join(" · ")}
                  </div>
                </button>

                {onApplySuggestion ? (
                  <button
                    type="button"
                    className="shrink-0 rounded-full px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.16em]"
                    style={{
                      border: "1px solid rgba(212,168,75,0.1)",
                      color: disabled ? "rgba(182,183,193,0.38)" : "rgba(244,225,177,0.72)",
                      background: "rgba(255,255,255,0.015)",
                    }}
                    onClick={() => onApplySuggestion(suggestion)}
                    disabled={disabled}
                    data-testid={`ritual-suggestion-apply-${suggestion.id}`}
                  >
                    Use
                  </button>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
