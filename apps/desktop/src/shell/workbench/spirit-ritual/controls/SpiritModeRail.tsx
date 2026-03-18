import { useCallback, useMemo, useRef } from "react";

export interface SpiritModeRailOption<T extends string> {
  id: T;
  label: string;
  caption: string;
  glyph: string;
  testId?: string;
}

export function SpiritModeRail<T extends string>({
  ariaLabel,
  options,
  value,
  accentColor,
  onChange,
  className,
}: {
  ariaLabel: string;
  options: Array<SpiritModeRailOption<T>>;
  value: T;
  accentColor: string;
  onChange: (value: T) => void;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const stations = useMemo(
    () => options.map((_, index) => {
      const ratio = options.length <= 1 ? 0.5 : index / (options.length - 1);
      const angle = (-112 + ratio * 224) * (Math.PI / 180);
      return {
        left: 48 + Math.cos(angle) * 30,
        top: 50 + Math.sin(angle) * 39,
      };
    }),
    [options],
  );

  const moveFocus = useCallback(
    (index: number) => {
      const container = containerRef.current;
      if (!container) return;
      const buttons = container.querySelectorAll<HTMLButtonElement>('[role="tab"]');
      buttons[index]?.focus();
    },
    [],
  );

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLButtonElement>, currentIndex: number) => {
      const { key } = event;
      let nextIndex = currentIndex;

      if (key === "ArrowDown" || key === "ArrowRight") {
        event.preventDefault();
        nextIndex = (currentIndex + 1) % options.length;
      } else if (key === "ArrowUp" || key === "ArrowLeft") {
        event.preventDefault();
        nextIndex = (currentIndex - 1 + options.length) % options.length;
      } else if (key === "Home") {
        event.preventDefault();
        nextIndex = 0;
      } else if (key === "End") {
        event.preventDefault();
        nextIndex = options.length - 1;
      } else {
        return;
      }

      onChange(options[nextIndex].id);
      moveFocus(nextIndex);
    },
    [moveFocus, onChange, options],
  );

  return (
    <div
      ref={containerRef}
      role="tablist"
      aria-label={ariaLabel}
      className={className}
      data-testid="spirit-bind-mode-rail"
      style={{ position: "relative" }}
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        style={{
          position: "absolute",
          inset: 0,
          width: "100%",
          height: "100%",
          overflow: "visible",
        }}
      >
        <path
          d="M80 10 C 38 18, 24 82, 78 90"
          fill="none"
          stroke={`${accentColor}28`}
          strokeWidth="0.7"
          strokeDasharray="1.4 5.2"
        />
      </svg>

      {options.map((option, index) => {
        const active = option.id === value;
        const station = stations[index] ?? { left: 50, top: 50 };
        return (
          <button
            key={option.id}
            type="button"
            role="tab"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(option.id)}
            onKeyDown={(event) => handleKeyDown(event, index)}
            data-testid={option.testId}
            className="group absolute -translate-x-1/2 -translate-y-1/2 text-left transition-all"
            style={{
              left: `${station.left}%`,
              top: `${station.top}%`,
            }}
          >
            <div className="relative">
              <div
                aria-hidden="true"
                className="flex h-11 w-11 items-center justify-center rounded-full border text-[15px]"
                style={{
                  borderColor: active ? `${accentColor}88` : "rgba(171, 177, 191, 0.16)",
                  color: active ? accentColor : "rgba(231, 233, 239, 0.72)",
                  background: active
                    ? `radial-gradient(circle at 34% 30%, ${accentColor}24, rgba(7, 12, 21, 0.96))`
                    : "linear-gradient(180deg, rgba(16, 21, 34, 0.9), rgba(9, 12, 20, 0.98))",
                  transform: active ? "scale(1.04)" : "scale(1)",
                  boxShadow: active ? `0 0 22px ${accentColor}20` : "none",
                  transition: "transform 140ms ease, border-color 140ms ease, color 140ms ease, box-shadow 140ms ease",
                }}
              >
                {option.glyph}
              </div>
              <span
                aria-hidden="true"
                className="absolute left-1/2 top-[calc(100%+2px)] h-4 w-px -translate-x-1/2"
                style={{
                  background: `linear-gradient(180deg, ${active ? `${accentColor}7a` : "rgba(171,177,191,0.22)"}, transparent)`,
                }}
              />
              <div
                className="pointer-events-none absolute left-1/2 top-[calc(100%+10px)] w-[84px] -translate-x-1/2 text-center"
                style={{ opacity: active ? 1 : 0.64 }}
              >
                <div
                  className="font-mono text-[9px] uppercase tracking-[0.16em]"
                  style={{ color: active ? accentColor : "rgba(236, 233, 225, 0.76)" }}
                >
                  {option.label}
                </div>
                {active ? (
                  <div
                    className="mt-1 text-[10px]"
                    style={{ color: "rgba(182, 183, 193, 0.58)", lineHeight: 1.35 }}
                  >
                    {option.caption}
                  </div>
                ) : null}
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
