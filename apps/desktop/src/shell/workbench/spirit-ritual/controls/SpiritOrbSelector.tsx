import { useCallback, useRef } from "react";

export interface SpiritOrbOption<T extends string> {
  value: T;
  label: string;
  caption: string;
  accentColor: string;
  testId?: string;
}

export function SpiritOrbSelector<T extends string>({
  ariaLabel,
  options,
  value,
  onChange,
}: {
  ariaLabel: string;
  options: Array<SpiritOrbOption<T>>;
  value: T | null;
  onChange: (value: T) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);

  const moveFocus = useCallback((index: number) => {
    const buttons = containerRef.current?.querySelectorAll<HTMLButtonElement>('[role="radio"]');
    buttons?.[index]?.focus();
  }, []);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
      const { key } = event;
      let nextIndex = index;
      if (key === "ArrowRight" || key === "ArrowDown") {
        event.preventDefault();
        nextIndex = (index + 1) % options.length;
      } else if (key === "ArrowLeft" || key === "ArrowUp") {
        event.preventDefault();
        nextIndex = (index - 1 + options.length) % options.length;
      } else if (key === "Home") {
        event.preventDefault();
        nextIndex = 0;
      } else if (key === "End") {
        event.preventDefault();
        nextIndex = options.length - 1;
      } else {
        return;
      }

      onChange(options[nextIndex].value);
      moveFocus(nextIndex);
    },
    [moveFocus, onChange, options],
  );

  return (
    <div
      ref={containerRef}
      role="radiogroup"
      aria-label={ariaLabel}
      data-testid="spirit-bind-manual-selector"
    >
      <div className="grid grid-cols-3 gap-x-3 gap-y-4">
        {options.map((option, index) => {
          const active = option.value === value;
          return (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={active}
              tabIndex={active || (value === null && index === 0) ? 0 : -1}
              onClick={() => onChange(option.value)}
              onKeyDown={(event) => handleKeyDown(event, index)}
              data-testid={option.testId}
              className="text-center transition-all"
            >
              <div
                aria-hidden="true"
                className="relative mx-auto flex h-12 w-12 items-center justify-center rounded-full border"
                style={{
                  borderColor: `${option.accentColor}${active ? "aa" : "44"}`,
                  background: active
                    ? `radial-gradient(circle at 32% 30%, ${option.accentColor}, rgba(9, 12, 21, 0.18))`
                    : `radial-gradient(circle at 32% 30%, ${option.accentColor}88, rgba(9, 12, 21, 0.14))`,
                  boxShadow: active ? `0 0 20px ${option.accentColor}3a` : "0 0 10px rgba(0,0,0,0.16)",
                  transform: active ? "scale(1.06)" : "scale(1)",
                  transition: "transform 120ms ease, box-shadow 120ms ease, border-color 120ms ease",
                }}
              >
                <span
                  className="absolute inset-[7px] rounded-full"
                  style={{
                    border: `1px solid ${option.accentColor}${active ? "70" : "2c"}`,
                  }}
                />
              </div>
              <div
                className="mt-2 font-mono text-[9px] uppercase tracking-[0.16em]"
                style={{ color: active ? option.accentColor : "rgba(236, 233, 225, 0.78)" }}
              >
                {option.label}
              </div>
            </button>
          );
        })}
      </div>

      {options.find((option) => option.value === value)?.caption ? (
        <div
          className="mt-4 px-1 text-[12px]"
          style={{
            color: "rgba(182, 183, 193, 0.68)",
            lineHeight: 1.45,
          }}
        >
          {options.find((option) => option.value === value)?.caption}
        </div>
      ) : null}
    </div>
  );
}
