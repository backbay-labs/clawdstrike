import { useCallback, useEffect, useRef, useState } from "react";

export function SpiritIntensitySlider({
  label,
  min,
  max,
  value,
  onChange,
}: {
  label: string;
  min: number;
  max: number;
  value: number;
  onChange: (value: number) => void;
}) {
  const [isDragging, setIsDragging] = useState(false);
  const [isHovering, setIsHovering] = useState(false);
  const [trail, setTrail] = useState<number[]>([]);
  const lastValueRef = useRef<number | null>(null);

  const range = max - min;
  const percent = range > 0 ? ((value - min) / range) * 100 : 0;

  const updateTrail = useCallback((nextValue: number) => {
    if (lastValueRef.current !== null && lastValueRef.current !== nextValue) {
      setTrail((current) => [lastValueRef.current!, ...current.slice(0, 3)]);
    }
    lastValueRef.current = nextValue;
  }, []);

  useEffect(() => {
    if (!isDragging) {
      const timer = setTimeout(() => {
        setTrail([]);
        lastValueRef.current = null;
      }, 120);
      return () => clearTimeout(timer);
    }
  }, [isDragging]);

  useEffect(() => {
    if (!isDragging) return;
    const handleMouseUp = () => setIsDragging(false);
    window.addEventListener("mouseup", handleMouseUp);
    window.addEventListener("touchend", handleMouseUp);
    return () => {
      window.removeEventListener("mouseup", handleMouseUp);
      window.removeEventListener("touchend", handleMouseUp);
    };
  }, [isDragging]);

  return (
    <label className="block">
      <div
        className="flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.14em]"
        style={{ color: "rgba(205, 208, 218, 0.62)" }}
      >
        <span>{label}</span>
        <span style={{ color: "rgba(236, 233, 225, 0.86)" }}>{value}</span>
      </div>
      <div
        className="relative mt-3 h-6"
        onMouseEnter={() => setIsHovering(true)}
        onMouseLeave={() => setIsHovering(false)}
      >
        <div
          className="absolute left-0 right-0 top-1/2 h-[4px] -translate-y-1/2 rounded-full"
          style={{ background: "rgba(208, 183, 116, 0.12)" }}
        />
        <div
          className="absolute left-0 top-1/2 h-[4px] -translate-y-1/2 rounded-full"
          style={{
            width: `${percent}%`,
            background:
              "linear-gradient(90deg, rgba(212,168,75,0.98), rgba(107,140,190,0.88))",
            boxShadow: "0 0 12px rgba(212,168,75,0.24)",
          }}
        />
        {trail.map((trailValue, index) => {
          const trailPercent = range > 0 ? ((trailValue - min) / range) * 100 : 0;
          return (
            <div
              key={`${trailValue}-${index}`}
              className="absolute top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full"
              style={{
                left: `${trailPercent}%`,
                background: "rgba(212,168,75,0.6)",
                opacity: Math.max(0.18, 0.45 - index * 0.1),
              }}
            />
          );
        })}
        <div
          className="absolute top-1/2 h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full border"
          style={{
            left: `${percent}%`,
            borderColor: "rgba(212,168,75,0.95)",
            background:
              "radial-gradient(circle at 30% 30%, rgba(244,222,152,1), rgba(212,168,75,0.88))",
            boxShadow: isDragging || isHovering
              ? "0 0 20px rgba(212,168,75,0.4)"
              : "0 0 12px rgba(212,168,75,0.22)",
            transform: `translate(-50%, -50%) scale(${isDragging || isHovering ? 1.08 : 1})`,
            transition: "transform 120ms ease, box-shadow 120ms ease",
          }}
        />
        <input
          type="range"
          min={min}
          max={max}
          value={value}
          onChange={(event) => {
            const nextValue = Number(event.target.value);
            if (isDragging) updateTrail(nextValue);
            onChange(nextValue);
          }}
          onMouseDown={() => {
            setIsDragging(true);
            lastValueRef.current = value;
          }}
          onTouchStart={() => {
            setIsDragging(true);
            lastValueRef.current = value;
          }}
          className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
          aria-label={label}
        />
      </div>
    </label>
  );
}
