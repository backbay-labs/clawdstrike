import { NoiseGrain } from "./NoiseGrain";

export function Plate({
  children,
  goldEdge = false,
  className = "",
  style,
}: {
  children: React.ReactNode;
  goldEdge?: boolean;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <div
      className={`glass-panel ${className}`}
      style={{
        ...style,
        boxShadow: goldEdge
          ? "inset 0 1px 0 var(--gold-edge)"
          : undefined,
      }}
    >
      <NoiseGrain />
      {children}
    </div>
  );
}
