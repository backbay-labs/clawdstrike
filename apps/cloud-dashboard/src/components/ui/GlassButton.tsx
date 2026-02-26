export function GlassButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="glass-panel hover-glass-button font-mono rounded-md px-5 py-2 text-sm disabled:opacity-50"
      style={{
        color: "#22d3ee",
        letterSpacing: "0.05em",
        cursor: disabled ? "default" : "pointer",
      }}
    >
      {children}
    </button>
  );
}
