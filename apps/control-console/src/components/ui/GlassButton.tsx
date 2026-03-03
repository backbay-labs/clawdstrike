export function GlassButton({
  onClick,
  disabled,
  children,
  variant = "secondary",
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
  variant?: "primary" | "secondary";
}) {
  const isPrimary = variant === "primary";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="glass-panel hover-glass-button font-mono rounded-md px-5 py-2 text-sm disabled:opacity-50"
      style={{
        color: isPrimary ? "var(--void)" : "var(--gold)",
        background: isPrimary ? "linear-gradient(180deg, var(--gold) 0%, #c5a04e 100%)" : undefined,
        letterSpacing: "0.05em",
        cursor: disabled ? "default" : "pointer",
      }}
    >
      {children}
    </button>
  );
}
