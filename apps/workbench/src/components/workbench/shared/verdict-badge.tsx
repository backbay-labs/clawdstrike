import { cn } from "@/lib/utils";

const verdictStyles = {
  allow: "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/25 shadow-[0_0_6px_-1px_#3dbf8420]",
  deny: "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/25 shadow-[0_0_6px_-1px_#c45c5c20]",
  warn: "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/25 shadow-[0_0_6px_-1px_#d4a84b20]",
} as const;

interface VerdictBadgeProps {
  verdict: "allow" | "deny" | "warn";
  className?: string;
  /** Enable a subtle pulsing glow for emphasis (e.g., overall verdict display). */
  glow?: boolean;
  /** Render at larger size for hero verdict displays. */
  size?: "sm" | "md";
}

export function VerdictBadge({ verdict, className, glow, size = "sm" }: VerdictBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center font-mono uppercase border rounded-md select-none tracking-wide",
        size === "sm" && "px-2 py-0.5 text-[10px]",
        size === "md" && "px-3 py-1 text-xs font-semibold",
        verdictStyles[verdict],
        glow && verdict === "allow" && "verdict-glow-allow",
        glow && verdict === "deny" && "verdict-glow-deny",
        className
      )}
    >
      {verdict}
    </span>
  );
}
