/**
 * Badge - Status and label badges
 */
import { clsx } from "clsx";

export interface BadgeProps {
  variant?: "default" | "success" | "warning" | "error" | "info";
  size?: "sm" | "md";
  children: React.ReactNode;
  className?: string;
}

export function Badge({ variant = "default", size = "sm", children, className }: BadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center font-medium rounded-full",
        // Variants
        variant === "default" && "bg-sdr-bg-tertiary text-sdr-text-secondary",
        variant === "success" && "bg-sdr-accent-green/20 text-sdr-accent-green",
        variant === "warning" && "bg-sdr-accent-amber/20 text-sdr-accent-amber",
        variant === "error" && "bg-sdr-accent-red/20 text-sdr-accent-red",
        variant === "info" && "bg-sdr-accent-blue/20 text-sdr-accent-blue",
        // Sizes
        size === "sm" && "px-2 py-0.5 text-xs",
        size === "md" && "px-2.5 py-1 text-sm",
        className
      )}
    >
      {children}
    </span>
  );
}
