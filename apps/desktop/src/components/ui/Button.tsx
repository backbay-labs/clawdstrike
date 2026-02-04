/**
 * Button - Reusable button component
 */
import { forwardRef, type ButtonHTMLAttributes } from "react";
import { clsx } from "clsx";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md" | "lg";
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", size = "md", disabled, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled}
        className={clsx(
          "inline-flex items-center justify-center font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-sdr-bg-primary",
          // Variants
          variant === "primary" &&
            "bg-sdr-accent-blue text-white hover:bg-sdr-accent-blue/90 focus:ring-sdr-accent-blue",
          variant === "secondary" &&
            "bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary focus:ring-sdr-accent-blue",
          variant === "ghost" &&
            "bg-transparent text-sdr-text-secondary hover:bg-sdr-bg-tertiary hover:text-sdr-text-primary",
          variant === "danger" &&
            "bg-sdr-accent-red text-white hover:bg-sdr-accent-red/90 focus:ring-sdr-accent-red",
          // Sizes
          size === "sm" && "px-2.5 py-1.5 text-xs",
          size === "md" && "px-3 py-2 text-sm",
          size === "lg" && "px-4 py-2.5 text-base",
          // Disabled
          disabled && "opacity-50 cursor-not-allowed",
          className
        )}
        {...props}
      />
    );
  }
);

Button.displayName = "Button";
