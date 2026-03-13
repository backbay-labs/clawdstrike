import React from "react";
import { cn } from "@/lib/utils";

/**
 * A card wrapper with a subtle hover highlight.
 * Formerly had a wobble/parallax effect; simplified to a clean card
 * that fits the production security-tool aesthetic.
 */
export const WobbleCard = ({
  children,
  containerClassName,
  className,
}: {
  children: React.ReactNode;
  containerClassName?: string;
  className?: string;
}) => {
  return (
    <section
      className={cn(
        "mx-auto w-full bg-[#0b0d13] relative rounded-2xl overflow-hidden guard-card-hover",
        containerClassName,
      )}
    >
      <div className="relative h-full sm:mx-0 sm:rounded-2xl overflow-hidden">
        <div className={cn("h-full px-4 py-20 sm:px-10", className)}>
          {children}
        </div>
      </div>
    </section>
  );
};
