import { useState, useEffect } from "react";

/**
 * Hook that exposes motion configuration respecting user's system preferences.
 * Use this to conditionally skip animations when the user prefers reduced motion.
 */
export function useMotionConfig() {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const handler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  return {
    prefersReducedMotion,
    // Motion library (framer-motion/motion) transition presets
    transition: prefersReducedMotion
      ? { duration: 0 }
      : { duration: 0.15, ease: [0.16, 1, 0.3, 1] },
    // For conditional animation props
    animate: !prefersReducedMotion,
  };
}
