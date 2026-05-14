import { useEffect, useState } from "react";

export function getObservatoryNowMs(): number {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

export function useObservatoryNow(active: boolean): number {
  const [nowMs, setNowMs] = useState(() => getObservatoryNowMs());

  useEffect(() => {
    if (!active) {
      setNowMs(getObservatoryNowMs());
      return;
    }

    let frameId = 0;
    const tick = () => {
      setNowMs(getObservatoryNowMs());
      frameId = window.requestAnimationFrame(tick);
    };

    frameId = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(frameId);
  }, [active]);

  return nowMs;
}
