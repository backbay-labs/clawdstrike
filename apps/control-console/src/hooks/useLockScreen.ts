import { useCallback, useState } from "react";
import { notifySSEConfigChanged } from "./useSSE";

export function useLockScreen() {
  const [locked, setLocked] = useState(() => localStorage.getItem("cs_locked") === "true");

  const lock = useCallback(() => {
    localStorage.setItem("cs_locked", "true");
    setLocked(true);
  }, []);

  const unlock = useCallback((apiKey?: string) => {
    localStorage.removeItem("cs_locked");
    setLocked(false);
    if (apiKey) {
      localStorage.setItem("hushd_api_key", apiKey);
      notifySSEConfigChanged();
    }
  }, []);

  return { locked, lock, unlock };
}
