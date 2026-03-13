/**
 * Mission store — stub (real implementation in sentinel-swarm worktree).
 */

import { createContext, useContext, type ReactNode } from "react";

interface MissionContextValue {
  missions: never[];
}

const MissionContext = createContext<MissionContextValue>({ missions: [] });

export function MissionProvider({ children }: { children: ReactNode }) {
  return (
    <MissionContext.Provider value={{ missions: [] }}>
      {children}
    </MissionContext.Provider>
  );
}

export function useMissions() {
  return useContext(MissionContext);
}
