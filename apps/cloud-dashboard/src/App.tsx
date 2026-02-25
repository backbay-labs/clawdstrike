import { DesktopOSProvider } from "@backbay/glia-desktop";
import { SharedSSEProvider } from "./context/SSEContext";
import { ClawdStrikeDesktop } from "./components/shell/ClawdStrikeDesktop";
import { processes, pinnedAppIds } from "./state/processRegistry";

export function App() {
  return (
    <SharedSSEProvider>
      <DesktopOSProvider
        processes={processes}
        initialPinnedApps={pinnedAppIds}
        enableSnapZones
        enableWindowGroups
        enableAnimations
      >
        <ClawdStrikeDesktop />
      </DesktopOSProvider>
    </SharedSSEProvider>
  );
}
