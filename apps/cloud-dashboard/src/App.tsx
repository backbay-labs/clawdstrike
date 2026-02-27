import { DesktopOSProvider, type PartialDesktopOSTheme } from "@backbay/glia-desktop";
import { SharedSSEProvider } from "./context/SSEContext";
import { ThemeProvider } from "./hooks/useTheme";
import { ClawdStrikeDesktop } from "./components/shell/ClawdStrikeDesktop";
import { ErrorBoundary } from "./components/shell/ErrorBoundary";
import { processes, pinnedAppIds } from "./state/processRegistry";

const artifactTheme: PartialDesktopOSTheme = {
  colors: {
    accent: "#d6b15a",
    accentMuted: "rgba(214,177,90,0.12)",
    accentGlow: "rgba(214,177,90,0.35)",
    windowBg: "#0b0d10",
    windowBorder: "rgba(27,34,48,0.8)",
    windowBorderFocused: "rgba(214,177,90,0.35)",
    titlebarBg: "#0b0d10",
    titlebarText: "#e7edf6",
    taskbarBg: "rgba(11,13,16,0.96)",
    taskbarText: "#9aa7b5",
    desktopBg: "#000000",
    iconText: "#9aa7b5",
    iconSelected: "rgba(214,177,90,0.12)",
    destructive: "#c23b3b",
    success: "#2daa6a",
    warning: "#d2a34b",
    textPrimary: "#e7edf6",
    textSecondary: "#9aa7b5",
    textMuted: "rgba(154,167,181,0.5)",
  },
  fonts: {
    display: '"Space Grotesk", sans-serif',
    body: '"Inter", sans-serif',
    mono: '"JetBrains Mono", monospace',
  },
  radii: {
    window: "14px",
    button: "10px",
    menu: "14px",
    input: "10px",
  },
  shadows: {
    window: "0 4px 24px rgba(0,0,0,0.5)",
    windowFocused: "0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(214,177,90,0.2)",
  },
};

export function App() {
  return (
    <ErrorBoundary>
      <SharedSSEProvider>
        <DesktopOSProvider
          processes={processes}
          initialPinnedApps={pinnedAppIds}
          enableSnapZones
          enableWindowGroups
          enableAnimations
          theme={artifactTheme}
        >
          <ThemeProvider />
          <ClawdStrikeDesktop />
        </DesktopOSProvider>
      </SharedSSEProvider>
    </ErrorBoundary>
  );
}
