/**
 * HuntronomerThemeProvider — Wraps glia's UiThemeProvider with CSS variable
 * injection disabled, then applies the huntronomer gold/steel palette directly.
 *
 * Why disableCssVariables: UiThemeProvider has a hydration tick that applies
 * nebula's CSS vars *after* our override useEffect, winning the race.
 * By disabling glia's CSS injection entirely, we own all --theme-* variables.
 * The UiThemeProvider context still works for hooks (useThemeTokens, etc.).
 */
import { UiThemeProvider, applyThemeCssVariables } from "@backbay/glia/theme";
import { useEffect, type ReactNode } from "react";
import { huntronomerTheme } from "./huntronomer";

export function HuntronomerThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    applyThemeCssVariables(huntronomerTheme, document.documentElement);
  }, []);

  return (
    <UiThemeProvider themeId="nebula" disableCssVariables>
      {children}
    </UiThemeProvider>
  );
}
