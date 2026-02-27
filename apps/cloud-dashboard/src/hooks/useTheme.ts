import { useCallback, useEffect, useState } from "react";
import { LIGHT_THEME_OVERRIDES } from "../state/lightTheme";

type Theme = "dark" | "light";

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "light") {
    for (const [prop, value] of Object.entries(LIGHT_THEME_OVERRIDES)) {
      root.style.setProperty(prop, value);
    }
  } else {
    for (const prop of Object.keys(LIGHT_THEME_OVERRIDES)) {
      root.style.removeProperty(prop);
    }
  }
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    const stored = localStorage.getItem("cs_theme");
    return stored === "light" ? "light" : "dark";
  });

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((t: Theme) => {
    localStorage.setItem("cs_theme", t);
    setThemeState(t);
  }, []);

  const toggle = useCallback(() => {
    setTheme(theme === "dark" ? "light" : "dark");
  }, [theme, setTheme]);

  return { theme, toggle, setTheme };
}

export function ThemeProvider() {
  useTheme();
  return null;
}
