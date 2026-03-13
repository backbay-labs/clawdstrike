// ---------------------------------------------------------------------------
// General Settings — app-level preferences (theme, editor, autosave)
// Persisted to localStorage independently of the policy store.
// ---------------------------------------------------------------------------
import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";
import React from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Theme = "dark";
export type FontSize = "small" | "medium" | "large";
export type AutosaveInterval = "off" | "5" | "15" | "30" | "60";

export interface GeneralSettings {
  theme: Theme;
  fontSize: FontSize;
  autosaveInterval: AutosaveInterval;
  showLineNumbers: boolean;
}

export const DEFAULT_GENERAL_SETTINGS: GeneralSettings = {
  theme: "dark",
  fontSize: "medium",
  autosaveInterval: "30",
  showLineNumbers: true,
};

// ---------------------------------------------------------------------------
// localStorage persistence
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_general_settings";

function loadSettings(): GeneralSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_GENERAL_SETTINGS;
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return DEFAULT_GENERAL_SETTINGS;

    // Validate each field and fall back to defaults for invalid values
    const theme: Theme = "dark"; // only dark supported for now
    const fontSize: FontSize =
      parsed.fontSize === "small" || parsed.fontSize === "medium" || parsed.fontSize === "large"
        ? parsed.fontSize
        : DEFAULT_GENERAL_SETTINGS.fontSize;
    const autosaveInterval: AutosaveInterval =
      parsed.autosaveInterval === "off" ||
      parsed.autosaveInterval === "5" ||
      parsed.autosaveInterval === "15" ||
      parsed.autosaveInterval === "30" ||
      parsed.autosaveInterval === "60"
        ? parsed.autosaveInterval
        : DEFAULT_GENERAL_SETTINGS.autosaveInterval;
    const showLineNumbers: boolean =
      typeof parsed.showLineNumbers === "boolean"
        ? parsed.showLineNumbers
        : DEFAULT_GENERAL_SETTINGS.showLineNumbers;

    return { theme, fontSize, autosaveInterval, showLineNumbers };
  } catch {
    return DEFAULT_GENERAL_SETTINGS;
  }
}

function persistSettings(settings: GeneralSettings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // Storage full or unavailable — ignore
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface GeneralSettingsContextValue {
  settings: GeneralSettings;
  updateSettings: (patch: Partial<GeneralSettings>) => void;
  resetSettings: () => void;
}

const GeneralSettingsContext = createContext<GeneralSettingsContextValue | null>(null);

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useGeneralSettings(): GeneralSettingsContextValue {
  const ctx = useContext(GeneralSettingsContext);
  if (!ctx) throw new Error("useGeneralSettings must be used within GeneralSettingsProvider");
  return ctx;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function GeneralSettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<GeneralSettings>(loadSettings);

  const updateSettings = useCallback((patch: Partial<GeneralSettings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      persistSettings(next);
      return next;
    });
  }, []);

  const resetSettings = useCallback(() => {
    setSettings(DEFAULT_GENERAL_SETTINGS);
    persistSettings(DEFAULT_GENERAL_SETTINGS);
  }, []);

  // Apply font-size CSS variable to the document so the editor can pick it up
  useEffect(() => {
    const root = document.documentElement;
    const sizeMap: Record<FontSize, string> = {
      small: "11.5px",
      medium: "12.5px",
      large: "14px",
    };
    root.style.setProperty("--editor-font-size", sizeMap[settings.fontSize]);
  }, [settings.fontSize]);

  const value: GeneralSettingsContextValue = {
    settings,
    updateSettings,
    resetSettings,
  };

  return React.createElement(GeneralSettingsContext.Provider, { value }, children);
}
