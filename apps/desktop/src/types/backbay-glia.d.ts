declare module "@backbay/glia/primitives" {
  import type * as React from "react";

  export const GlassPanel: React.FC<React.HTMLAttributes<HTMLDivElement> & { variant?: string }>;
  export const GlassHeader: React.FC<React.HTMLAttributes<HTMLDivElement>>;
  export const GlassCard: React.FC<React.HTMLAttributes<HTMLDivElement> & { variant?: string }>;

  export const GlowButton: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: string }>;
  export const GlowInput: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { variant?: string }>;
  export const Badge: React.FC<React.HTMLAttributes<HTMLSpanElement> & { variant?: string }>;

  export const GlitchText: React.FC<React.HTMLAttributes<HTMLSpanElement> & { text?: string; variants?: string[] }>;

  export const KPIStat: React.FC<Record<string, unknown>>;
  export const HUDProgressRing: React.FC<Record<string, unknown>>;
}

declare module "@backbay/glia/theme" {
  import type * as React from "react";

  export const UiThemeProvider: React.FC<{ themeId: string; children?: React.ReactNode }>;
}
