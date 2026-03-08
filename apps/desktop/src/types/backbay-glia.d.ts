declare module "@backbay/glia/primitives" {
  import type * as React from "react";

  export const GlassPanel: React.FC<React.HTMLAttributes<HTMLDivElement> & { variant?: string }>;
  export const GlassHeader: React.FC<React.HTMLAttributes<HTMLDivElement>>;
  export const GlassCard: React.FC<React.HTMLAttributes<HTMLDivElement> & { variant?: string }>;
  export const GlassTextarea: React.FC<
    React.TextareaHTMLAttributes<HTMLTextAreaElement> & {
      variant?: string;
      size?: string;
      label?: string;
      description?: string;
      error?: string;
      autoResize?: boolean;
      showCount?: boolean;
      maxLength?: number;
    }
  >;

  export const GlowButton: React.FC<
    React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: string }
  >;
  export const GlowInput: React.FC<
    React.InputHTMLAttributes<HTMLInputElement> & { variant?: string }
  >;
  export const Badge: React.FC<React.HTMLAttributes<HTMLSpanElement> & { variant?: string }>;
  export const CodeBlock: React.FC<{
    code: string;
    language?: string;
    title?: string;
    showLineNumbers?: boolean;
    showCopyButton?: boolean;
    highlightLines?: number[];
    maxHeight?: number | string;
    wordWrap?: boolean;
    className?: string;
    style?: React.CSSProperties;
  }>;
  export const Tabs: React.FC<
    React.HTMLAttributes<HTMLDivElement> & {
      value?: string;
      defaultValue?: string;
      onValueChange?: (value: string) => void;
    }
  >;
  export const TabsList: React.FC<React.HTMLAttributes<HTMLDivElement>>;
  export const TabsTrigger: React.FC<
    React.ButtonHTMLAttributes<HTMLButtonElement> & { value: string }
  >;
  export const TabsContent: React.FC<React.HTMLAttributes<HTMLDivElement> & { value: string }>;

  export const GlitchText: React.FC<
    React.HTMLAttributes<HTMLSpanElement> & { text?: string; variants?: string[] }
  >;

  export const KPIStat: React.FC<Record<string, unknown>>;
  export const HUDProgressRing: React.FC<Record<string, unknown>>;
}

declare module "@backbay/glia/theme" {
  import type * as React from "react";

  export const UiThemeProvider: React.FC<{ themeId: string; children?: React.ReactNode }>;
}
