/**
 * Huntronomer Theme — Origin gold + steel palette for Clawdstrike
 *
 * Replaces nebula's cyan/magenta neon with gold/steel accents.
 * Follows the UiTheme shape from @backbay/glia.
 */

// Gold: #d5ad57  Steel: #7e8ba7  (from --origin-gold, --origin-steel-bright)
const GOLD = "#d5ad57";
const GOLD_DIM = "#9f7c3a";
const STEEL = "#7e8ba7";
const GREEN = "#3dbf84";
const AMBER = "#d4a84b";
const RED = "#c45c5c";

export const huntronomerTheme = {
  id: "huntronomer",
  name: "Huntronomer",
  description: "Origin gold + steel palette for Clawdstrike runtime security",

  color: {
    bg: {
      body: "#05060a",
      panel: "rgba(8, 10, 16, 0.94)",
      elevated: "rgba(14, 17, 24, 0.98)",
      horizon: "#05060a",
    },
    text: {
      primary: "#ece7dc",
      muted: "#b6b7c1",
      soft: "#7f8494",
    },
    accent: {
      primary: GOLD,
      secondary: STEEL,
      positive: GREEN,
      warning: AMBER,
      destructive: RED,
    },
    border: "rgba(213, 173, 87, 0.14)",
    ring: GOLD,
  },

  glass: {
    panelBg: "rgba(8, 10, 16, 0.94)",
    panelBorder: "rgba(213, 173, 87, 0.14)",
    panelBlur: "24px",
    headerGradient:
      "linear-gradient(to right, rgba(213, 173, 87, 0.03), rgba(213, 173, 87, 0.015), transparent)",
    cardBg: "rgba(213, 173, 87, 0.02)",
    cardBorder: "rgba(213, 173, 87, 0.06)",
    hoverBg: "rgba(213, 173, 87, 0.08)",
    activeBorder: "rgba(213, 173, 87, 0.35)",
    activeShadow: "0 6px 28px rgba(213, 173, 87, 0.1)",
  },

  elevation: {
    softDrop: "0 2px 8px rgba(0, 0, 0, 0.2)",
    hudPanel:
      "0 8px 32px rgba(2, 4, 8, 0.6), inset 0 1px 0 rgba(213, 173, 87, 0.03)",
    hudRail:
      "0 -6px 32px rgba(2, 4, 8, 0.6), inset 0 1px 0 rgba(213, 173, 87, 0.03)",
    modal:
      "0 16px 48px rgba(0, 0, 0, 0.5), 0 8px 24px rgba(213, 173, 87, 0.06)",
    glow: "0 0 16px 1px rgba(213, 173, 87, 0.3)",
  },

  motion: {
    fast: { duration: 0.15, ease: "easeOut" },
    normal: { duration: 0.2, ease: "easeOut" },
    spring: { type: "spring", damping: 25, stiffness: 280 },
    ambientDrift: { duration: 10, ease: "linear" },
    ripple: { duration: 2, ease: "easeInOut" },
  },

  ambient: {
    type: "nebula-stars",
    particleColors: [GOLD, STEEL, GOLD_DIM, GREEN],
    particleDensity: 0.35,
    particleSpeed: 0.15,
    particleSizeRange: [1, 2.5] as [number, number],
    horizonGradient: `
      radial-gradient(ellipse at top left, rgba(213, 173, 87, 0.06), transparent 50%),
      radial-gradient(ellipse at bottom right, rgba(126, 139, 167, 0.04), transparent 50%),
      radial-gradient(circle at 30% 70%, rgba(213, 173, 87, 0.02), transparent 40%)
    `,
    rippleColorPrimary: "rgba(213, 173, 87, 0.03)",
    rippleColorSecondary: "rgba(126, 139, 167, 0.02)",
    glowIntensity: 0.4,
  },

  controls: {
    switch: {
      track: {
        bg: {
          on: "rgba(213, 173, 87, 0.2)",
          off: "rgba(255, 255, 255, 0.08)",
        },
        border: {
          on: "rgba(213, 173, 87, 0.4)",
          off: "rgba(255, 255, 255, 0.15)",
        },
      },
      thumb: {
        bg: {
          on: GOLD,
          off: "#7f8494",
        },
        shadow: {
          on: "0 0 8px rgba(213, 173, 87, 0.5)",
          off: "0 1px 2px rgba(0, 0, 0, 0.2)",
        },
      },
    },
    slider: {
      track: {
        bg: "rgba(255, 255, 255, 0.08)",
        border: "rgba(255, 255, 255, 0.15)",
      },
      thumb: {
        bg: GOLD,
        shadow: "0 0 8px rgba(213, 173, 87, 0.5)",
      },
      fill: "rgba(213, 173, 87, 0.6)",
    },
    buttonGlow: {
      hoverBg: "rgba(213, 173, 87, 0.08)",
      hoverText: GOLD,
      hoverShadow: "0 0 10px rgba(213, 173, 87, 0.1)",
    },
  },
};
