/**
 * Clawdstrike Sidebar Sigils — Custom SVG icon set.
 *
 * Design language: geometric, angular, diamond motifs,
 * thin precise strokes. Built to match the System Heartbeat sigil.
 */

import type { CSSProperties } from "react";

export interface SigilProps {
  size?: number;
  stroke?: number;
  className?: string;
  style?: CSSProperties;
}

/** Shared SVG root attributes. */
const base = (p: SigilProps) => ({
  width: p.size ?? 24,
  height: p.size ?? 24,
  viewBox: "0 0 24 24",
  fill: "none" as const,
  stroke: "currentColor",
  strokeWidth: p.stroke ?? 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  className: p.className,
  style: p.style,
});


/** Sentinel — watchful eye with diamond iris */
export function SigilSentinel(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M2 12 Q12 4 22 12 Q12 20 2 12Z" />
      <path d="M12 9.5 L14.5 12 L12 14.5 L9.5 12Z" />
    </svg>
  );
}

/** Findings & Intel — diamond target with crosshairs */
export function SigilFindings(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M12 3 L20 12 L12 21 L4 12Z" />
      <line x1="12" y1="7" x2="12" y2="17" />
      <line x1="7" y1="12" x2="17" y2="12" />
    </svg>
  );
}

/** Lab — geometric flask with reaction line */
export function SigilLab(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M9 3 V9 L4 20 H20 L15 9 V3" />
      <line x1="8" y1="3" x2="16" y2="3" />
      <line x1="6.5" y1="15" x2="17.5" y2="15" />
    </svg>
  );
}

/** Swarms — three connected diamond nodes */
export function SigilSwarms(p: SigilProps) {
  return (
    <svg {...base(p)}>
      {/* Node diamonds */}
      <path d="M7 4 L9.5 7 L7 10 L4.5 7Z" />
      <path d="M17 4 L19.5 7 L17 10 L14.5 7Z" />
      <path d="M12 14 L14.5 17 L12 20 L9.5 17Z" />
      {/* Connections */}
      <line x1="9.5" y1="7" x2="14.5" y2="7" />
      <line x1="7" y1="10" x2="9.5" y2="17" />
      <line x1="17" y1="10" x2="14.5" y2="17" />
    </svg>
  );
}

/** Missions — routed objective marker with waypoint rails */
export function SigilMission(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M6 4 L18 4 L14 10 L18 16 L6 16 Z" />
      <line x1="6" y1="4" x2="6" y2="21" />
      <path d="M10 8 L12 10 L10 12" />
    </svg>
  );
}


/** Editor — code brackets with diamond cursor */
export function SigilEditor(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <polyline points="9,5 4,12 9,19" />
      <polyline points="15,5 20,12 15,19" />
      <path d="M12 8 L14 12 L12 16 L10 12Z" />
    </svg>
  );
}

/** Library — book with spine and index lines */
export function SigilLibrary(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <rect x="4" y="2" width="16" height="20" rx="1.5" />
      <line x1="8" y1="2" x2="8" y2="22" />
      <line x1="11" y1="7" x2="17" y2="7" />
      <line x1="11" y1="11" x2="17" y2="11" />
      <line x1="11" y1="15" x2="15" y2="15" />
    </svg>
  );
}


/** Compliance — shield with checkmark */
export function SigilCompliance(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M12 2 L20 6 V12 C20 17 12 22 12 22 C12 22 4 17 4 12 V6Z" />
      <polyline points="9,12 11,15 16,9" />
    </svg>
  );
}

/** Approvals — hexagonal seal with diamond stamp */
export function SigilApprovals(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M12 3 L19 7 V15 L12 19 L5 15 V7Z" />
      <path d="M12 8 L15 12 L12 16 L9 12Z" />
    </svg>
  );
}

/** Audit — magnifying glass with scan lines */
export function SigilAudit(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <line x1="15.5" y1="15.5" x2="21" y2="21" />
      <line x1="7.5" y1="9" x2="13.5" y2="9" />
      <line x1="7.5" y1="12" x2="12" y2="12" />
    </svg>
  );
}

/** Receipts — document with fold corner and seal */
export function SigilReceipts(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M6 2 H14 L18 6 V22 H6Z" />
      <path d="M14 2 V6 H18" />
      <circle cx="14" cy="17" r="2.5" />
    </svg>
  );
}

/** Fleet — server stack with status indicators */
export function SigilFleet(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <rect x="3" y="2" width="18" height="5" rx="1" />
      <rect x="3" y="9.5" width="18" height="5" rx="1" />
      <rect x="3" y="17" width="18" height="5" rx="1" />
      <circle cx="6.5" cy="4.5" r="1" fill="currentColor" stroke="none" />
      <circle cx="6.5" cy="12" r="1" fill="currentColor" stroke="none" />
      <circle cx="6.5" cy="19.5" r="1" fill="currentColor" stroke="none" />
    </svg>
  );
}

/** Topology — network hierarchy graph */
export function SigilTopology(p: SigilProps) {
  return (
    <svg {...base(p)}>
      {/* Connections first (behind nodes) */}
      <line x1="12" y1="6.5" x2="5" y2="11.5" />
      <line x1="12" y1="6.5" x2="19" y2="11.5" />
      <line x1="5" y1="16.5" x2="12" y2="19" />
      <line x1="19" y1="16.5" x2="12" y2="19" />
      {/* Nodes */}
      <circle cx="12" cy="4" r="2.5" />
      <circle cx="5" cy="14" r="2.5" />
      <circle cx="19" cy="14" r="2.5" />
      <circle cx="12" cy="21" r="2" />
    </svg>
  );
}


/** Observatory — ring with station dots (minimap motif) */
export function SigilObservatory(p: SigilProps) {
  return (
    <svg {...base(p)}>
      {/* outer ring */}
      <circle cx="12" cy="12" r="9" fill="none" />
      {/* center core */}
      <circle cx="12" cy="12" r="2" />
      {/* 5 station dots on ring */}
      <circle cx="12" cy="3" r="1.2" />
      <circle cx="20.5" cy="7.5" r="1.2" />
      <circle cx="20.5" cy="16.5" r="1.2" />
      <circle cx="3.5" cy="16.5" r="1.2" />
      <circle cx="3.5" cy="7.5" r="1.2" />
    </svg>
  );
}

/** Settings — diamond core with radiating control lines */
export function SigilSettings(p: SigilProps) {
  return (
    <svg {...base(p)}>
      <path d="M12 8 L16 12 L12 16 L8 12Z" />
      <line x1="12" y1="2" x2="12" y2="6" />
      <line x1="12" y1="18" x2="12" y2="22" />
      <line x1="2" y1="12" x2="6" y2="12" />
      <line x1="18" y1="12" x2="22" y2="12" />
      <line x1="5.8" y1="5.8" x2="8.5" y2="8.5" />
      <line x1="15.5" y1="15.5" x2="18.2" y2="18.2" />
      <line x1="5.8" y1="18.2" x2="8.5" y2="15.5" />
      <line x1="15.5" y1="8.5" x2="18.2" y2="5.8" />
    </svg>
  );
}

/** Hunt — crosshair target with center dot (recon/hunt motif) */
export function SigilHunt(p: SigilProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...base(p)}
    >
      {/* Crosshair target */}
      <circle cx="12" cy="12" r="6" />
      <line x1="12" y1="2" x2="12" y2="6" />
      <line x1="12" y1="18" x2="12" y2="22" />
      <line x1="2" y1="12" x2="6" y2="12" />
      <line x1="18" y1="12" x2="22" y2="12" />
      <circle cx="12" cy="12" r="1.5" />
    </svg>
  );
}
