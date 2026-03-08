/** Micro icons (14px inline) extracted from LensSidebar */
import type { ArtifactKind } from "../huntTypes";
import type { TabKind } from "../workbenchState";

export function PlusIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <path d="M7 3v8M3 7h8" />
    </svg>
  );
}

export function TemplateIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="2" width="10" height="10" rx="1.5" />
      <path d="M2 5.5h10" />
      <path d="M5 5.5v6.5" />
    </svg>
  );
}

export function DocIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 2h5.5L11 4.5V12H3V2z" />
      <path d="M5 7h4M5 9.5h2.5" />
    </svg>
  );
}

export function FolderIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M2 4a1 1 0 011-1h2.5l1 1H11a1 1 0 011 1v5.5a1 1 0 01-1 1H3a1 1 0 01-1-1V4z" />
    </svg>
  );
}

export function ScopeIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <circle cx="7" cy="7" r="4" />
      <circle cx="7" cy="7" r="1" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function FeedIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <path d="M2 10a6 6 0 016-6" />
      <path d="M2 7a3 3 0 013-3" />
      <circle cx="3" cy="11" r="1" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function TerminalIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 5l3 2.5L3 10" />
      <path d="M8 10h3" />
    </svg>
  );
}

export function ReticleIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <circle cx="7" cy="7" r="3.5" />
      <path d="M7 2v2M7 10v2M2 7h2M10 7h2" />
    </svg>
  );
}

export function ArtifactIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M7 2l4.5 2.5v5L7 12l-4.5-2.5v-5L7 2z" />
      <path d="M7 7v5" />
      <path d="M2.5 4.5L7 7l4.5-2.5" />
    </svg>
  );
}

export function RunIcon() {
  return (
    <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 3v8l7-4-7-4z" />
    </svg>
  );
}

export const ARTIFACT_KIND_ICONS: Record<ArtifactKind, () => React.JSX.Element> = {
  signal: ReticleIcon,
  entity: ScopeIcon,
  file: FolderIcon,
  receipt: DocIcon,
  note: DocIcon,
  query: TerminalIcon,
  snapshot: ArtifactIcon,
  evidence: ArtifactIcon,
};

export const TAB_KIND_ICONS: Partial<Record<TabKind, () => React.JSX.Element>> = {
  file: FolderIcon,
  hunt: ReticleIcon,
  receipt: DocIcon,
  policy: DocIcon,
  artifact: ArtifactIcon,
  sandbox: TerminalIcon,
  "signal-thread": ReticleIcon,
  case: DocIcon,
  brief: DocIcon,
  profile: ScopeIcon,
  "threat-radar": ReticleIcon,
  "attack-graph": ArtifactIcon,
  "network-map": ScopeIcon,
  workflow: RunIcon,
  marketplace: ArtifactIcon,
  operations: TerminalIcon,
  welcome: DocIcon,
};
