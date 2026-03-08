/**
 * OrbVisuals - shared visual primitives for orb components.
 */

export function NexusIcon() {
  return (
    <svg
      className="nexus-orb-icon"
      viewBox="0 0 24 24"
      width="28"
      height="28"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" opacity="0.4" />
      <circle cx="12" cy="12" r="5" fill="currentColor" opacity="0.3" />
      <path d="M12 3a9 9 0 0 1 6.36 2.64" opacity="0.6" />
      <circle cx="12" cy="12" r="2" fill="currentColor" />
      <ellipse cx="12" cy="12" rx="9" ry="3" transform="rotate(-30 12 12)" opacity="0.2" />
    </svg>
  );
}
