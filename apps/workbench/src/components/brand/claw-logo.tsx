import { cn } from "@/lib/utils";

export function ClawLogo({
  className,
  size = 24,
}: {
  className?: string;
  size?: number;
}) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      width={size}
      height={size}
      className={cn("shrink-0", className)}
    >
      {/* Gothic frame (barbed diamond) */}
      <path
        d="M12 3.3 L17.6 8.9 L20.7 12 L17.6 15.1 L12 20.7 L6.4 15.1 L3.3 12 L6.4 8.9 Z"
        stroke="#d4a84b"
        strokeWidth="2"
        strokeLinejoin="miter"
      />

      {/* tooth notches */}
      <path d="M12 3.3 L11.2 5.0 L12.8 5.0 Z" fill="#d4a84b" />
      <path d="M20.7 12 L19.0 11.2 L19.0 12.8 Z" fill="#d4a84b" />
      <path d="M12 20.7 L12.8 19.0 L11.2 19.0 Z" fill="#d4a84b" />
      <path d="M3.3 12 L5.0 12.8 L5.0 11.2 Z" fill="#d4a84b" />

      {/* inner bind ring */}
      <circle cx="12" cy="12" r="1.35" stroke="#d4a84b" strokeWidth="2" />

      {/* three claw slashes */}
      <path
        d="M8.2 7.9 L6.9 16.0"
        stroke="#d4a84b"
        strokeWidth="2"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />
      <path
        d="M12 7.2 L12 16.8"
        stroke="#d4a84b"
        strokeWidth="2"
        strokeLinecap="square"
      />
      <path
        d="M15.8 7.9 L17.1 16.0"
        stroke="#d4a84b"
        strokeWidth="2"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />

      {/* crown barbs */}
      <path
        d="M9.7 6.9 L10.2 8.0"
        stroke="#d4a84b"
        strokeWidth="2"
        strokeLinecap="square"
        opacity="0.9"
      />
      <path
        d="M14.3 6.9 L13.8 8.0"
        stroke="#d4a84b"
        strokeWidth="2"
        strokeLinecap="square"
        opacity="0.9"
      />
    </svg>
  );
}
