import { IconShield, IconBraces, IconFile, IconHexagons } from "@tabler/icons-react";
import { FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";

// ---- Props ----

interface FileTypeIconProps {
  fileType: FileType | string;
  size?: number;
  stroke?: number;
  className?: string;
}

// ---- Helpers ----

function getIconColor(fileType: string): string {
  return FILE_TYPE_REGISTRY[fileType as FileType]?.iconColor ?? "#6f7f9a";
}

function getLabel(fileType: string): string {
  return FILE_TYPE_REGISTRY[fileType as FileType]?.label ?? "File";
}

// ---- Component ----

/**
 * Renders a file-type icon or text badge for a given file type.
 *
 * - `clawdstrike_policy` -> IconShield (gold)
 * - `sigma_rule`         -> "SIG" text badge (blue)
 * - `yara_rule`          -> "YAR" text badge (orange)
 * - `ocsf_event`         -> IconBraces (green)
 * - fallback             -> IconFile (neutral gray)
 */
export function FileTypeIcon({
  fileType,
  size = 14,
  stroke = 1.5,
  className,
}: FileTypeIconProps) {
  switch (fileType) {
    case "sigma_rule":
      return (
        <span
          className={className}
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: `${Math.max(7, Math.round(size * 0.5))}px`,
            fontWeight: 700,
            fontFamily: "monospace",
            lineHeight: 1,
            color: getIconColor(fileType),
            width: size,
            height: size,
            borderRadius: 2,
            letterSpacing: "-0.02em",
          }}
          aria-label={getLabel(fileType)}
        >
          SIG
        </span>
      );

    case "yara_rule":
      return (
        <span
          className={className}
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: `${Math.max(7, Math.round(size * 0.5))}px`,
            fontWeight: 700,
            fontFamily: "monospace",
            lineHeight: 1,
            color: getIconColor(fileType),
            width: size,
            height: size,
            borderRadius: 2,
            letterSpacing: "-0.02em",
          }}
          aria-label={getLabel(fileType)}
        >
          YAR
        </span>
      );

    case "clawdstrike_policy":
      return (
        <IconShield
          size={size}
          stroke={stroke}
          style={{ color: getIconColor(fileType) }}
          aria-label={getLabel(fileType)}
          className={className}
        />
      );

    case "ocsf_event":
      return (
        <IconBraces
          size={size}
          stroke={stroke}
          style={{ color: getIconColor(fileType) }}
          aria-label={getLabel(fileType)}
          className={className}
        />
      );

    case "swarm_bundle":
      return (
        <IconHexagons
          size={size}
          stroke={stroke}
          style={{ color: getIconColor(fileType) }}
          aria-label={getLabel(fileType)}
          className={className}
        />
      );

    default:
      return (
        <IconFile
          size={size}
          stroke={stroke}
          style={{ color: "#6f7f9a" }}
          aria-label="File"
          className={className}
        />
      );
  }
}
