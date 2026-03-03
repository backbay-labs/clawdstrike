import { useMemo } from "react";
import { type DiffLine, diffLines } from "../../utils/simpleDiff";
import { GlassButton, NoiseGrain } from "../ui";

interface PolicyDiffViewerProps {
  oldYaml: string;
  newYaml: string;
  onClose: () => void;
}

export function PolicyDiffViewer({ oldYaml, newYaml, onClose }: PolicyDiffViewerProps) {
  const diff = useMemo(() => diffLines(oldYaml, newYaml), [oldYaml, newYaml]);

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 40,
        display: "flex",
        flexDirection: "column",
        background: "rgba(11,13,16,0.98)",
        backdropFilter: "blur(24px)",
      }}
    >
      <NoiseGrain />

      {/* Header */}
      <div
        style={{
          position: "relative",
          zIndex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          borderBottom: "1px solid var(--slate)",
        }}
      >
        <h2
          className="font-mono"
          style={{
            fontSize: 12,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            color: "var(--gold)",
            margin: 0,
          }}
        >
          Policy Diff
        </h2>
        <GlassButton onClick={onClose}>Close</GlassButton>
      </div>

      {/* Diff columns */}
      <div
        style={{
          position: "relative",
          zIndex: 1,
          flex: 1,
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 1,
          overflow: "hidden",
          background: "var(--slate)",
        }}
      >
        <DiffColumn label="Previous" lines={diff.left} />
        <DiffColumn label="Current" lines={diff.right} />
      </div>
    </div>
  );
}

function DiffColumn({ label, lines }: { label: string; lines: DiffLine[] }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        background: "rgba(7,8,10,0.95)",
        overflow: "hidden",
      }}
    >
      <div
        className="font-mono"
        style={{
          padding: "8px 12px",
          fontSize: 10,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          color: "var(--muted)",
          borderBottom: "1px solid var(--slate)",
          flexShrink: 0,
        }}
      >
        {label}
      </div>
      <div style={{ flex: 1, overflow: "auto", padding: "4px 0" }}>
        {lines.map((line, idx) => (
          <DiffLineRow key={idx} line={line} />
        ))}
      </div>
    </div>
  );
}

function DiffLineRow({ line }: { line: DiffLine }) {
  let bg = "transparent";
  let borderLeft = "2px solid transparent";

  if (line.type === "added") {
    bg = "rgba(45,170,106,0.08)";
    borderLeft = "2px solid var(--stamp-allowed)";
  } else if (line.type === "removed") {
    bg = "rgba(194,59,59,0.08)";
    borderLeft = "2px solid var(--stamp-blocked)";
  }

  return (
    <div
      className="font-mono"
      style={{
        display: "flex",
        fontSize: 12,
        lineHeight: "20px",
        background: bg,
        borderLeft,
      }}
    >
      <span
        style={{
          width: 40,
          textAlign: "right",
          paddingRight: 8,
          color: "rgba(154,167,181,0.3)",
          userSelect: "none",
          flexShrink: 0,
        }}
      >
        {line.lineNumber}
      </span>
      <span
        style={{
          whiteSpace: "pre",
          color:
            line.type === "added"
              ? "var(--stamp-allowed)"
              : line.type === "removed"
                ? "var(--stamp-blocked)"
                : "rgba(229,231,235,0.85)",
          paddingRight: 12,
        }}
      >
        {line.content}
      </span>
    </div>
  );
}
