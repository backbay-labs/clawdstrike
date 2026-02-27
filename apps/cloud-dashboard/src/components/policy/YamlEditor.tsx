import { useCallback, useRef } from "react";
import { highlightYaml } from "../../utils/yamlHighlight";

interface YamlEditorProps {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
}

export function YamlEditor({ value, onChange, readOnly }: YamlEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const preRef = useRef<HTMLPreElement>(null);

  const syncScroll = useCallback(() => {
    const ta = textareaRef.current;
    const pre = preRef.current;
    if (ta && pre) {
      pre.scrollTop = ta.scrollTop;
      pre.scrollLeft = ta.scrollLeft;
    }
  }, []);

  const lines = value.split("\n");
  const lineCount = lines.length;
  const highlighted = highlightYaml(value);

  return (
    <div
      className="glass-panel rounded-lg"
      style={{
        position: "relative",
        background: "rgba(7,8,10,0.88)",
        height: "100%",
        display: "flex",
      }}
    >
      {/* Line numbers gutter */}
      <div
        className="font-mono"
        style={{
          padding: "12px 0",
          minWidth: 44,
          textAlign: "right",
          fontSize: 13,
          lineHeight: "20px",
          color: "rgba(154,167,181,0.3)",
          userSelect: "none",
          borderRight: "1px solid var(--slate)",
          flexShrink: 0,
          overflow: "hidden",
        }}
      >
        {Array.from({ length: lineCount }, (_, i) => (
          <div key={i} style={{ paddingRight: 8 }}>
            {i + 1}
          </div>
        ))}
      </div>

      {/* Editor area */}
      <div style={{ position: "relative", flex: 1, overflow: "hidden" }}>
        {/* Highlighted overlay */}
        <pre
          ref={preRef}
          className="font-mono"
          aria-hidden
          style={{
            position: "absolute",
            inset: 0,
            margin: 0,
            padding: 12,
            fontSize: 13,
            lineHeight: "20px",
            whiteSpace: "pre",
            overflow: "auto",
            pointerEvents: "none",
            zIndex: 1,
            color: "rgba(229,231,235,0.85)",
          }}
          dangerouslySetInnerHTML={{ __html: highlighted + "\n" }}
        />

        {/* Textarea */}
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onScroll={syncScroll}
          readOnly={readOnly}
          spellCheck={false}
          className="font-mono"
          style={{
            position: "relative",
            display: "block",
            width: "100%",
            height: "100%",
            margin: 0,
            padding: 12,
            fontSize: 13,
            lineHeight: "20px",
            whiteSpace: "pre",
            overflow: "auto",
            background: "transparent",
            color: "transparent",
            caretColor: "var(--gold)",
            border: "none",
            outline: "none",
            resize: "none",
            zIndex: 2,
          }}
        />
      </div>
    </div>
  );
}
