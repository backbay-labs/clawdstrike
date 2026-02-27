const GUARDS = [
  "ForbiddenPathGuard",
  "EgressAllowlistGuard",
  "SecretLeakGuard",
  "PatchIntegrityGuard",
  "McpToolGuard",
  "PromptInjectionGuard",
  "JailbreakGuard",
] as const;

interface GuardSelectorProps {
  value: string;
  onChange: (guard: string) => void;
}

export function GuardSelector({ value, onChange }: GuardSelectorProps) {
  return (
    <div>
      <label
        className="font-mono"
        style={{
          display: "block",
          fontSize: 10,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          color: "rgba(214,177,90,0.6)",
          marginBottom: 6,
        }}
      >
        Select Guard
      </label>
      <select
        className="glass-input font-mono rounded-md"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          width: "100%",
          padding: "8px 12px",
          fontSize: 13,
          color: "var(--text)",
          outline: "none",
          appearance: "none",
          cursor: "pointer",
        }}
      >
        {GUARDS.map((g) => (
          <option key={g} value={g} style={{ background: "var(--obsidian)", color: "var(--text)" }}>
            {g}
          </option>
        ))}
      </select>
    </div>
  );
}
