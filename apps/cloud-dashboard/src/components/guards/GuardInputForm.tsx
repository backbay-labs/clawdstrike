import { useState, useEffect } from "react";
import { GlassButton } from "../ui";

interface GuardInputFormProps {
  guard: string;
  onSubmit: (input: Record<string, unknown>) => void;
}

interface FieldConfig {
  name: string;
  label: string;
  type: "text" | "textarea";
  placeholder: string;
}

const GUARD_FIELDS: Record<string, FieldConfig[]> = {
  ForbiddenPathGuard: [
    { name: "path", label: "File Path", type: "text", placeholder: "/etc/passwd" },
  ],
  EgressAllowlistGuard: [
    { name: "domain", label: "Domain", type: "text", placeholder: "api.example.com" },
  ],
  SecretLeakGuard: [
    { name: "content", label: "File Content", type: "textarea", placeholder: "Paste file content to scan for secrets..." },
  ],
  PatchIntegrityGuard: [
    { name: "patch", label: "Patch Content", type: "textarea", placeholder: "Paste unified diff / patch content..." },
  ],
  McpToolGuard: [
    { name: "tool_name", label: "Tool Name", type: "text", placeholder: "filesystem.read" },
  ],
  PromptInjectionGuard: [
    { name: "prompt", label: "Prompt", type: "textarea", placeholder: "Enter prompt text to test..." },
  ],
  JailbreakGuard: [
    { name: "message", label: "Message", type: "textarea", placeholder: "Enter message to test for jailbreak..." },
  ],
};

export function GuardInputForm({ guard, onSubmit }: GuardInputFormProps) {
  const fields = GUARD_FIELDS[guard] ?? [];
  const [values, setValues] = useState<Record<string, string>>({});

  // Reset values when guard changes
  useEffect(() => { setValues({}); }, [guard]);

  const handleChange = (name: string, value: string) => {
    setValues((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = () => {
    const input: Record<string, unknown> = {};
    for (const field of fields) {
      input[field.name] = values[field.name] ?? "";
    }
    // Map fields to standard API fields
    if (input.path) input.target = input.path;
    if (input.domain) input.target = input.domain;
    if (input.tool_name) input.target = input.tool_name;
    onSubmit(input);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {fields.map((field) => (
        <div key={field.name}>
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
            {field.label}
          </label>
          {field.type === "textarea" ? (
            <textarea
              className="glass-input font-mono rounded-md"
              placeholder={field.placeholder}
              value={values[field.name] ?? ""}
              onChange={(e) => handleChange(field.name, e.target.value)}
              rows={6}
              style={{
                width: "100%",
                padding: "8px 12px",
                fontSize: 13,
                color: "var(--text)",
                outline: "none",
                resize: "vertical",
              }}
            />
          ) : (
            <input
              type="text"
              className="glass-input font-mono rounded-md"
              placeholder={field.placeholder}
              value={values[field.name] ?? ""}
              onChange={(e) => handleChange(field.name, e.target.value)}
              style={{
                width: "100%",
                padding: "8px 12px",
                fontSize: 13,
                color: "var(--text)",
                outline: "none",
              }}
            />
          )}
        </div>
      ))}

      <div style={{ marginTop: 4 }}>
        <GlassButton onClick={handleSubmit}>Test Guard</GlassButton>
      </div>
    </div>
  );
}
