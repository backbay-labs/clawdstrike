import { useState } from "react";
import type { HushdInstance } from "../../hooks/useMultiInstance";
import { GlassButton } from "../ui";

const INPUT_FOCUS_CSS =
  "glass-input font-body rounded-md px-3 py-2 text-sm outline-none transition-colors duration-150 focus:ring-1 placeholder:text-[rgba(100,116,139,0.5)]";

const focusRingStyle = {
  "--tw-ring-color": "rgba(214,177,90,0.4)",
} as React.CSSProperties;

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="font-mono text-[10px]"
      style={{
        color: "rgba(214,177,90,0.55)",
        textTransform: "uppercase",
        letterSpacing: "0.1em",
      }}
    >
      {children}
    </span>
  );
}

export function MultiInstance({
  instances,
  activeId,
  onAdd,
  onRemove,
  onSwitch,
}: {
  instances: HushdInstance[];
  activeId: string;
  onAdd: (inst: Omit<HushdInstance, "id">) => void;
  onRemove: (id: string) => void;
  onSwitch: (id: string) => void;
}) {
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newApiKey, setNewApiKey] = useState("");

  function handleAdd() {
    if (!newName.trim() || !newUrl.trim()) return;
    onAdd({ name: newName.trim(), url: newUrl.trim(), apiKey: newApiKey.trim() });
    setNewName("");
    setNewUrl("");
    setNewApiKey("");
  }

  return (
    <div className="relative z-10 space-y-4">
      {instances.length > 0 ? (
        <div className="space-y-2">
          {instances.map((inst) => {
            const isActive = inst.id === activeId;
            return (
              <div
                key={inst.id}
                className="glass-panel flex items-center gap-3 rounded-md p-3"
                style={{
                  borderColor: isActive
                    ? "rgba(214,177,90,0.35)"
                    : "rgba(27,34,48,0.6)",
                }}
              >
                {isActive && (
                  <span
                    className="rounded-full"
                    style={{
                      width: 8,
                      height: 8,
                      background: "#d6b15a",
                      flexShrink: 0,
                    }}
                  />
                )}
                <div className="flex-1 min-w-0">
                  <p
                    className="font-mono text-sm"
                    style={{ color: "rgba(229,231,235,0.9)" }}
                  >
                    {inst.name}
                  </p>
                  <p
                    className="font-body truncate text-xs"
                    style={{ color: "rgba(229,231,235,0.4)" }}
                  >
                    {inst.url}
                  </p>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  {!isActive && (
                    <GlassButton onClick={() => onSwitch(inst.id)}>Switch</GlassButton>
                  )}
                  <button
                    type="button"
                    onClick={() => onRemove(inst.id)}
                    className="font-mono rounded-md px-3 py-2 text-xs"
                    style={{
                      background: "rgba(194,59,59,0.08)",
                      border: "1px solid rgba(194,59,59,0.2)",
                      color: "#c23b3b",
                      cursor: "pointer",
                    }}
                  >
                    Remove
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p
          className="font-body text-sm"
          style={{ color: "rgba(229,231,235,0.4)" }}
        >
          No instances configured. Add one below to manage multiple hushd connections.
        </p>
      )}

      <div className="glass-panel rounded-md p-4 space-y-3">
        <p
          className="font-mono text-xs"
          style={{ color: "rgba(229,231,235,0.6)", letterSpacing: "0.05em" }}
        >
          Add Instance
        </p>
        <div className="space-y-3">
          <label className="flex flex-col gap-1">
            <FieldLabel>Name</FieldLabel>
            <input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Production"
              className={INPUT_FOCUS_CSS}
              style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
            />
          </label>
          <label className="flex flex-col gap-1">
            <FieldLabel>hushd URL</FieldLabel>
            <input
              type="url"
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
              placeholder="http://localhost:9876"
              className={INPUT_FOCUS_CSS}
              style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
            />
          </label>
          <label className="flex flex-col gap-1">
            <FieldLabel>API Key (optional)</FieldLabel>
            <input
              type="password"
              value={newApiKey}
              onChange={(e) => setNewApiKey(e.target.value)}
              placeholder="Bearer token"
              className={INPUT_FOCUS_CSS}
              style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
            />
          </label>
          <GlassButton onClick={handleAdd}>Add Instance</GlassButton>
        </div>
      </div>
    </div>
  );
}
