import { useState } from "react";
import type { AlertRule } from "../../hooks/useAlertRules";
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

export function AlertRules({
  rules,
  onAdd,
  onRemove,
  onUpdate,
  triggered,
}: {
  rules: AlertRule[];
  onAdd: (rule: Omit<AlertRule, "id">) => void;
  onRemove: (id: string) => void;
  onUpdate: (id: string, updates: Partial<AlertRule>) => void;
  triggered: boolean;
}) {
  const [newThreshold, setNewThreshold] = useState("5");
  const [newWindow, setNewWindow] = useState("10");
  const [newWebhook, setNewWebhook] = useState("");

  function handleAdd() {
    const threshold = parseInt(newThreshold, 10);
    const windowMinutes = parseInt(newWindow, 10);
    if (isNaN(threshold) || isNaN(windowMinutes) || threshold < 1 || windowMinutes < 1) return;
    onAdd({
      threshold,
      windowMinutes,
      webhookUrl: newWebhook.trim() || undefined,
      enabled: true,
    });
    setNewThreshold("5");
    setNewWindow("10");
    setNewWebhook("");
  }

  return (
    <div className="relative z-10 space-y-4">
      {triggered && (
        <div
          className="glass-panel rounded-md p-3 text-sm"
          style={{
            borderColor: "rgba(194,59,59,0.4)",
            color: "#c23b3b",
          }}
        >
          Alert triggered — violation threshold exceeded
        </div>
      )}

      {rules.length > 0 && (
        <div className="space-y-3">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="glass-panel rounded-md p-3"
              style={{
                opacity: rule.enabled ? 1 : 0.5,
                borderColor: rule.enabled
                  ? "rgba(27,34,48,0.6)"
                  : "rgba(27,34,48,0.3)",
              }}
            >
              <div className="flex items-center gap-3 flex-wrap">
                <label className="flex flex-col gap-1">
                  <FieldLabel>Threshold</FieldLabel>
                  <input
                    type="number"
                    min={1}
                    value={rule.threshold}
                    onChange={(e) =>
                      onUpdate(rule.id, { threshold: parseInt(e.target.value, 10) || 1 })
                    }
                    className={INPUT_FOCUS_CSS}
                    style={{ ...focusRingStyle, width: 80, color: "rgba(229,231,235,0.92)" }}
                  />
                </label>

                <label className="flex flex-col gap-1">
                  <FieldLabel>Window (min)</FieldLabel>
                  <input
                    type="number"
                    min={1}
                    value={rule.windowMinutes}
                    onChange={(e) =>
                      onUpdate(rule.id, { windowMinutes: parseInt(e.target.value, 10) || 1 })
                    }
                    className={INPUT_FOCUS_CSS}
                    style={{ ...focusRingStyle, width: 80, color: "rgba(229,231,235,0.92)" }}
                  />
                </label>

                <label className="flex flex-col gap-1 flex-1 min-w-[150px]">
                  <FieldLabel>Webhook URL</FieldLabel>
                  <input
                    type="url"
                    value={rule.webhookUrl || ""}
                    onChange={(e) =>
                      onUpdate(rule.id, { webhookUrl: e.target.value || undefined })
                    }
                    placeholder="https://..."
                    className={INPUT_FOCUS_CSS}
                    style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
                  />
                </label>

                <div className="flex items-end gap-2 self-end">
                  <button
                    type="button"
                    onClick={() => onUpdate(rule.id, { enabled: !rule.enabled })}
                    className="font-mono rounded-md px-3 py-2 text-xs"
                    style={{
                      background: rule.enabled
                        ? "rgba(45,170,106,0.1)"
                        : "rgba(100,116,139,0.1)",
                      border: "1px solid rgba(27,34,48,0.5)",
                      color: rule.enabled ? "#2daa6a" : "rgba(229,231,235,0.4)",
                      cursor: "pointer",
                    }}
                  >
                    {rule.enabled ? "ON" : "OFF"}
                  </button>
                  <button
                    type="button"
                    onClick={() => onRemove(rule.id)}
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
            </div>
          ))}
        </div>
      )}

      {rules.length === 0 && (
        <p
          className="font-body text-sm"
          style={{ color: "rgba(229,231,235,0.4)" }}
        >
          No alert rules configured. Add one below.
        </p>
      )}

      <div className="glass-panel rounded-md p-4 space-y-3">
        <p
          className="font-mono text-xs"
          style={{ color: "rgba(229,231,235,0.6)", letterSpacing: "0.05em" }}
        >
          New Rule
        </p>
        <div className="flex items-end gap-3 flex-wrap">
          <label className="flex flex-col gap-1">
            <FieldLabel>Threshold</FieldLabel>
            <input
              type="number"
              min={1}
              value={newThreshold}
              onChange={(e) => setNewThreshold(e.target.value)}
              className={INPUT_FOCUS_CSS}
              style={{ ...focusRingStyle, width: 80, color: "rgba(229,231,235,0.92)" }}
            />
          </label>
          <label className="flex flex-col gap-1">
            <FieldLabel>Window (min)</FieldLabel>
            <input
              type="number"
              min={1}
              value={newWindow}
              onChange={(e) => setNewWindow(e.target.value)}
              className={INPUT_FOCUS_CSS}
              style={{ ...focusRingStyle, width: 80, color: "rgba(229,231,235,0.92)" }}
            />
          </label>
          <label className="flex flex-col gap-1 flex-1 min-w-[150px]">
            <FieldLabel>Webhook URL (optional)</FieldLabel>
            <input
              type="url"
              value={newWebhook}
              onChange={(e) => setNewWebhook(e.target.value)}
              placeholder="https://..."
              className={INPUT_FOCUS_CSS}
              style={{ ...focusRingStyle, color: "rgba(229,231,235,0.92)" }}
            />
          </label>
          <GlassButton onClick={handleAdd}>Add Rule</GlassButton>
        </div>
      </div>
    </div>
  );
}
