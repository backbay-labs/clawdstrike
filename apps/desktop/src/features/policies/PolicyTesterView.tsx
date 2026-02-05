/**
 * PolicyTesterView - Simulate policy checks
 */
import { useState } from "react";
import type { FormEvent } from "react";
import { clsx } from "clsx";
import { useConnection } from "@/context/ConnectionContext";
import { HushdClient, type CheckResponse } from "@/services/hushdClient";
import type { ActionType } from "@/types/events";

interface TestForm {
  actionType: ActionType;
  target: string;
  content: string;
  agentId: string;
}

export function PolicyTesterView() {
  const { status, daemonUrl } = useConnection();

  const [form, setForm] = useState<TestForm>({
    actionType: "file_access",
    target: "",
    content: "",
    agentId: "",
  });

  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!form.target.trim()) return;

    setIsRunning(true);
    setResult(null);
    setError(null);

    try {
      const client = new HushdClient(daemonUrl);
      const response = await client.check({
        action_type: form.actionType,
        target: form.target.trim(),
        content: form.content.trim() || undefined,
        agent_id: form.agentId.trim() || undefined,
      });
      setResult(response);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Check failed");
    } finally {
      setIsRunning(false);
    }
  };

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full text-sdr-text-secondary">
        Not connected to daemon
      </div>
    );
  }

  return (
    <div className="flex h-full">
      {/* Form panel */}
      <div className="w-1/2 border-r border-sdr-border flex flex-col">
        {/* Header */}
        <div className="px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <h1 className="text-lg font-semibold text-sdr-text-primary">Policy Tester</h1>
          <p className="text-sm text-sdr-text-muted mt-0.5">
            Simulate policy checks against the active policy
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Action type */}
          <div>
            <label className="block text-sm font-medium text-sdr-text-primary mb-2">
              Action Type
            </label>
            <div className="grid grid-cols-3 gap-2">
              {ACTION_TYPES.map((type) => (
                <ActionTypeButton
                  key={type.value}
                  type={type}
                  selected={form.actionType === type.value}
                  onClick={() => setForm({ ...form, actionType: type.value })}
                />
              ))}
            </div>
          </div>

          {/* Target */}
          <div>
            <label className="block text-sm font-medium text-sdr-text-primary mb-2">
              Target
            </label>
            <input
              type="text"
              value={form.target}
              onChange={(e) => setForm({ ...form, target: e.target.value })}
              placeholder={getTargetPlaceholder(form.actionType)}
              className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
            />
            <p className="text-xs text-sdr-text-muted mt-1">
              {getTargetHelp(form.actionType)}
            </p>
          </div>

          {/* Content (for file_write, patch) */}
          {(form.actionType === "file_write" || form.actionType === "patch") && (
            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-2">
                Content
              </label>
              <textarea
                value={form.content}
                onChange={(e) => setForm({ ...form, content: e.target.value })}
                placeholder="File content or patch..."
                rows={6}
                className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm resize-none"
              />
            </div>
          )}

          {/* Agent ID (optional) */}
          <div>
            <label className="block text-sm font-medium text-sdr-text-primary mb-2">
              Agent ID <span className="text-sdr-text-muted">(optional)</span>
            </label>
            <input
              type="text"
              value={form.agentId}
              onChange={(e) => setForm({ ...form, agentId: e.target.value })}
              placeholder="agent_coder_001"
              className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono text-sm"
            />
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={isRunning || !form.target.trim()}
            className="w-full px-4 py-2.5 bg-sdr-accent-blue text-white font-medium rounded-md hover:bg-sdr-accent-blue/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isRunning ? "Running Check..." : "Run Check"}
          </button>
        </form>
      </div>

      {/* Result panel */}
      <div className="w-1/2 flex flex-col bg-sdr-bg-primary">
        <div className="px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <h2 className="font-medium text-sdr-text-primary">Result</h2>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {isRunning && (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              <div className="animate-spin w-6 h-6 border-2 border-sdr-accent-blue border-t-transparent rounded-full" />
            </div>
          )}

          {error && (
            <div className="p-4 bg-sdr-accent-red/10 border border-sdr-accent-red/30 rounded-lg">
              <p className="text-sdr-accent-red font-medium">Error</p>
              <p className="text-sm text-sdr-text-secondary mt-1">{error}</p>
            </div>
          )}

          {result && <ResultDisplay result={result} />}

          {!isRunning && !error && !result && (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              Run a check to see results
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const ACTION_TYPES: { value: ActionType; label: string; icon: string }[] = [
  { value: "file_access", label: "File Read", icon: "file" },
  { value: "file_write", label: "File Write", icon: "edit" },
  { value: "egress", label: "Network", icon: "globe" },
  { value: "shell", label: "Shell", icon: "terminal" },
  { value: "mcp_tool", label: "MCP Tool", icon: "tool" },
  { value: "patch", label: "Patch", icon: "diff" },
];

function getTargetPlaceholder(actionType: ActionType): string {
  switch (actionType) {
    case "file_access":
    case "file_write":
    case "patch":
      return "/path/to/file";
    case "egress":
      return "api.example.com:443";
    case "shell":
      return "ls -la";
    case "mcp_tool":
      return "tool_name";
    default:
      return "target";
  }
}

function getTargetHelp(actionType: ActionType): string {
  switch (actionType) {
    case "file_access":
      return "Path to the file being read";
    case "file_write":
      return "Path to the file being written";
    case "egress":
      return "Host and optional port (e.g., api.example.com:443)";
    case "shell":
      return "Shell command to execute";
    case "mcp_tool":
      return "Name of the MCP tool";
    case "patch":
      return "Path to the file being patched";
    default:
      return "";
  }
}

interface ActionTypeButtonProps {
  type: { value: ActionType; label: string };
  selected: boolean;
  onClick: () => void;
}

function ActionTypeButton({ type, selected, onClick }: ActionTypeButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "px-3 py-2 text-sm font-medium rounded-md border transition-colors",
        selected
          ? "bg-sdr-accent-blue/20 border-sdr-accent-blue text-sdr-accent-blue"
          : "bg-sdr-bg-tertiary border-sdr-border text-sdr-text-secondary hover:text-sdr-text-primary"
      )}
    >
      {type.label}
    </button>
  );
}

function ResultDisplay({ result }: { result: CheckResponse }) {
  return (
    <div className="space-y-4">
      {/* Verdict */}
      <div
        className={clsx(
          "p-4 rounded-lg border",
          result.allowed
            ? "bg-verdict-allowed/10 border-verdict-allowed/30"
            : "bg-verdict-blocked/10 border-verdict-blocked/30"
        )}
      >
        <div className="flex items-center gap-2">
          {result.allowed ? (
            <CheckCircleIcon className="w-6 h-6 text-verdict-allowed" />
          ) : (
            <XCircleIcon className="w-6 h-6 text-verdict-blocked" />
          )}
          <span
            className={clsx(
              "text-lg font-semibold",
              result.allowed ? "text-verdict-allowed" : "text-verdict-blocked"
            )}
          >
            {result.allowed ? "ALLOWED" : "BLOCKED"}
          </span>
        </div>
      </div>

      {/* Details */}
      <div className="space-y-3">
        {result.guard && (
          <div>
            <span className="text-xs text-sdr-text-muted uppercase tracking-wide">Guard</span>
            <p className="text-sm text-sdr-text-primary font-mono mt-1">{result.guard}</p>
          </div>
        )}

        {result.severity && (
          <div>
            <span className="text-xs text-sdr-text-muted uppercase tracking-wide">Severity</span>
            <p className="text-sm text-sdr-text-primary mt-1 capitalize">{result.severity}</p>
          </div>
        )}

        {result.message && (
          <div>
            <span className="text-xs text-sdr-text-muted uppercase tracking-wide">Message</span>
            <p className="text-sm text-sdr-text-secondary mt-1">{result.message}</p>
          </div>
        )}

        {result.details && Object.keys(result.details).length > 0 && (
          <div>
            <span className="text-xs text-sdr-text-muted uppercase tracking-wide">Details</span>
            <pre className="text-xs text-sdr-text-secondary mt-1 bg-sdr-bg-tertiary p-2 rounded overflow-x-auto">
              {JSON.stringify(result.details, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function CheckCircleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function XCircleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <path d="M15 9l-6 6M9 9l6 6" />
    </svg>
  );
}
