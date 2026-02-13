export const SHELL_OPEN_COMMAND_PALETTE_EVENT = "shell:open-command-palette";
export const SHELL_EXECUTE_HOT_COMMAND_EVENT = "shell:execute-hot-command";
export const SHELL_FOCUS_AGENT_SESSION_EVENT = "shell:focus-agent-session";

export type ShellFocusAgentSessionDetail = {
  sessionKey?: string;
  agentId?: string;
};

export function dispatchShellOpenCommandPalette() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(SHELL_OPEN_COMMAND_PALETTE_EVENT));
}

export function dispatchShellExecuteHotCommand(detail: { id: string; payload: string }) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(SHELL_EXECUTE_HOT_COMMAND_EVENT, { detail }));
}

export function dispatchShellFocusAgentSession(detail: ShellFocusAgentSessionDetail) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(SHELL_FOCUS_AGENT_SESSION_EVENT, { detail }));
}
