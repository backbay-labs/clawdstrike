import { useCallback, useState } from "react";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Button as MovingBorderButton } from "@/components/ui/moving-border";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import type {
  TestScenario,
  TestActionType,
  Verdict,
  ThreatSeverity,
  AgentProfile,
  AgentRuntime,
  OriginContext,
  OriginProvider,
  SpaceType,
  Visibility,
  ProvenanceConfidence,
  ActorType,
} from "@/lib/workbench/types";
import { IconWorld, IconChevronDown, IconBolt, IconUser, IconX, IconPlug } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

const ACTION_TYPES: { value: TestActionType; label: string }[] = [
  { value: "file_access", label: "File Access" },
  { value: "file_write", label: "File Write" },
  { value: "network_egress", label: "Network Egress" },
  { value: "shell_command", label: "Shell Command" },
  { value: "mcp_tool_call", label: "MCP Tool Call" },
  { value: "patch_apply", label: "Patch Apply" },
  { value: "user_input", label: "User Input" },
];

const VERDICT_OPTIONS: { value: Verdict | "none"; label: string }[] = [
  { value: "none", label: "No expectation" },
  { value: "allow", label: "Allow" },
  { value: "deny", label: "Deny" },
  { value: "warn", label: "Warn" },
];

const SEVERITY_OPTIONS: { value: ThreatSeverity | "none"; label: string }[] = [
  { value: "none", label: "Unclassified" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const AGENT_RUNTIME_OPTIONS: { value: AgentRuntime; label: string }[] = [
  { value: "claude", label: "Claude" },
  { value: "gpt-4", label: "GPT-4" },
  { value: "gemini", label: "Gemini" },
  { value: "llama", label: "Llama" },
  { value: "mistral", label: "Mistral" },
  { value: "custom", label: "Custom" },
];

interface ScenarioBuilderProps {
  scenario: TestScenario;
  onChange: (scenario: TestScenario) => void;
  onRun: (scenario: TestScenario) => void;
  isCreating: boolean;
}

export function ScenarioBuilder({
  scenario,
  onChange,
  onRun,
  isCreating,
}: ScenarioBuilderProps) {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const activeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const isV14 = (editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }).version === "1.4.0";
  const hasOrigins = Boolean((editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} }).origins);

  const update = useCallback(
    (patch: Partial<TestScenario>) => {
      onChange({ ...scenario, ...patch });
    },
    [scenario, onChange],
  );

  const updatePayload = useCallback(
    (key: string, value: unknown) => {
      onChange({ ...scenario, payload: { ...scenario.payload, [key]: value } });
    },
    [scenario, onChange],
  );

  const handleActionTypeChange = useCallback(
    (value: TestActionType) => {
      // Reset payload when action type changes
      const defaults: Record<TestActionType, Record<string, unknown>> = {
        file_access: { path: "" },
        file_write: { path: "", content: "" },
        network_egress: { host: "", port: 443 },
        shell_command: { command: "" },
        mcp_tool_call: { tool: "", args: {} },
        patch_apply: { path: "", content: "" },
        user_input: { text: "" },
      };
      onChange({
        ...scenario,
        actionType: value,
        payload: defaults[value],
      });
    },
    [scenario, onChange],
  );

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="font-syne font-bold text-lg text-[#ece7dc] mb-6">
        {isCreating ? "New Probe Scenario" : "Edit Probe Scenario"}
      </h2>

      <div className="space-y-5">
        {/* Agent Profile Section */}
        <AgentProfileSection
          agentProfile={scenario.agentProfile}
          onChange={(profile) => update({ agentProfile: profile })}
        />

        {/* Name */}
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
            Scenario Name
          </label>
          <Input
            value={scenario.name}
            onChange={(e) => update({ name: e.target.value })}
            placeholder="e.g. SSH Key Exfiltration Probe"
            className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] placeholder:text-[#6f7f9a]/50"
          />
        </div>

        {/* Description */}
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
            Description
          </label>
          <Input
            value={scenario.description}
            onChange={(e) => update({ description: e.target.value })}
            placeholder="What attack surface or behavior does this probe target?"
            className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] placeholder:text-[#6f7f9a]/50"
          />
        </div>

        {/* Severity + MITRE Ref row */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
              Threat Severity
            </label>
            <Select
              value={scenario.severity ?? "none"}
              onValueChange={(val) =>
                update({
                  severity: val === "none" ? undefined : (val as ThreatSeverity),
                })
              }
            >
              <SelectTrigger className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {SEVERITY_OPTIONS.map((s) => (
                  <SelectItem key={s.value} value={s.value}>
                    {s.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
              Threat Reference
            </label>
            <Input
              value={scenario.threatRef ?? ""}
              onChange={(e) => update({ threatRef: e.target.value || undefined })}
              placeholder="e.g. T1552.004"
              className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </div>
        </div>

        {/* Action Type */}
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
            Action Type
          </label>
          <Select
            value={scenario.actionType}
            onValueChange={(val) => handleActionTypeChange(val as TestActionType)}
          >
            <SelectTrigger className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-[#131721] border-[#2d3240]">
              {ACTION_TYPES.map((at) => (
                <SelectItem key={at.value} value={at.value}>
                  {at.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Dynamic payload fields */}
        <div className="border border-[#2d3240] rounded-lg p-4 bg-[#0b0d13]/50">
          <h3 className="text-xs font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
            Probe Payload
          </h3>
          <PayloadFields
            actionType={scenario.actionType}
            payload={scenario.payload}
            onUpdate={updatePayload}
          />
        </div>

        {/* Expected verdict */}
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
            Expected Verdict
          </label>
          <Select
            value={scenario.expectedVerdict ?? "none"}
            onValueChange={(val) =>
              update({
                expectedVerdict: val === "none" ? undefined : (val as Verdict),
              })
            }
          >
            <SelectTrigger className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-[#131721] border-[#2d3240]">
              {VERDICT_OPTIONS.map((v) => (
                <SelectItem key={v.value} value={v.value}>
                  {v.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Origin Context (v1.4.0 only, when origins are configured) */}
        {isV14 && hasOrigins && (
          <OriginContextSection
            originContext={scenario.originContext}
            onChange={(ctx) => update({ originContext: ctx })}
          />
        )}

        {/* Run button */}
        <div className="pt-2">
          <MovingBorderButton
            onClick={() => onRun(scenario)}
            containerClassName="h-10 w-full"
            borderClassName="bg-[radial-gradient(#d4a84b_40%,transparent_60%)]"
            className="bg-[#0b0d13] border-[#2d3240] text-[#d4a84b] font-syne font-bold text-sm"
            borderRadius="0.5rem"
          >
            <IconBolt size={15} stroke={2} className="mr-1.5 inline-block" />
            Execute Probe
          </MovingBorderButton>
          <p className="text-[9px] font-mono text-[#6f7f9a]/40 text-center mt-1.5">
            Ctrl+Enter
          </p>
        </div>
      </div>
    </div>
  );
}


const DEFAULT_AGENT_PROFILE: AgentProfile = {
  agentName: "autonomous-agent-01",
  agentType: "claude",
};

function AgentProfileSection({
  agentProfile,
  onChange,
}: {
  agentProfile: AgentProfile | undefined;
  onChange: (profile: AgentProfile | undefined) => void;
}) {
  const { connection, agents } = useFleetConnection();
  const isConnected = connection.connected;
  const [permissionInput, setPermissionInput] = useState("");

  const profile = agentProfile ?? DEFAULT_AGENT_PROFILE;

  const updateProfile = useCallback(
    (patch: Partial<AgentProfile>) => {
      onChange({ ...profile, ...patch });
    },
    [profile, onChange],
  );

  const handleFleetAgentSelect = useCallback(
    (agentId: string | null) => {
      if (!agentId || agentId === "__custom__") {
        onChange({
          agentName: "",
          agentType: profile.agentType,
          permissions: profile.permissions,
        });
        return;
      }
      const agent = agents.find((a) => a.endpoint_agent_id === agentId);
      if (agent) {
        onChange({
          agentId: agent.endpoint_agent_id,
          agentName: agent.endpoint_agent_id,
          agentType: profile.agentType,
          permissions: profile.permissions,
        });
      }
    },
    [agents, profile, onChange],
  );

  const addPermission = useCallback(
    (tag: string) => {
      const trimmed = tag.trim();
      if (!trimmed) return;
      const existing = profile.permissions ?? [];
      if (existing.includes(trimmed)) return;
      updateProfile({ permissions: [...existing, trimmed] });
    },
    [profile, updateProfile],
  );

  const removePermission = useCallback(
    (tag: string) => {
      const existing = profile.permissions ?? [];
      updateProfile({ permissions: existing.filter((p) => p !== tag) });
    },
    [profile, updateProfile],
  );

  const handlePermissionKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter" || e.key === ",") {
        e.preventDefault();
        addPermission(permissionInput);
        setPermissionInput("");
      }
    },
    [permissionInput, addPermission],
  );

  return (
    <div className="border border-[#2d3240] rounded-lg p-4 bg-[#0b0d13]/50">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <IconUser size={13} stroke={1.5} className="text-[#d4a84b]" />
          <h3 className="text-xs font-mono uppercase tracking-wider text-[#6f7f9a]">
            Agent Profile
          </h3>
        </div>
        {isConnected && (
          <div className="flex items-center gap-1">
            <IconPlug size={10} stroke={1.5} className="text-[#3dbf84]" />
            <span className="text-[9px] font-mono text-[#3dbf84]/70">fleet</span>
          </div>
        )}
      </div>

      <div className="space-y-3">
        {/* Agent name / fleet selector */}
        <div>
          <label className="block text-[10px] font-mono text-[#6f7f9a]/60 mb-1">
            {isConnected ? "Agent" : "Agent Name"}
          </label>
          {isConnected && agents.length > 0 ? (
            <Select
              value={profile.agentId ?? "__custom__"}
              onValueChange={handleFleetAgentSelect}
            >
              <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
                <SelectValue placeholder="Select fleet agent..." />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {agents.map((a) => (
                  <SelectItem
                    key={a.endpoint_agent_id}
                    value={a.endpoint_agent_id}
                    className="text-xs font-mono"
                  >
                    <span className="flex items-center gap-1.5">
                      <span
                        className={cn(
                          "inline-block w-1.5 h-1.5 rounded-full",
                          a.online ? "bg-[#3dbf84]" : "bg-[#6f7f9a]/40",
                        )}
                      />
                      {a.endpoint_agent_id}
                      {a.posture && (
                        <span className="text-[9px] text-[#6f7f9a]/60 ml-1">
                          [{a.posture}]
                        </span>
                      )}
                    </span>
                  </SelectItem>
                ))}
                <SelectItem value="__custom__" className="text-xs font-mono text-[#6f7f9a]">
                  Custom agent...
                </SelectItem>
              </SelectContent>
            </Select>
          ) : (
            <Input
              value={profile.agentName}
              onChange={(e) => updateProfile({ agentName: e.target.value, agentId: undefined })}
              placeholder="e.g. autonomous-agent-01"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          )}
          {/* Show editable name field when a fleet agent is selected (since fleet ID may not be human-friendly) */}
          {isConnected && profile.agentId && (
            <Input
              value={profile.agentName}
              onChange={(e) => updateProfile({ agentName: e.target.value })}
              placeholder="Display name"
              className="mt-1.5 bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          )}
          {/* Also show free-text name when "Custom agent..." selected while connected */}
          {isConnected && !profile.agentId && agents.length > 0 && (
            <Input
              value={profile.agentName}
              onChange={(e) => updateProfile({ agentName: e.target.value })}
              placeholder="Agent display name"
              className="mt-1.5 bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          )}
        </div>

        {/* Agent type selector */}
        <div>
          <label className="block text-[10px] font-mono text-[#6f7f9a]/60 mb-1">
            Runtime
          </label>
          <Select
            value={profile.agentType}
            onValueChange={(val) => updateProfile({ agentType: val as AgentRuntime })}
          >
            <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-[#131721] border-[#2d3240]">
              {AGENT_RUNTIME_OPTIONS.map((rt) => (
                <SelectItem key={rt.value} value={rt.value} className="text-xs font-mono">
                  {rt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Permissions / capabilities tags */}
        <div>
          <label className="block text-[10px] font-mono text-[#6f7f9a]/60 mb-1">
            Permissions
          </label>
          {/* Tag list */}
          {(profile.permissions ?? []).length > 0 && (
            <div className="flex flex-wrap gap-1 mb-1.5">
              {(profile.permissions ?? []).map((perm) => (
                <span
                  key={perm}
                  className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono text-[#ece7dc]/80 bg-[#131721] border border-[#2d3240] rounded"
                >
                  {perm}
                  <button
                    type="button"
                    onClick={() => removePermission(perm)}
                    className="text-[#6f7f9a] hover:text-[#c45c5c] transition-colors ml-0.5"
                  >
                    <IconX size={9} stroke={2} />
                  </button>
                </span>
              ))}
            </div>
          )}
          <Input
            value={permissionInput}
            onChange={(e) => setPermissionInput(e.target.value)}
            onKeyDown={handlePermissionKeyDown}
            onBlur={() => {
              if (permissionInput.trim()) {
                addPermission(permissionInput);
                setPermissionInput("");
              }
            }}
            placeholder="e.g. file_read, shell_exec (Enter to add)"
            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
          />
          <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
            Capabilities this agent claims. Comma or Enter to add tags.
          </p>
        </div>
      </div>
    </div>
  );
}


function PayloadFields({
  actionType,
  payload,
  onUpdate,
}: {
  actionType: TestActionType;
  payload: Record<string, unknown>;
  onUpdate: (key: string, value: unknown) => void;
}) {
  switch (actionType) {
    case "file_access":
      return (
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
            Target Path
          </label>
          <Input
            value={(payload.path as string) ?? ""}
            onChange={(e) => onUpdate("path", e.target.value)}
            placeholder="/path/to/file"
            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
          />
          <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
            Filesystem path the agent attempts to read. Evaluated against forbidden_path and path_allowlist guards.
          </p>
        </div>
      );

    case "file_write":
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Target Path
            </label>
            <Input
              value={(payload.path as string) ?? ""}
              onChange={(e) => onUpdate("path", e.target.value)}
              placeholder="/path/to/file"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              Destination path for the write operation. Checked against path allowlists.
            </p>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Payload Content
            </label>
            <Textarea
              value={(payload.content as string) ?? ""}
              onChange={(e) => onUpdate("content", e.target.value)}
              placeholder="File content to write..."
              rows={5}
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              Content body scanned by secret_leak guard for embedded credentials and API keys.
            </p>
          </div>
        </div>
      );

    case "network_egress":
      return (
        <div className="grid grid-cols-[1fr_120px] gap-3">
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Egress Destination
            </label>
            <Input
              value={(payload.host as string) ?? ""}
              onChange={(e) => onUpdate("host", e.target.value)}
              placeholder="api.example.com"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              Domain or host the agent attempts to reach. Evaluated against egress allowlist rules.
            </p>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Port
            </label>
            <Input
              type="number"
              value={String(payload.port ?? 443)}
              onChange={(e) => onUpdate("port", parseInt(e.target.value, 10) || 443)}
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs"
            />
          </div>
        </div>
      );

    case "shell_command":
      return (
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
            Shell Directive
          </label>
          <Textarea
            value={(payload.command as string) ?? ""}
            onChange={(e) => onUpdate("command", e.target.value)}
            placeholder="e.g. git status --short"
            rows={3}
            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
          />
          <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
            Shell command the agent attempts to execute. Checked against forbidden command patterns and path restrictions.
          </p>
        </div>
      );

    case "mcp_tool_call":
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              MCP Tool Identifier
            </label>
            <Input
              value={(payload.tool as string) ?? ""}
              onChange={(e) => onUpdate("tool", e.target.value)}
              placeholder="e.g. read_file"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              MCP tool name the agent invokes. Evaluated against the mcp_tool guard allow/block lists.
            </p>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Arguments (JSON)
            </label>
            <Textarea
              value={
                typeof payload.args === "string"
                  ? payload.args
                  : JSON.stringify(payload.args ?? {}, null, 2)
              }
              onChange={(e) => {
                try {
                  onUpdate("args", JSON.parse(e.target.value));
                } catch {
                  onUpdate("args", e.target.value);
                }
              }}
              placeholder='{ "path": "/src/main.ts" }'
              rows={3}
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              Tool arguments as JSON. Checked against max_args_size limit if configured.
            </p>
          </div>
        </div>
      );

    case "patch_apply":
      return (
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Target Path
            </label>
            <Input
              value={(payload.path as string) ?? ""}
              onChange={(e) => onUpdate("path", e.target.value)}
              placeholder="/path/to/file"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              File path receiving the patch. Checked against path allowlists and forbidden patterns.
            </p>
          </div>
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
              Payload Content
            </label>
            <Textarea
              value={(payload.content as string) ?? ""}
              onChange={(e) => onUpdate("content", e.target.value)}
              placeholder={"+added line\n-removed line"}
              rows={6}
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
            <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
              Unified diff content. Validated by patch_integrity guard for size limits and balance ratios.
            </p>
          </div>
        </div>
      );

    case "user_input":
      return (
        <div>
          <label className="block text-xs font-medium text-[#6f7f9a] mb-1">
            Input Text
          </label>
          <Textarea
            value={(payload.text as string) ?? ""}
            onChange={(e) => onUpdate("text", e.target.value)}
            placeholder="Enter user input to test..."
            rows={5}
            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
          />
          <p className="text-[9px] text-[#6f7f9a]/50 mt-1">
            User-supplied text scanned for prompt injection and jailbreak attempts.
          </p>
        </div>
      );

    default:
      return (
        <p className="text-[#6f7f9a] text-xs">
          No payload fields for this action type.
        </p>
      );
  }
}


const ORIGIN_PROVIDERS: { value: OriginProvider; label: string }[] = [
  { value: "slack", label: "Slack" },
  { value: "teams", label: "Teams" },
  { value: "github", label: "GitHub" },
  { value: "jira", label: "Jira" },
  { value: "email", label: "Email" },
  { value: "discord", label: "Discord" },
  { value: "webhook", label: "Webhook" },
];

const ORIGIN_SPACE_TYPES: { value: SpaceType; label: string }[] = [
  { value: "channel", label: "Channel" },
  { value: "group", label: "Group" },
  { value: "dm", label: "DM" },
  { value: "thread", label: "Thread" },
  { value: "issue", label: "Issue" },
  { value: "ticket", label: "Ticket" },
  { value: "pull_request", label: "Pull Request" },
  { value: "email_thread", label: "Email Thread" },
];

const ORIGIN_VISIBILITY: { value: Visibility; label: string }[] = [
  { value: "private", label: "Private" },
  { value: "internal", label: "Internal" },
  { value: "public", label: "Public" },
  { value: "external_shared", label: "External Shared" },
  { value: "unknown", label: "Unknown" },
];

const ORIGIN_PROVENANCE: { value: ProvenanceConfidence; label: string }[] = [
  { value: "strong", label: "Strong" },
  { value: "medium", label: "Medium" },
  { value: "weak", label: "Weak" },
  { value: "unknown", label: "Unknown" },
];

const ORIGIN_ACTOR_TYPES: { value: ActorType; label: string }[] = [
  { value: "human", label: "Human" },
  { value: "bot", label: "Bot" },
  { value: "service", label: "Service" },
  { value: "unknown", label: "Unknown" },
];

function OriginContextSection({
  originContext,
  onChange,
}: {
  originContext: OriginContext | undefined;
  onChange: (ctx: OriginContext | undefined) => void;
}) {
  const enabled = Boolean(originContext);
  const [expanded, setExpanded] = useState(false);

  const handleToggle = useCallback(
    (checked: boolean) => {
      if (checked) {
        onChange({ provider: "slack" });
      } else {
        onChange(undefined);
      }
    },
    [onChange],
  );

  const updateField = useCallback(
    <K extends keyof OriginContext>(key: K, value: OriginContext[K] | undefined) => {
      if (!originContext) return;
      const updated = { ...originContext };
      if (value === undefined || value === "" || value === "__none__") {
        delete updated[key];
      } else {
        updated[key] = value as OriginContext[K];
      }
      onChange(updated);
    },
    [originContext, onChange],
  );

  return (
    <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13]/50 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-2">
          <IconWorld size={14} stroke={1.5} className="text-[#d4a84b]" />
          <span className="text-xs font-mono uppercase tracking-wider text-[#6f7f9a]">
            Origin Context
          </span>
          <span className="inline-flex items-center px-1.5 py-0 text-[9px] font-mono text-[#d4a84b] border border-[#d4a84b]/20 bg-[#d4a84b]/5 rounded">
            v1.4.0
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={enabled}
            onCheckedChange={handleToggle}
            className="data-checked:bg-[#d4a84b]"
          />
          {enabled && (
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              className="p-1 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
            >
              <IconChevronDown
                size={14}
                stroke={1.5}
                className={cn(
                  "transition-transform duration-150",
                  expanded && "rotate-180",
                )}
              />
            </button>
          )}
        </div>
      </div>

      {/* Fields */}
      {enabled && originContext && (
        <div className="px-4 pb-4 space-y-3 border-t border-[#2d3240]/50 pt-3">
          {/* Provider (always visible) */}
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
              Provider
            </label>
            <Select
              value={originContext.provider}
              onValueChange={(val) => updateField("provider", val as OriginProvider)}
            >
              <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {ORIGIN_PROVIDERS.map((p) => (
                  <SelectItem key={p.value} value={p.value} className="text-xs font-mono">
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Space ID (always visible) */}
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
              Space / Channel ID
            </label>
            <Input
              value={originContext.space_id ?? ""}
              onChange={(e) => updateField("space_id", e.target.value || undefined)}
              placeholder="e.g. C12345, #general"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </div>

          {/* Visibility (always visible) */}
          <div>
            <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
              Visibility
            </label>
            <Select
              value={originContext.visibility ?? "__none__"}
              onValueChange={(val) =>
                updateField("visibility", val === "__none__" ? undefined : val as Visibility)
              }
            >
              <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                  Not set
                </SelectItem>
                {ORIGIN_VISIBILITY.map((v) => (
                  <SelectItem key={v.value} value={v.value} className="text-xs font-mono">
                    {v.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Expanded fields */}
          {expanded && (
            <div className="space-y-3 pt-1 border-t border-[#2d3240]/30">
              {/* Tenant ID */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Tenant ID
                </label>
                <Input
                  value={originContext.tenant_id ?? ""}
                  onChange={(e) => updateField("tenant_id", e.target.value || undefined)}
                  placeholder="e.g. T12345"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </div>

              {/* Space Type */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Space Type
                </label>
                <Select
                  value={originContext.space_type ?? "__none__"}
                  onValueChange={(val) =>
                    updateField("space_type", val === "__none__" ? undefined : val as SpaceType)
                  }
                >
                  <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                      Not set
                    </SelectItem>
                    {ORIGIN_SPACE_TYPES.map((st) => (
                      <SelectItem key={st.value} value={st.value} className="text-xs font-mono">
                        {st.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Thread ID */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Thread ID
                </label>
                <Input
                  value={originContext.thread_id ?? ""}
                  onChange={(e) => updateField("thread_id", e.target.value || undefined)}
                  placeholder="e.g. thread-42"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </div>

              {/* Actor ID */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Actor ID
                </label>
                <Input
                  value={originContext.actor_id ?? ""}
                  onChange={(e) => updateField("actor_id", e.target.value || undefined)}
                  placeholder="e.g. U001"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </div>

              {/* Actor Type */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Actor Type
                </label>
                <Select
                  value={originContext.actor_type ?? "__none__"}
                  onValueChange={(val) =>
                    updateField("actor_type", val === "__none__" ? undefined : val as ActorType)
                  }
                >
                  <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                      Not set
                    </SelectItem>
                    {ORIGIN_ACTOR_TYPES.map((at) => (
                      <SelectItem key={at.value} value={at.value} className="text-xs font-mono">
                        {at.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Actor Role */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Actor Role
                </label>
                <Input
                  value={originContext.actor_role ?? ""}
                  onChange={(e) => updateField("actor_role", e.target.value || undefined)}
                  placeholder="e.g. admin, incident_commander"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </div>

              {/* External Participants */}
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-[#6f7f9a]">
                  External Participants
                </label>
                <Select
                  value={
                    originContext.external_participants === undefined
                      ? "__none__"
                      : originContext.external_participants
                        ? "true"
                        : "false"
                  }
                  onValueChange={(val) =>
                    updateField(
                      "external_participants",
                      val === "__none__" ? undefined : val === "true",
                    )
                  }
                >
                  <SelectTrigger className="w-24 bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">N/A</SelectItem>
                    <SelectItem value="true" className="text-xs font-mono">Yes</SelectItem>
                    <SelectItem value="false" className="text-xs font-mono">No</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Tags */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Tags
                </label>
                <Input
                  value={(originContext.tags ?? []).join(", ")}
                  onChange={(e) => {
                    const tags = e.target.value
                      .split(",")
                      .map((t) => t.trim())
                      .filter(Boolean);
                    updateField("tags", tags.length > 0 ? tags : undefined);
                  }}
                  placeholder="e.g. hipaa, pci (comma-separated)"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </div>

              {/* Sensitivity */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Sensitivity
                </label>
                <Input
                  value={originContext.sensitivity ?? ""}
                  onChange={(e) => updateField("sensitivity", e.target.value || undefined)}
                  placeholder="e.g. high, medium, low"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </div>

              {/* Provenance Confidence */}
              <div>
                <label className="block text-xs font-medium text-[#6f7f9a] mb-1.5">
                  Provenance Confidence
                </label>
                <Select
                  value={originContext.provenance_confidence ?? "__none__"}
                  onValueChange={(val) =>
                    updateField(
                      "provenance_confidence",
                      val === "__none__" ? undefined : val as ProvenanceConfidence,
                    )
                  }
                >
                  <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] w-full text-xs font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                      Not set
                    </SelectItem>
                    {ORIGIN_PROVENANCE.map((pc) => (
                      <SelectItem key={pc.value} value={pc.value} className="text-xs font-mono">
                        {pc.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          {!expanded && (
            <button
              type="button"
              onClick={() => setExpanded(true)}
              className="text-[10px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
            >
              Show more fields...
            </button>
          )}
        </div>
      )}
    </div>
  );
}
