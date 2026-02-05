/**
 * AgentDetailPanel - Detailed view of selected agent
 */
import { clsx } from "clsx";
import type { ReactNode } from "react";
import type { AgentNode } from "@/types/agents";
import { TRUST_COLORS } from "@/types/agents";
import { useSwarm } from "@/context/SwarmContext";

interface AgentDetailPanelProps {
  agent: AgentNode;
  onClose: () => void;
}

export function AgentDetailPanel({ agent, onClose }: AgentDetailPanelProps) {
  const { getAgentDelegations } = useSwarm();
  const delegations = getAgentDelegations(agent.id);

  const trustColor = TRUST_COLORS[agent.trust_level];
  const incomingDelegations = delegations.filter((d) => d.to === agent.id);
  const outgoingDelegations = delegations.filter((d) => d.from === agent.id);

  return (
    <div className="h-full bg-sdr-bg-secondary/95 backdrop-blur border-l border-sdr-border flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border">
        <div className="flex items-center gap-2">
          <div
            className="w-3 h-3 rounded-full"
            style={{ backgroundColor: trustColor }}
          />
          <h2 className="font-medium text-sdr-text-primary">{agent.name}</h2>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-sdr-text-muted hover:text-sdr-text-primary rounded"
        >
          <CloseIcon />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Identity */}
        <Section title="Identity">
          <Row label="ID" value={agent.id} mono />
          <Row label="Role" value={agent.role} />
          <Row label="Trust Level">
            <TrustBadge level={agent.trust_level} />
          </Row>
          {agent.threat_score > 0 && (
            <Row label="Threat Score">
              <ThreatIndicator score={agent.threat_score} />
            </Row>
          )}
        </Section>

        {/* Public Key */}
        <Section title="Public Key">
          <code className="text-xs text-sdr-text-secondary font-mono break-all">
            {agent.public_key}
          </code>
        </Section>

        {/* Capabilities */}
        <Section title="Capabilities">
          {agent.capabilities.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {agent.capabilities.map((cap, i) => (
                <span
                  key={i}
                  className="px-2 py-0.5 text-xs bg-sdr-bg-tertiary text-sdr-text-secondary rounded"
                >
                  {cap.type}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-sdr-text-muted">No capabilities</p>
          )}
        </Section>

        {/* Delegations */}
        {(incomingDelegations.length > 0 || outgoingDelegations.length > 0) && (
          <Section title="Delegations">
            {incomingDelegations.length > 0 && (
              <div className="mb-2">
                <p className="text-xs text-sdr-text-muted mb-1">Received from:</p>
                {incomingDelegations.map((d) => (
                  <DelegationRow key={d.id} delegation={d} type="from" />
                ))}
              </div>
            )}
            {outgoingDelegations.length > 0 && (
              <div>
                <p className="text-xs text-sdr-text-muted mb-1">Granted to:</p>
                {outgoingDelegations.map((d) => (
                  <DelegationRow key={d.id} delegation={d} type="to" />
                ))}
              </div>
            )}
          </Section>
        )}

        {/* Activity */}
        <Section title="Activity">
          <Row label="Events" value={String(agent.event_count ?? 0)} />
          <Row label="Blocked" value={String(agent.blocked_count ?? 0)} />
          {agent.last_activity && (
            <Row
              label="Last Active"
              value={new Date(agent.last_activity).toLocaleString()}
            />
          )}
        </Section>

        {/* Metadata */}
        {agent.metadata && Object.keys(agent.metadata).length > 0 && (
          <Section title="Metadata">
            {Object.entries(agent.metadata).map(([key, value]) => (
              <Row key={key} label={key} value={value} />
            ))}
          </Section>
        )}
      </div>

      {/* Actions */}
      <div className="p-3 border-t border-sdr-border">
        <button className="w-full px-3 py-2 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors">
          View Events
        </button>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
        {title}
      </h3>
      {children}
    </div>
  );
}

function Row({
  label,
  value,
  mono,
  children,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  children?: ReactNode;
}) {
  return (
    <div className="flex items-start gap-2 text-sm mb-1">
      <span className="text-sdr-text-muted w-20 shrink-0">{label}</span>
      {children ?? (
        <span
          className={clsx(
            "text-sdr-text-primary break-all",
            mono && "font-mono text-xs"
          )}
        >
          {value}
        </span>
      )}
    </div>
  );
}

function TrustBadge({ level }: { level: string }) {
  const color = TRUST_COLORS[level as keyof typeof TRUST_COLORS] ?? "#9090a0";

  return (
    <span
      className="px-2 py-0.5 text-xs font-medium rounded"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {level}
    </span>
  );
}

function ThreatIndicator({ score }: { score: number }) {
  const percentage = Math.round(score * 100);
  const color =
    score > 0.7 ? "#ef4444" : score > 0.4 ? "#f97316" : score > 0.2 ? "#f59e0b" : "#22c55e";

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-sdr-bg-tertiary rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${percentage}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-mono" style={{ color }}>
        {percentage}%
      </span>
    </div>
  );
}

function DelegationRow({
  delegation,
  type,
}: {
  delegation: { id: string; from: string; to: string; capabilities: { type: string }[] };
  type: "from" | "to";
}) {
  const agentId = type === "from" ? delegation.from : delegation.to;

  return (
    <div className="text-xs text-sdr-text-secondary pl-2 border-l border-sdr-border mb-1">
      <span className="font-mono">{agentId.slice(0, 12)}...</span>
      <span className="text-sdr-text-muted ml-1">
        ({delegation.capabilities.length} caps)
      </span>
    </div>
  );
}

function CloseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}
