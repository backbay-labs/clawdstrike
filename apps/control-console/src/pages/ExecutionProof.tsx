import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type EndpointProviderState,
  fetchResponseExecutionProof,
  fetchResponseExecutions,
  type ResponseExecutionProofResponse,
  type ResponseExecutionRecord,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";
import { type ReceiptVerification, verifyReceipt } from "../utils/receiptVerify";

type EndpointDecisionValue = Record<string, unknown>;

interface CorrelationCheck {
  label: string;
  passed: boolean;
  detail: string;
}

type BaseReceiptKey = keyof Pick<
  ResponseExecutionProofResponse,
  "requestReceipt" | "executionReceipt" | "evidenceBundleReceipt"
>;

interface ReceiptChainEntry {
  key: string;
  label: string;
  receipt: SignedReceiptJson;
}

type ReceiptVerificationMap = Partial<Record<string, ReceiptVerification>>;

const BASE_RECEIPT_LABELS: Array<{
  key: BaseReceiptKey;
  label: string;
}> = [
  { key: "requestReceipt", label: "Request" },
  { key: "executionReceipt", label: "Execution" },
  { key: "evidenceBundleReceipt", label: "Evidence Bundle" },
];

const PROVIDER_STALE_AFTER_MS = 15 * 60_000;

export function ExecutionProof(_props: { windowId?: string }) {
  const [executionId, setExecutionId] = useState("");
  const [executions, setExecutions] = useState<ResponseExecutionRecord[]>([]);
  const [proof, setProof] = useState<ResponseExecutionProofResponse | null>(null);
  const [loadingExecutions, setLoadingExecutions] = useState(false);
  const [loadingProof, setLoadingProof] = useState(false);
  const [verifyingProof, setVerifyingProof] = useState(false);
  const [receiptVerification, setReceiptVerification] = useState<ReceiptVerificationMap>({});
  const [evidenceHashChecks, setEvidenceHashChecks] = useState<CorrelationCheck[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadExecutions = useCallback(async () => {
    setLoadingExecutions(true);
    try {
      const response = await fetchResponseExecutions({ limit: 50 });
      setExecutions(response.executions);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load response executions");
    } finally {
      setLoadingExecutions(false);
    }
  }, []);

  useEffect(() => {
    loadExecutions();
  }, [loadExecutions]);

  const loadProof = useCallback(async (id: string) => {
    const trimmed = id.trim();
    if (!trimmed) return;
    setLoadingProof(true);
    try {
      const response = await fetchResponseExecutionProof(trimmed);
      setProof(response);
      setExecutionId(response.execution.execution.executionId);
      setReceiptVerification({});
      setEvidenceHashChecks([]);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch execution proof");
    } finally {
      setLoadingProof(false);
    }
  }, []);

  const selectedExecutionId = proof?.execution.execution.executionId ?? executionId.trim();
  const proofSummary = useMemo(() => buildProofSummary(proof), [proof]);
  const correlationChecks = useMemo(() => buildCorrelationChecks(proof), [proof]);
  const receiptChain = useMemo(() => (proof ? receiptChainEntries(proof) : []), [proof]);
  const affectedIdentityLabels = useMemo(() => proofAffectedIdentityLabels(proof), [proof]);
  const affectedToolLabels = useMemo(() => proofAffectedToolLabels(proof), [proof]);

  useEffect(() => {
    let cancelled = false;
    if (!proof) {
      setEvidenceHashChecks([]);
      return;
    }

    buildEvidenceHashChecks(proof)
      .then((checks) => {
        if (!cancelled) setEvidenceHashChecks(checks);
      })
      .catch((err) => {
        if (!cancelled) {
          setEvidenceHashChecks([
            {
              label: "Evidence hash verification",
              passed: false,
              detail: err instanceof Error ? err.message : "failed",
            },
          ]);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [proof]);

  const verifyChain = useCallback(async () => {
    if (!proof) return;
    setVerifyingProof(true);
    try {
      const entries = await Promise.all(
        receiptChain.map(async (receipt) => {
          const result = await verifyReceipt(JSON.stringify(receipt.receipt));
          return [receipt.key, result] as const;
        }),
      );
      setReceiptVerification(Object.fromEntries(entries));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to verify receipt chain");
    } finally {
      setVerifyingProof(false);
    }
  }, [proof, receiptChain]);

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p
            className="font-mono"
            style={{
              color: "rgba(214,177,90,0.72)",
              fontSize: "0.68rem",
              letterSpacing: "0.16em",
              textTransform: "uppercase",
            }}
          >
            Local response ledger
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Proof at Execution
          </h1>
        </div>

        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <label className="flex min-w-0 flex-1 flex-col gap-1">
            <span
              className="font-mono"
              style={{
                color: "rgba(154,167,181,0.62)",
                fontSize: "0.65rem",
                letterSpacing: "0.12em",
                textTransform: "uppercase",
              }}
            >
              Execution ID
            </span>
            <input
              value={executionId}
              onChange={(event) => setExecutionId(event.target.value)}
              className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
              style={{ color: "var(--text)", width: "min(58vw, 360px)" }}
            />
          </label>
          <GlassButton
            variant="primary"
            onClick={() => loadProof(executionId)}
            disabled={loadingProof || !executionId.trim()}
          >
            {loadingProof ? "Fetching..." : "Fetch Proof"}
          </GlassButton>
          <GlassButton onClick={loadExecutions} disabled={loadingExecutions}>
            Refresh
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner tone="error" message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(280px,0.72fr)_minmax(0,1.28fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Recent" title="Executions" />
          <div className="mt-3 max-h-[520px] space-y-2 overflow-y-auto pr-1">
            {executions.length === 0 ? (
              <EmptyState text={loadingExecutions ? "Loading executions" : "No executions"} />
            ) : (
              executions.map((record) => (
                <ExecutionRow
                  key={record.execution.executionId}
                  record={record}
                  selected={record.execution.executionId === selectedExecutionId}
                  onLoad={() => loadProof(record.execution.executionId)}
                  loading={loadingProof}
                />
              ))
            )}
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <ProofMetric label="Execution" value={proof?.execution.execution.executionId ?? "-"} />
            <ProofMetric label="Action" value={proof?.execution.execution.action ?? "-"} />
            <ProofMetric label="Status" value={proof?.execution.execution.status ?? "-"} />
            <ProofMetric label="Identities" value={numberText(proof?.affectedIdentityCount)} />
            <ProofMetric label="Tools" value={numberText(proof?.affectedToolCount)} />
            <ProofMetric
              label="Transitions"
              value={proof ? String(proof.transitionReceipts?.length ?? 0) : "-"}
            />
            <ProofMetric
              label="Rollbacks"
              value={proof ? String(proof.rollbackReceipts?.length ?? 0) : "-"}
            />
            <ProofMetric
              label="Acknowledgements"
              value={proof ? String(proof.acknowledgementReceipts?.length ?? 0) : "-"}
            />
          </div>

          {!proof ? (
            <Plate className="p-6">
              <EmptyState text="Select an execution" />
            </Plate>
          ) : (
            <>
              <Plate className="p-4" goldEdge>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <PanelTitle eyebrow="Proof Chain" title={proofSummary.title} />
                  <div className="flex flex-wrap gap-2">
                    <GlassButton
                      onClick={() =>
                        exportAsJSON(
                          [proof],
                          proofExportFilename(proof.execution.execution.executionId),
                        )
                      }
                    >
                      Export Proof
                    </GlassButton>
                    <GlassButton
                      onClick={() =>
                        exportAsJSON(
                          [
                            buildVerificationVerdict(
                              proof,
                              receiptVerification,
                              correlationChecks,
                              evidenceHashChecks,
                            ),
                          ],
                          verdictExportFilename(proof.execution.execution.executionId),
                        )
                      }
                    >
                      Export Verdict
                    </GlassButton>
                    <GlassButton onClick={verifyChain} disabled={verifyingProof}>
                      {verifyingProof ? "Verifying..." : "Verify Chain"}
                    </GlassButton>
                  </div>
                </div>
                <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
                  {receiptChain.map((receipt) => (
                    <ReceiptStep
                      key={receipt.key}
                      label={receipt.label}
                      receipt={receipt.receipt}
                      verification={receiptVerification[receipt.key]}
                    />
                  ))}
                </div>
              </Plate>

              <div className="grid grid-cols-1 gap-5 lg:grid-cols-[0.95fr_1.05fr]">
                <Plate className="p-4">
                  <PanelTitle eyebrow="Providers" title="Execution State" />
                  <div className="mt-3 space-y-2">
                    {proof.providerState.providers.map((provider) => (
                      <ProviderRow
                        key={
                          provider.providerId ?? provider.providerKind ?? JSON.stringify(provider)
                        }
                        provider={provider}
                      />
                    ))}
                  </div>
                </Plate>

                <Plate className="p-4">
                  <PanelTitle eyebrow="Graph" title={proof.graph.graphSliceId ?? "No graph id"} />
                  <div className="mt-4 space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      <SmallFact
                        label="Root"
                        value={proof.graph.rootNodeId ?? proof.graph.processNodeId ?? "-"}
                      />
                      <SmallFact label="Nodes" value={numberText(proof.graph.nodeCount)} />
                      <SmallFact label="Edges" value={numberText(proof.graph.edgeCount)} />
                      <SmallFact label="Hash" value={proof.graph.contentHash ?? "-"} mono />
                    </div>
                    <LabelList
                      label="Responsible Identities"
                      items={affectedIdentityLabels}
                      emptyText="No identity context loaded"
                    />
                    <LabelList
                      label="Responsible Tools"
                      items={affectedToolLabels}
                      emptyText="No tool-call context loaded"
                    />
                  </div>
                </Plate>
              </div>

              <Plate className="p-4">
                <PanelTitle eyebrow="Ledger" title="Stored Artifacts" />
                <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
                  <SmallFact
                    label="Execution ledger"
                    value={proof.executionPath ?? "transient"}
                    mono
                  />
                  <SmallFact label="Receipt ledger" value={proof.receiptPath ?? "transient"} mono />
                </div>
              </Plate>

              <Plate className="p-4">
                <PanelTitle eyebrow="Correlation" title="Package Bindings" />
                <div className="mt-4 grid grid-cols-1 gap-2 lg:grid-cols-2">
                  {correlationChecks.map((check) => (
                    <CorrelationLine key={check.label} check={check} />
                  ))}
                  {evidenceHashChecks.map((check) => (
                    <CorrelationLine key={check.label} check={check} />
                  ))}
                </div>
              </Plate>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

function ExecutionRow({
  record,
  selected,
  onLoad,
  loading,
}: {
  record: ResponseExecutionRecord;
  selected: boolean;
  onLoad: () => void;
  loading: boolean;
}) {
  const execution = record.execution;

  return (
    <button
      type="button"
      aria-label={`Load proof for ${execution.executionId}`}
      onClick={onLoad}
      disabled={loading}
      className="hover-row w-full rounded-md px-3 py-2 text-left disabled:opacity-50"
      style={{
        border: selected ? "1px solid rgba(214,177,90,0.42)" : "1px solid rgba(27,34,48,0.82)",
        background: selected ? "rgba(214,177,90,0.10)" : "rgba(7,8,10,0.56)",
      }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-sm" style={{ color: "var(--text)" }}>
          {execution.executionId}
        </span>
        <StatusPill value={execution.status ?? "unknown"} />
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
        <InlineMeta label="action" value={execution.action ?? "-"} />
        <InlineMeta label="bundle" value={execution.evidenceBundle?.bundleId ?? "-"} />
      </div>
    </button>
  );
}

function ReceiptStep({
  label,
  receipt,
  verification,
}: {
  label: string;
  receipt: SignedReceiptJson;
  verification?: ReceiptVerification;
}) {
  const decision = endpointDecision(receipt);
  const family = stringValue(decision?.receiptFamily) ?? "unknown";
  const policy = asRecord(decision?.policy);
  const policyHash = stringValue(policy?.policyHash);
  const policyEpoch = policyEpochText(policy?.policyEpoch);
  const receiptId = stringValue(asRecord(receipt.receipt)?.receipt_id);

  return (
    <div
      style={{
        border: "1px solid rgba(27,34,48,0.82)",
        borderRadius: 8,
        padding: "0.8rem",
        background: "rgba(0,0,0,0.24)",
        minHeight: 124,
      }}
    >
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.58)",
          fontSize: "0.62rem",
          letterSpacing: "0.13em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p className="font-mono mt-2 text-sm" style={{ color: "var(--gold)" }}>
        {family}
      </p>
      <p
        className="font-mono mt-3 truncate"
        style={{ color: "rgba(154,167,181,0.52)", fontSize: "0.68rem" }}
      >
        {receiptId ?? "no receipt id"}
      </p>
      {policyHash && (
        <p
          className="font-mono mt-1 truncate"
          style={{ color: "rgba(154,167,181,0.38)", fontSize: "0.64rem" }}
        >
          {policyHash}
        </p>
      )}
      {policyEpoch && (
        <p
          className="font-mono mt-1"
          style={{ color: "rgba(214,177,90,0.56)", fontSize: "0.64rem" }}
        >
          epoch:{policyEpoch}
        </p>
      )}
      {verification && <VerificationLine label={label} verification={verification} />}
    </div>
  );
}

function VerificationLine({
  label,
  verification,
}: {
  label: string;
  verification: ReceiptVerification;
}) {
  const ok = verification.valid;
  const text = ok ? `${label} verified` : `${label} failed: ${verification.error ?? "invalid"}`;

  return (
    <p
      className="font-mono mt-3"
      style={{
        color: ok ? "var(--stamp-allowed)" : "var(--crimson)",
        fontSize: "0.66rem",
      }}
    >
      {text}
    </p>
  );
}

function CorrelationLine({ check }: { check: CorrelationCheck }) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{
        border: `1px solid ${check.passed ? "rgba(45,170,106,0.28)" : "rgba(194,59,59,0.32)"}`,
        background: check.passed ? "rgba(45,170,106,0.06)" : "rgba(194,59,59,0.08)",
      }}
    >
      <p
        className="font-mono"
        style={{
          color: check.passed ? "var(--stamp-allowed)" : "var(--crimson)",
          fontSize: "0.7rem",
          letterSpacing: "0.04em",
        }}
      >
        {check.label} {check.passed ? "match" : "mismatch"}
      </p>
      <p
        className="font-mono mt-1 truncate"
        style={{ color: "rgba(154,167,181,0.48)", fontSize: "0.64rem" }}
      >
        {check.detail}
      </p>
    </div>
  );
}

function ProviderRow({ provider }: { provider: EndpointProviderState }) {
  const state = providerDisplayState(provider);
  const providerId = provider.providerId ?? provider.providerKind ?? "provider";
  const reasons = provider.degradationReasons?.filter((reason) => reason.trim()) ?? [];

  return (
    <div
      className="flex items-center justify-between gap-3 rounded-md px-3 py-2"
      style={{ border: `1px solid ${state.border}`, background: state.background }}
    >
      <div className="min-w-0">
        <p className="font-mono truncate text-sm" style={{ color: "var(--text)" }}>
          {providerId}
        </p>
        <p className="font-mono" style={{ color: "rgba(154,167,181,0.52)", fontSize: "0.66rem" }}>
          {provider.active ? "active" : "inactive"} | installed:
          {provider.installed === false ? "no" : "yes"}
        </p>
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
          <InlineMeta label="last_seen" value={provider.lastSeen ?? "-"} />
          {provider.droppedEventCount != null && (
            <InlineMeta label="dropped" value={String(provider.droppedEventCount)} />
          )}
          {provider.deadlineMissCount != null && (
            <InlineMeta label="deadline_miss" value={String(provider.deadlineMissCount)} />
          )}
        </div>
        {reasons.length > 0 && (
          <p
            className="font-mono mt-1 truncate"
            style={{ color: state.color, fontSize: "0.64rem" }}
          >
            {reasons.join(", ")}
          </p>
        )}
      </div>
      <span
        className="font-mono"
        style={{
          color: state.color,
          border: `1px solid ${state.border}`,
          borderRadius: 5,
          padding: "3px 7px",
          fontSize: "0.62rem",
          letterSpacing: 0,
          textTransform: "uppercase",
        }}
      >
        {state.label}
      </span>
    </div>
  );
}

function providerDisplayState(provider: EndpointProviderState) {
  if (provider.installed === false) {
    return {
      label: "MISSING",
      color: "var(--crimson)",
      border: "rgba(194,59,59,0.34)",
      background: "rgba(194,59,59,0.08)",
    };
  }
  if (provider.degraded === true || provider.healthy === false) {
    return {
      label: "DEGRADED",
      color: "var(--crimson)",
      border: "rgba(194,59,59,0.34)",
      background: "rgba(194,59,59,0.08)",
    };
  }
  if (provider.stale === true || providerLastSeenStale(provider.lastSeen)) {
    return {
      label: "STALE",
      color: "var(--stamp-warn)",
      border: "rgba(214,177,90,0.36)",
      background: "rgba(214,177,90,0.08)",
    };
  }
  if (provider.active === false) {
    return {
      label: "INACTIVE",
      color: "var(--stamp-warn)",
      border: "rgba(214,177,90,0.36)",
      background: "rgba(214,177,90,0.08)",
    };
  }
  return {
    label: "HEALTHY",
    color: "var(--stamp-allowed)",
    border: "rgba(45,170,106,0.34)",
    background: "rgba(45,170,106,0.06)",
  };
}

function providerLastSeenStale(lastSeen: string | null | undefined): boolean {
  if (!lastSeen) return false;
  const observedAt = new Date(lastSeen).getTime();
  if (Number.isNaN(observedAt)) return false;
  return Date.now() - observedAt > PROVIDER_STALE_AFTER_MS;
}

function ProofMetric({ label, value }: { label: string; value: string }) {
  return (
    <Plate className="p-4">
      <p
        className="font-mono"
        style={{
          position: "relative",
          color: "rgba(154,167,181,0.58)",
          fontSize: "0.62rem",
          letterSpacing: "0.13em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className="font-display mt-2 truncate"
        style={{ position: "relative", color: "var(--text)", fontSize: "1.25rem", fontWeight: 700 }}
      >
        {value}
      </p>
    </Plate>
  );
}

function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div style={{ position: "relative" }}>
      <p
        className="font-mono"
        style={{
          color: "rgba(214,177,90,0.66)",
          fontSize: "0.62rem",
          letterSpacing: "0.14em",
          textTransform: "uppercase",
        }}
      >
        {eyebrow}
      </p>
      <h2
        className="font-display mt-1"
        style={{ color: "var(--text)", fontSize: "1.05rem", fontWeight: 700 }}
      >
        {title}
      </h2>
    </div>
  );
}

function SmallFact({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className={mono ? "font-mono mt-1 truncate" : "font-body mt-1 truncate"}
        style={{ color: "var(--text)", fontSize: mono ? "0.72rem" : "0.88rem" }}
      >
        {value}
      </p>
    </div>
  );
}

function InlineMeta({ label, value }: { label: string; value: string }) {
  return (
    <span className="font-mono" style={{ color: "rgba(154,167,181,0.46)", fontSize: "0.64rem" }}>
      {label}:{value}
    </span>
  );
}

function LabelList({
  label,
  items,
  emptyText,
}: {
  label: string;
  items: string[];
  emptyText: string;
}) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.length === 0 ? (
          <EmptyState text={emptyText} />
        ) : (
          items.map((item) => <Tag key={item}>{item}</Tag>)
        )}
      </div>
    </div>
  );
}

function Tag({ children }: { children: string }) {
  return (
    <span
      className="font-mono rounded-md px-2 py-1"
      style={{
        border: "1px solid rgba(27,34,48,0.82)",
        background: "rgba(0,0,0,0.22)",
        color: "var(--text)",
        fontSize: "0.66rem",
      }}
    >
      {children}
    </span>
  );
}

function StatusPill({ value }: { value: string }) {
  const ok = value === "succeeded";
  return (
    <span
      className="font-mono"
      style={{
        color: ok ? "var(--stamp-allowed)" : "var(--gold)",
        border: `1px solid ${ok ? "rgba(45,170,106,0.32)" : "rgba(214,177,90,0.28)"}`,
        borderRadius: 5,
        padding: "2px 6px",
        fontSize: "0.58rem",
        letterSpacing: "0.09em",
        textTransform: "uppercase",
      }}
    >
      {value}
    </span>
  );
}

function StatusBanner({ tone, message }: { tone: "error"; message: string }) {
  return (
    <div
      className="glass-panel"
      style={{
        background: tone === "error" ? "rgba(194,59,59,0.08)" : undefined,
        border: tone === "error" ? "1px solid rgba(194,59,59,0.3)" : undefined,
        padding: "0.7rem 1rem",
      }}
    >
      <NoiseGrain />
      <p
        className="font-mono"
        style={{ position: "relative", color: "var(--crimson)", fontSize: "0.78rem" }}
      >
        {message}
      </p>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <p
      className="font-mono"
      style={{
        position: "relative",
        color: "rgba(154,167,181,0.5)",
        fontSize: "0.78rem",
        letterSpacing: "0.06em",
      }}
    >
      {text}
    </p>
  );
}

function buildProofSummary(proof: ResponseExecutionProofResponse | null) {
  if (!proof) return { title: "-" };
  const action = proof.execution.execution.action ?? "response";
  const status = proof.execution.execution.status ?? "unknown";
  return { title: `${action} / ${status}` };
}

function proofAffectedIdentityLabels(proof: ResponseExecutionProofResponse | null): string[] {
  const identities = proof?.affectedIdentities;
  if (!identities) return [];
  return [
    ...identityBucketLabels("Host", identities.hosts),
    ...identityBucketLabels("User", identities.users),
    ...identityBucketLabels("Session", identities.sessions),
    ...identityBucketLabels("Agent", identities.agents),
    ...identityBucketLabels("Workload", identities.workloads),
    ...identityBucketLabels("Approval", identities.approvals),
  ].sort();
}

function identityBucketLabels(
  prefix: string,
  identities: Array<{ id: string; label: string }>,
): string[] {
  return identities
    .map((identity) => `${prefix}: ${identity.id || identity.label}`)
    .filter(isString);
}

function proofAffectedToolLabels(proof: ResponseExecutionProofResponse | null): string[] {
  return (proof?.affectedTools ?? [])
    .map((tool) => tool.toolName || tool.label)
    .filter(isString)
    .sort();
}

function buildVerificationVerdict(
  proof: ResponseExecutionProofResponse,
  receiptVerification: ReceiptVerificationMap,
  correlationChecks: CorrelationCheck[],
  evidenceHashChecks: CorrelationCheck[],
) {
  const execution = proof.execution.execution;
  const receipts = receiptChainEntries(proof);
  return {
    kind: "clawdstrike.execution_proof.verdict.v1",
    generatedAt: new Date().toISOString(),
    executionId: execution.executionId,
    actionId: execution.actionId ?? null,
    action: execution.action ?? null,
    status: execution.status ?? null,
    proof: {
      executionPath: proof.executionPath ?? null,
      receiptPath: proof.receiptPath ?? null,
      graphSliceId: proof.graph.graphSliceId ?? null,
      evidenceBundleId: execution.evidenceBundle?.bundleId ?? null,
      affectedIdentityCount: proof.affectedIdentityCount ?? null,
      affectedToolCount: proof.affectedToolCount ?? null,
      affectedIdentities: proof.affectedIdentities ?? null,
      affectedTools: proof.affectedTools ?? null,
    },
    signatures: receipts.map(({ key, label }) => {
      const verification = receiptVerification[key];
      const result: {
        receipt: string;
        label: string;
        status: "valid" | "invalid" | "not_run";
        error?: string;
      } = {
        receipt: key,
        label,
        status: verification ? (verification.valid ? "valid" : "invalid") : "not_run",
      };
      if (verification?.error) result.error = verification.error;
      return result;
    }),
    correlations: serializeChecks(correlationChecks),
    evidenceHashes: serializeChecks(evidenceHashChecks),
  };
}

function serializeChecks(checks: CorrelationCheck[]) {
  return checks.map(({ label, passed, detail }) => ({ label, passed, detail }));
}

function receiptChainEntries(proof: ResponseExecutionProofResponse): ReceiptChainEntry[] {
  return [
    ...BASE_RECEIPT_LABELS.map(({ key, label }) => ({
      key,
      label,
      receipt: proof[key],
    })),
    ...(proof.transitionReceipts ?? []).map((receipt, index) => ({
      key: `transitionReceipts.${index}`,
      label: `Transition ${index + 1}`,
      receipt,
    })),
    ...(proof.rollbackReceipts ?? []).map((receipt, index) => ({
      key: `rollbackReceipts.${index}`,
      label: `Rollback ${index + 1}`,
      receipt,
    })),
    ...(proof.acknowledgementReceipts ?? []).map((receipt, index) => ({
      key: `acknowledgementReceipts.${index}`,
      label: `Acknowledgement ${index + 1}`,
      receipt,
    })),
  ];
}

function buildCorrelationChecks(proof: ResponseExecutionProofResponse | null): CorrelationCheck[] {
  if (!proof) return [];
  const execution = proof.execution.execution;
  const requestDecision = endpointDecision(proof.requestReceipt);
  const executionDecision = endpointDecision(proof.executionReceipt);
  const bundleDecision = endpointDecision(proof.evidenceBundleReceipt);
  const requestRecord = asRecord(requestDecision?.decision);
  const executionRecord = asRecord(executionDecision?.decision);
  const bundleRecord = asRecord(bundleDecision?.decision);
  const expectedActionId = execution.actionId ?? "";
  const expectedExecutionId = execution.executionId;
  const expectedBundleId = execution.evidenceBundle?.bundleId ?? "";
  const expectedAction = execution.action ?? "";
  const expectedRollbackRef = proof.execution.rollbackRef ?? execution.rollbackRef ?? "";
  const expectedActor = asRecord(execution.actor);
  const requestActionId = stringField(requestRecord, "findingId", "finding_id");
  const receiptExecutionId = stringField(executionRecord, "findingId", "finding_id");
  const receiptBundleId = stringField(bundleRecord, "findingId", "finding_id");
  const requestAction = stringField(requestRecord, "action");
  const executionAction = stringField(executionRecord, "action");
  const bundleAction = stringField(bundleRecord, "action");
  const expectedGraphId = proof.graph.graphSliceId ?? execution.evidenceBundle?.graphSliceId ?? "";
  const requestGraphId = stringField(
    asRecord(requestDecision?.graph),
    "graphSliceId",
    "graph_slice_id",
  );
  const executionGraphId = stringField(
    asRecord(executionDecision?.graph),
    "graphSliceId",
    "graph_slice_id",
  );
  const bundleGraphId = stringField(
    asRecord(bundleDecision?.graph),
    "graphSliceId",
    "graph_slice_id",
  );

  const checks: CorrelationCheck[] = [
    {
      label: "Request action ID",
      passed: valuesMatch(requestActionId, expectedActionId),
      detail: `${requestActionId ?? "-"} / ${expectedActionId || "-"}`,
    },
    {
      label: "Execution ID",
      passed: valuesMatch(receiptExecutionId, expectedExecutionId),
      detail: `${receiptExecutionId ?? "-"} / ${expectedExecutionId || "-"}`,
    },
    {
      label: "Bundle ID",
      passed: valuesMatch(receiptBundleId, expectedBundleId),
      detail: `${receiptBundleId ?? "-"} / ${expectedBundleId || "-"}`,
    },
    {
      label: "Action type",
      passed:
        valuesMatch(requestAction, execution.action) &&
        valuesMatch(executionAction, execution.action) &&
        valuesMatch(bundleAction, execution.action),
      detail: [requestAction, executionAction, bundleAction]
        .map((value) => value ?? "-")
        .join(" / "),
    },
    {
      label: "Graph slice",
      passed:
        valuesMatch(requestGraphId, expectedGraphId) &&
        valuesMatch(executionGraphId, expectedGraphId) &&
        valuesMatch(bundleGraphId, expectedGraphId),
      detail: [requestGraphId, executionGraphId, bundleGraphId]
        .map((value) => value ?? "-")
        .join(" / "),
    },
    receiptSignerContinuityCheck(proof),
    responseActorIdentityCheck(expectedActor, requestDecision, executionDecision),
    responseActorHashContinuityCheck(requestDecision, executionDecision),
  ];

  checks.push(
    ...receiptDecisionCorrelationChecks(
      "Transition",
      proof.transitionReceipts ?? [],
      expectedAction,
      expectedRollbackRef,
    ),
    ...receiptDecisionCorrelationChecks(
      "Rollback",
      proof.rollbackReceipts ?? [],
      expectedAction,
      expectedRollbackRef,
    ),
    ...receiptDecisionCorrelationChecks(
      "Acknowledgement",
      proof.acknowledgementReceipts ?? [],
      expectedAction,
      expectedRollbackRef,
    ),
    ...receiptActorHashContinuityChecks(
      "Transition",
      proof.transitionReceipts ?? [],
      evidenceHash(requestDecision, "actorHash"),
    ),
  );

  return checks;
}

const RESPONSE_ACTOR_FIELDS = [
  ["userId", "user_id"],
  ["sessionId", "session_id"],
  ["agentId", "agent_id"],
  ["workloadId", "workload_id"],
  ["approvalId", "approval_id"],
] as const;

function responseActorIdentityCheck(
  expectedActor: Record<string, unknown> | null,
  requestDecision: EndpointDecisionValue | null,
  executionDecision: EndpointDecisionValue | null,
): CorrelationCheck {
  const requestActor = asRecord(requestDecision?.actor);
  const executionActor = asRecord(executionDecision?.actor);
  const expected = RESPONSE_ACTOR_FIELDS.flatMap(([camel, snake]) => {
    const value = stringField(expectedActor, camel, snake);
    return value ? [{ key: camel, value }] : [];
  });
  const mismatches = expected.filter(
    ({ key, value }) =>
      !valuesMatch(stringField(requestActor, key), value) ||
      !valuesMatch(stringField(executionActor, key), value),
  );
  const passed = expected.length > 0 && mismatches.length === 0;
  const detail = passed
    ? expected.map(({ key, value }) => `${key}:${value}`).join(" / ")
    : `mismatch:${mismatches.map(({ key }) => key).join(",") || "missing-actor"}`;
  return {
    label: "Response actor identity",
    passed,
    detail,
  };
}

function responseActorHashContinuityCheck(
  requestDecision: EndpointDecisionValue | null,
  executionDecision: EndpointDecisionValue | null,
): CorrelationCheck {
  const hashes = [
    evidenceHash(requestDecision, "actorHash"),
    evidenceHash(executionDecision, "actorHash"),
    evidenceHash(executionDecision, "executionActorHash"),
  ].map(normalizeHash);
  const present = hashes.flatMap((hash) => (hash ? [hash] : []));
  const passed = present.length === hashes.length && new Set(present).size === 1;
  return {
    label: "Response actor hash continuity",
    passed,
    detail: hashes.map(shortHash).join(" / "),
  };
}

function receiptActorHashContinuityChecks(
  label: string,
  receipts: SignedReceiptJson[],
  expectedActorHash: string | null,
): CorrelationCheck[] {
  const expected = normalizeHash(expectedActorHash);
  if (receipts.length === 0 || !expected) return [];
  const receiptHashes = receipts.map((receipt) => {
    const decision = endpointDecision(receipt);
    return [
      normalizeHash(evidenceHash(decision, "actorHash")),
      normalizeHash(evidenceHash(decision, "executionActorHash")),
    ];
  });
  const passed = receiptHashes.every((hashes) =>
    hashes.every((hash) => valuesMatch(hash, expected)),
  );
  return [
    {
      label: `${label} actor hash continuity`,
      passed,
      detail: receiptHashes.map((hashes) => hashes.map(shortHash).join("/")).join(" / "),
    },
  ];
}

function receiptSignerContinuityCheck(proof: ResponseExecutionProofResponse): CorrelationCheck {
  const entries = receiptChainEntries(proof);
  const signerKeys = entries.map((entry) => ({
    label: entry.label,
    key: receiptSignerPublicKey(entry.receipt),
  }));
  const missing = signerKeys.filter((entry) => !entry.key).map((entry) => entry.label);
  const unique = Array.from(new Set(signerKeys.flatMap((entry) => (entry.key ? [entry.key] : []))));
  const passed = missing.length === 0 && unique.length === 1;
  const detail =
    missing.length > 0
      ? `missing:${missing.join(",")}`
      : unique.map((key) => shortHash(key)).join(" / ");
  return {
    label: "Receipt signer continuity",
    passed,
    detail,
  };
}

function receiptSignerPublicKey(receipt: SignedReceiptJson): string | null {
  const decision = endpointDecision(receipt);
  return stringField(asRecord(decision?.signer), "signerPublicKey", "signer_public_key");
}

function receiptDecisionCorrelationChecks(
  label: string,
  receipts: SignedReceiptJson[],
  expectedAction: string,
  expectedRollbackRef: string,
): CorrelationCheck[] {
  if (receipts.length === 0) return [];
  const decisions = receipts.map(endpointDecision);
  const actions = decisions.map((decision) => stringField(asRecord(decision?.decision), "action"));
  const rollbackRefs = decisions.map((decision) =>
    stringField(asRecord(decision?.decision), "rollbackRef", "rollback_ref"),
  );
  return [
    {
      label: `${label} action type`,
      passed: actions.every((action) => valuesMatch(action, expectedAction)),
      detail: actions.map((value) => value ?? "-").join(" / "),
    },
    {
      label: `${label} rollback ref`,
      passed: rollbackRefs.every((rollbackRef) => valuesMatch(rollbackRef, expectedRollbackRef)),
      detail: rollbackRefs.map((value) => value ?? "-").join(" / "),
    },
  ];
}

async function buildEvidenceHashChecks(
  proof: ResponseExecutionProofResponse,
): Promise<CorrelationCheck[]> {
  const execution = proof.execution.execution;
  const actionId = execution.actionId ?? "";
  const executionId = execution.executionId;
  const bundleId = execution.evidenceBundle?.bundleId ?? "";
  const graphSliceId = proof.graph.graphSliceId ?? execution.evidenceBundle?.graphSliceId ?? "";
  const contentHash = execution.evidenceBundle?.contentHash ?? "";
  const nodeCount = numberText(execution.evidenceBundle?.nodeCount);
  const edgeCount = numberText(execution.evidenceBundle?.edgeCount);
  const rollbackRef = proof.execution.rollbackRef ?? execution.rollbackRef ?? "";

  const specs = [
    {
      label: "Request action hash",
      decision: endpointDecision(proof.requestReceipt),
      key: "responseActionId",
      expected: actionId,
    },
    {
      label: "Request graph hash",
      decision: endpointDecision(proof.requestReceipt),
      key: "graphSliceId",
      expected: graphSliceId,
    },
    {
      label: "Execution action hash",
      decision: endpointDecision(proof.executionReceipt),
      key: "responseActionId",
      expected: actionId,
    },
    {
      label: "Execution ID hash",
      decision: endpointDecision(proof.executionReceipt),
      key: "executionId",
      expected: executionId,
    },
    {
      label: "Execution bundle hash",
      decision: endpointDecision(proof.executionReceipt),
      key: "evidenceBundleId",
      expected: bundleId,
    },
    {
      label: "Execution graph hash",
      decision: endpointDecision(proof.executionReceipt),
      key: "graphSliceId",
      expected: graphSliceId,
    },
    {
      label: "Bundle ID hash",
      decision: endpointDecision(proof.evidenceBundleReceipt),
      key: "evidenceBundleId",
      expected: bundleId,
    },
    {
      label: "Bundle graph hash",
      decision: endpointDecision(proof.evidenceBundleReceipt),
      key: "graphSliceId",
      expected: graphSliceId,
    },
    {
      label: "Bundle content hash",
      decision: endpointDecision(proof.evidenceBundleReceipt),
      key: "contentHash",
      expected: contentHash,
    },
    {
      label: "Bundle node count hash",
      decision: endpointDecision(proof.evidenceBundleReceipt),
      key: "nodeCount",
      expected: nodeCount,
    },
    {
      label: "Bundle edge count hash",
      decision: endpointDecision(proof.evidenceBundleReceipt),
      key: "edgeCount",
      expected: edgeCount,
    },
    ...lifecycleEvidenceHashSpecs(
      "Transition",
      proof.transitionReceipts ?? [],
      actionId,
      executionId,
      graphSliceId,
      rollbackRef,
    ),
    ...lifecycleEvidenceHashSpecs(
      "Rollback",
      proof.rollbackReceipts ?? [],
      actionId,
      executionId,
      graphSliceId,
      rollbackRef,
    ),
    ...lifecycleEvidenceHashSpecs(
      "Acknowledgement",
      proof.acknowledgementReceipts ?? [],
      actionId,
      executionId,
      graphSliceId,
      rollbackRef,
    ),
  ];

  return Promise.all(
    specs.map(async (spec) => {
      const actualHash = evidenceHash(spec.decision, spec.key);
      const expectedHash = spec.expected ? await sha256Prefixed(spec.expected) : null;
      return {
        label: spec.label,
        passed: valuesMatch(normalizeHash(actualHash), expectedHash),
        detail: `${shortHash(actualHash)} / ${shortHash(expectedHash)}`,
      };
    }),
  );
}

function lifecycleEvidenceHashSpecs(
  label: string,
  receipts: SignedReceiptJson[],
  actionId: string,
  executionId: string,
  graphSliceId: string,
  rollbackRef: string,
) {
  return receipts.flatMap((receipt, index) => {
    const decision = endpointDecision(receipt);
    const ordinal = `${label} ${index + 1}`;
    const specs = [
      {
        label: `${ordinal} action hash`,
        decision,
        key: "responseActionId",
        expected: actionId,
      },
      {
        label: `${ordinal} graph hash`,
        decision,
        key: "graphSliceId",
        expected: graphSliceId,
      },
      {
        label: `${ordinal} rollback hash`,
        decision,
        key: "rollbackRef",
        expected: rollbackRef,
      },
    ];
    if (label === "Rollback" || label === "Acknowledgement") {
      specs.push({
        label: `${ordinal} execution hash`,
        decision,
        key: "executionId",
        expected: executionId,
      });
    }
    if (label === "Acknowledgement") {
      specs.push({
        label: `${ordinal} acknowledged-by hash`,
        decision,
        key: "acknowledgedBy",
        expected: stringField(asRecord(decision?.actor), "agentId", "agent_id") ?? "",
      });
    }
    return specs;
  });
}

function endpointDecision(receipt: SignedReceiptJson): EndpointDecisionValue | null {
  const receiptValue = asRecord(receipt.receipt);
  const metadata = asRecord(receiptValue?.metadata);
  return asRecord(metadata?.endpointDecision);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function stringField(record: Record<string, unknown> | null, ...keys: string[]): string | null {
  if (!record) return null;
  for (const key of keys) {
    const value = stringValue(record[key]);
    if (value) return value;
  }
  return null;
}

function evidenceHash(decision: EndpointDecisionValue | null, key: string): string | null {
  const evidence = Array.isArray(decision?.evidence) ? decision.evidence : [];
  for (const item of evidence) {
    const record = asRecord(item);
    if (stringValue(record?.key) === key) {
      return stringField(record, "valueHash", "value_hash");
    }
  }
  return null;
}

function valuesMatch(
  actual: string | null | undefined,
  expected: string | null | undefined,
): boolean {
  return Boolean(actual && expected && actual === expected);
}

function normalizeHash(value: string | null | undefined): string | null {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed) return null;
  return trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
}

function shortHash(value: string | null | undefined): string {
  const normalized = normalizeHash(value);
  if (!normalized) return "-";
  return normalized.length > 18 ? `${normalized.slice(0, 18)}...` : normalized;
}

async function sha256Prefixed(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer);
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
  return `0x${hex}`;
}

function numberText(value: unknown): string {
  return typeof value === "number" ? String(value) : "-";
}

function policyEpochText(value: unknown): string | null {
  if (typeof value === "number") return String(value);
  return stringValue(value);
}

function proofExportFilename(executionId: string): string {
  return `execution-proof-${safeFilenameId(executionId)}`;
}

function verdictExportFilename(executionId: string): string {
  return `execution-proof-verdict-${safeFilenameId(executionId)}`;
}

function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}
