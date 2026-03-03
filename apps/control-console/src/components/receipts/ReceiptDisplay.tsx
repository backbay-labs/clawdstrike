import type { ReceiptVerification } from "../../utils/receiptVerify";
import { NoiseGrain, Stamp } from "../ui";

export function ReceiptDisplay({ result }: { result: ReceiptVerification }) {
  return (
    <div className="glass-panel" style={{ padding: 20 }}>
      <NoiseGrain />
      <div
        style={{
          position: "relative",
          zIndex: 2,
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        {/* Verification status */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Stamp variant={result.valid ? "allowed" : "blocked"}>
            {result.valid ? "VALID" : "INVALID"}
          </Stamp>
          {result.error && (
            <span className="font-mono" style={{ fontSize: 11, color: "var(--crimson)" }}>
              {result.error}
            </span>
          )}
        </div>

        {/* Receipt fields */}
        {result.receipt && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Field
              label="Signer Key"
              value={result.receipt.signer_public_key.slice(0, 24) + "..."}
            />
            <Field label="Decision" value={result.receipt.decision} />
            <Field label="Action" value={result.receipt.action_type} />
            {result.receipt.target && <Field label="Target" value={result.receipt.target} />}
            {result.receipt.guard && <Field label="Guard" value={result.receipt.guard} />}
            <Field label="Policy Hash" value={result.receipt.policy_hash.slice(0, 24) + "..."} />
            <Field label="Timestamp" value={result.receipt.timestamp} />
            <Field label="Signature" value={result.receipt.signature.slice(0, 24) + "..."} />
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
      <span
        className="font-mono"
        style={{
          fontSize: 10,
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          color: "rgba(214,177,90,0.55)",
          width: 90,
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{ fontSize: 12, color: "var(--text)", wordBreak: "break-all" }}
      >
        {value}
      </span>
    </div>
  );
}
