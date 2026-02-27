import { useState } from "react";
import { verifyReceipt, type ReceiptVerification } from "../utils/receiptVerify";
import { ReceiptDisplay } from "../components/receipts/ReceiptDisplay";
import { GlassButton } from "../components/ui";

export function ReceiptVerifier(_props: { windowId?: string }) {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ReceiptVerification | null>(null);
  const [loading, setLoading] = useState(false);

  const handleVerify = async () => {
    if (!input.trim()) return;
    setLoading(true);
    try {
      const r = await verifyReceipt(input);
      setResult(r);
    } catch {
      setResult({ valid: false, error: "Unexpected error during verification" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5" style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Paste a signed receipt JSON..."
        className="glass-input font-mono rounded-md p-3 text-sm outline-none"
        style={{ color: "var(--text)", width: "100%", minHeight: 200, resize: "vertical" }}
      />

      <div style={{ display: "flex", gap: 8 }}>
        <GlassButton variant="primary" onClick={handleVerify} disabled={loading || !input.trim()}>
          {loading ? "Verifying..." : "Verify"}
        </GlassButton>
        {result && (
          <GlassButton onClick={() => { setResult(null); setInput(""); }}>Clear</GlassButton>
        )}
      </div>

      {result && <ReceiptDisplay result={result} />}
    </div>
  );
}
