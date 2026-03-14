import { useState, useRef, useEffect } from "react";
import { useOperator } from "@/lib/workbench/operator-store";

export function IdentityPrompt() {
  const { currentOperator, initialized, createIdentity } = useOperator();
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const submittingRef = useRef(false);
  useEffect(() => () => { mountedRef.current = false; }, []);

  if (!initialized || currentOperator !== null) return null;

  const handleCreate = async () => {
    if (!name.trim()) return;
    if (submittingRef.current) return;
    submittingRef.current = true;
    setCreating(true);
    setError(null);
    try {
      await createIdentity(name.trim());
    } catch (e) {
      if (mountedRef.current) {
        setError(e instanceof Error ? e.message : "Failed to create identity");
      }
    } finally {
      submittingRef.current = false;
      if (mountedRef.current) {
        setCreating(false);
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#05060a]/80 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-[#2d3240] bg-[#131721] p-8 shadow-2xl">
        <div
          className="mx-auto mb-6 h-1 w-12 rounded-full bg-[#d4a84b]"
          style={{ boxShadow: "0 0 12px rgba(212,168,75,0.3)" }}
        />
        <h2 className="text-center text-base font-semibold text-[#ece7dc] tracking-[-0.01em]">
          Create Your Operator Identity
        </h2>
        <p className="mt-2 text-center text-[11px] text-[#6f7f9a]/70 leading-relaxed">
          This generates an Ed25519 keypair that identifies you across swarms,
          sentinels, and signed artifacts. Your private key is stored locally.
        </p>
        <div className="mt-6">
          <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
            Display Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreate();
            }}
            placeholder="Your name or callsign"
            maxLength={64}
            autoFocus
            className="mt-1.5 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2.5 text-[13px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none transition-colors focus:border-[#d4a84b]/40"
          />
        </div>
        {error && (
          <p className="mt-3 text-center text-[11px] text-[#c45c5c]">{error}</p>
        )}
        <button
          onClick={handleCreate}
          disabled={creating || !name.trim()}
          className="mt-5 flex w-full items-center justify-center gap-2 rounded-md px-4 py-2.5 text-[12px] font-semibold transition-colors bg-[#d4a84b]/10 border border-[#d4a84b]/30 text-[#d4a84b] hover:bg-[#d4a84b]/20 disabled:opacity-30 disabled:cursor-not-allowed"
        >
          {creating ? "Generating keypair..." : "Create Identity"}
        </button>
      </div>
    </div>
  );
}
