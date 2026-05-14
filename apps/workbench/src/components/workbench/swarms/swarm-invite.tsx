// Swarm Invite — Create and Accept invitation tokens for swarm membership.
//
// Two tabs:
//   1. Create Invitation — generate a signed base64url token for sharing
//   2. Accept Invitation — paste and validate an invitation token to join
import { useState, useCallback, useMemo, useRef } from "react";
import {
  IconMail,
  IconMailOpened,
  IconCopy,
  IconCheck,
  IconAlertTriangle,
  IconClock,
  IconShieldCheck,
  IconUser,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { useOperator } from "@/features/operator/stores/operator-store";
import { useSwarms } from "@/features/swarm/stores/swarm-store";
import type { SwarmOperatorRole } from "@/lib/workbench/operator-types";
import { ROLE_HIERARCHY } from "@/lib/workbench/operator-types";
import {
  createInvitation,
  serializeInvitation,
  deserializeInvitation,
  validateInvitation,
  acceptInvitation,
} from "@/lib/workbench/invitation-manager";


type InviteTab = "create" | "accept";

const INVITE_TABS: SubTab[] = [
  { id: "create", label: "Create Invitation", icon: IconMail },
  { id: "accept", label: "Accept Invitation", icon: IconMailOpened },
];

const EXPIRY_OPTIONS: { label: string; ms: number }[] = [
  { label: "1 hour", ms: 60 * 60 * 1000 },
  { label: "1 day", ms: 24 * 60 * 60 * 1000 },
  { label: "7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  { label: "30 days", ms: 30 * 24 * 60 * 60 * 1000 },
];

const ROLE_OPTIONS: SwarmOperatorRole[] = ["observer", "contributor", "admin"];


export function SwarmInvite({ swarmId }: { swarmId: string }) {
  const [activeTab, setActiveTab] = useState<InviteTab>("create");

  return (
    <div className="flex flex-col gap-4">
      {/* Tabs */}
      <SubTabBar tabs={INVITE_TABS} activeTab={activeTab} onTabChange={(id) => setActiveTab(id as InviteTab)} />

      {activeTab === "create" && <CreateTab swarmId={swarmId} />}
      {activeTab === "accept" && <AcceptTab swarmId={swarmId} />}
    </div>
  );
}


function CreateTab({ swarmId }: { swarmId: string }) {
  const { currentOperator, getSecretKey } = useOperator();
  const { addInvitation, swarms } = useSwarms();

  const [role, setRole] = useState<SwarmOperatorRole>("contributor");
  const [expiryMs, setExpiryMs] = useState(EXPIRY_OPTIONS[2].ms);
  const [message, setMessage] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  // Cap available roles at operator's own role in this swarm
  const currentSwarm = swarms.find((s) => s.id === swarmId);
  const currentMember = currentSwarm?.members.find(
    (m) => m.fingerprint === currentOperator?.fingerprint,
  );
  const operatorRole: SwarmOperatorRole =
    (currentMember?.role as SwarmOperatorRole) ?? "observer";
  const availableRoles = useMemo(
    () => ROLE_OPTIONS.filter((r) => ROLE_HIERARCHY[r] <= ROLE_HIERARCHY[operatorRole]),
    [operatorRole],
  );

  const handleGenerate = useCallback(async () => {
    if (!currentOperator) {
      setError("No operator identity — create one in Settings first.");
      return;
    }
    if (!currentMember) {
      setError("You must be a member of this swarm to create invitations.");
      return;
    }
    setGenerating(true);
    setError(null);
    setResult(null);
    try {
      const secretKey = await getSecretKey();
      if (!secretKey) {
        setError("Secret key unavailable.");
        return;
      }
      const signed = await createInvitation({
        inviterIdentity: currentOperator,
        inviterSecretKey: secretKey,
        inviterRole: operatorRole,
        swarmId,
        grantedRole: role,
        expiresInMs: expiryMs,
        message: message.trim() || undefined,
      });
      const encoded = serializeInvitation(signed);
      setResult(encoded);
      addInvitation(swarmId, signed.claims.jti);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate invitation");
    } finally {
      setGenerating(false);
    }
  }, [currentOperator, currentMember, getSecretKey, swarmId, role, expiryMs, message, addInvitation, operatorRole]);

  const handleCopy = useCallback(() => {
    if (!result) return;
    navigator.clipboard.writeText(result);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [result]);

  return (
    <div className="flex flex-col gap-4">
      {/* Role selector */}
      <div>
        <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
          Granted Role
        </label>
        <div className="mt-1.5 flex items-center gap-1.5">
          {availableRoles.map((r) => (
            <button
              key={r}
              onClick={() => setRole(r)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-[11px] font-medium border capitalize transition-colors",
                role === r
                  ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10"
                  : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/20 hover:text-[#ece7dc]",
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Expiry picker */}
      <div>
        <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
          Expiry
        </label>
        <div className="mt-1.5 flex items-center gap-1.5">
          {EXPIRY_OPTIONS.map((opt) => (
            <button
              key={opt.ms}
              onClick={() => setExpiryMs(opt.ms)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-[11px] font-medium border transition-colors",
                expiryMs === opt.ms
                  ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10"
                  : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/20 hover:text-[#ece7dc]",
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Message */}
      <div>
        <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
          Message (optional)
        </label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Personal note for the invitee..."
          rows={2}
          maxLength={256}
          className="mt-1.5 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none transition-colors focus:border-[#d4a84b]/40 resize-none"
        />
      </div>

      {/* Generate button */}
      <button
        onClick={handleGenerate}
        disabled={generating || !currentMember}
        className={cn(
          "flex items-center justify-center gap-2 rounded-md px-4 py-2 text-[11px] font-medium transition-colors",
          generating
            ? "bg-[#2d3240]/30 border border-[#2d3240]/40 text-[#6f7f9a]/30 cursor-wait"
            : "bg-[#d4a84b]/10 border border-[#d4a84b]/30 text-[#d4a84b] hover:bg-[#d4a84b]/20",
        )}
      >
        <IconMail size={13} stroke={1.5} />
        {generating ? "Generating..." : "Generate Invitation"}
      </button>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 rounded-md border border-[#c45c5c]/30 bg-[#c45c5c]/5 px-3 py-2 text-[11px] text-[#c45c5c]">
          <IconAlertTriangle size={13} stroke={1.5} />
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="flex flex-col gap-2">
          <label className="text-[10px] uppercase tracking-[0.08em] text-[#3dbf84]/60 font-semibold flex items-center gap-1.5">
            <IconCheck size={11} stroke={2} />
            Invitation Token
          </label>
          <div className="relative">
            <textarea
              readOnly
              value={result}
              rows={4}
              className="w-full rounded-md border border-[#3dbf84]/20 bg-[#05060a] px-3 py-2 text-[10px] font-mono text-[#ece7dc]/70 outline-none resize-none"
            />
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 rounded-md border border-[#2d3240] bg-[#131721] p-1.5 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
            >
              {copied ? <IconCheck size={12} className="text-[#3dbf84]" /> : <IconCopy size={12} />}
            </button>
          </div>
          <p className="text-[10px] text-[#6f7f9a]/50">
            Share this token with the person you want to invite. It expires in{" "}
            {EXPIRY_OPTIONS.find((o) => o.ms === expiryMs)?.label ?? "unknown"}.
          </p>
        </div>
      )}
    </div>
  );
}


function AcceptTab({ swarmId }: { swarmId: string }) {
  const { currentOperator, getSecretKey } = useOperator();
  const { markInvitationUsed, addMember } = useSwarms();

  const [token, setToken] = useState("");
  const [status, setStatus] = useState<"idle" | "validating" | "valid" | "accepted" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [parsedInfo, setParsedInfo] = useState<{
    swarmId: string;
    issuerFingerprint: string;
    role: SwarmOperatorRole;
    expiry: string;
    message?: string;
  } | null>(null);

  const validationSeqRef = useRef(0);

  const handlePaste = useCallback(
    async (value: string) => {
      setToken(value);
      setParsedInfo(null);
      setError(null);
      if (!value.trim()) {
        setStatus("idle");
        return;
      }
      const seq = ++validationSeqRef.current;
      setStatus("validating");
      try {
        const signed = deserializeInvitation(value.trim());
        const validation = await validateInvitation(signed);
        if (seq !== validationSeqRef.current) return; // stale
        if (!validation.valid) {
          setError(validation.error ?? "Invalid invitation");
          setStatus("error");
          return;
        }
        setParsedInfo({
          swarmId: signed.claims.swarmId,
          issuerFingerprint: signed.claims.iss,
          role: signed.claims.grantedRole,
          expiry: new Date(signed.claims.exp).toLocaleString(),
          message: signed.claims.message,
        });
        setStatus("valid");
      } catch (e) {
        if (seq !== validationSeqRef.current) return; // stale
        setError(e instanceof Error ? e.message : "Failed to parse invitation token");
        setStatus("error");
      }
    },
    [],
  );

  const handleAccept = useCallback(async () => {
    if (!currentOperator || !token.trim()) return;
    setError(null);
    try {
      const secretKey = await getSecretKey();
      if (!secretKey) {
        setError("Secret key unavailable.");
        return;
      }
      const signed = deserializeInvitation(token.trim());
      const accepted = await acceptInvitation(signed, currentOperator, secretKey);
      markInvitationUsed(accepted.invitation.claims.swarmId, accepted.invitation.claims.jti);
      const now = Date.now();
      addMember(accepted.invitation.claims.swarmId, {
        type: "operator",
        fingerprint: currentOperator.fingerprint,
        displayName: currentOperator.displayName,
        role: accepted.invitation.claims.grantedRole,
        reputation: {
          overall: 0.5,
          trustLevel: "Medium",
          intelContributed: 0,
          truePositives: 0,
          falsePositives: 0,
          lastUpdated: now,
        },
        joinedAt: now,
        lastSeenAt: now,
        sentinelId: null,
        invitedBy: accepted.invitation.claims.iss,
        invitationDepth: accepted.invitation.claims.depth,
      });
      setStatus("accepted");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to accept invitation");
      setStatus("error");
    }
  }, [currentOperator, getSecretKey, token, markInvitationUsed, addMember]);

  return (
    <div className="flex flex-col gap-4">
      {/* Paste field */}
      <div>
        <label className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/60 font-semibold">
          Invitation Token
        </label>
        <textarea
          value={token}
          onChange={(e) => handlePaste(e.target.value)}
          placeholder="Paste a base64url invitation token..."
          rows={4}
          className="mt-1.5 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[10px] font-mono text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none transition-colors focus:border-[#d4a84b]/40 resize-none"
        />
      </div>

      {/* Validation status */}
      {status === "validating" && (
        <div className="flex items-center gap-2 text-[11px] text-[#6f7f9a]">
          <IconClock size={13} stroke={1.5} className="animate-pulse" />
          Validating...
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 rounded-md border border-[#c45c5c]/30 bg-[#c45c5c]/5 px-3 py-2 text-[11px] text-[#c45c5c]">
          <IconAlertTriangle size={13} stroke={1.5} />
          {error}
        </div>
      )}

      {/* Parsed details */}
      {parsedInfo && status === "valid" && (
        <div className="rounded-md border border-[#3dbf84]/20 bg-[#3dbf84]/5 p-4 flex flex-col gap-2">
          <div className="flex items-center gap-2 text-[11px] text-[#3dbf84] font-medium">
            <IconShieldCheck size={13} stroke={1.5} />
            Valid Invitation
          </div>
          <div className="grid grid-cols-2 gap-y-1.5 gap-x-4 text-[10px]">
            <span className="text-[#6f7f9a]">Swarm ID</span>
            <span className="font-mono text-[#ece7dc]/70 truncate">{parsedInfo.swarmId}</span>
            <span className="text-[#6f7f9a]">Inviter</span>
            <span className="font-mono text-[#ece7dc]/70 flex items-center gap-1">
              <IconUser size={10} stroke={1.5} />
              {parsedInfo.issuerFingerprint}
            </span>
            <span className="text-[#6f7f9a]">Role</span>
            <span className="text-[#ece7dc]/70 capitalize">{parsedInfo.role}</span>
            <span className="text-[#6f7f9a]">Expires</span>
            <span className="text-[#ece7dc]/70">{parsedInfo.expiry}</span>
          </div>
          {parsedInfo.message && (
            <div className="mt-1 text-[10px] text-[#ece7dc]/50 italic">
              "{parsedInfo.message}"
            </div>
          )}
          <button
            onClick={handleAccept}
            className="mt-2 flex items-center justify-center gap-2 rounded-md px-4 py-2 text-[11px] font-medium bg-[#3dbf84]/10 border border-[#3dbf84]/30 text-[#3dbf84] hover:bg-[#3dbf84]/20 transition-colors"
          >
            <IconMailOpened size={13} stroke={1.5} />
            Accept Invitation
          </button>
        </div>
      )}

      {/* Success */}
      {status === "accepted" && (
        <div className="flex items-center gap-2 rounded-md border border-[#3dbf84]/30 bg-[#3dbf84]/5 px-3 py-2 text-[11px] text-[#3dbf84]">
          <IconCheck size={13} stroke={1.5} />
          Invitation accepted. You have joined the swarm.
        </div>
      )}
    </div>
  );
}


