import { useState, useEffect, useCallback } from "react";
import {
  IconArrowLeft,
  IconShieldCheck,
  IconVectorTriangle,
  IconBug,
  IconSpeakerphone,
  IconFileDescription,
  IconGitPullRequest,
  IconLock,
  IconUsers,
  IconWorld,
  IconDiamond,
  IconMoon,
  IconStar,
  IconKey,
  IconCrown,
  IconSpiral,
  IconWaveSine,
  IconEyeCheck,
  IconCheck,
  IconAlertTriangle,
  IconCircleDot,
  IconClock,
  IconFingerprint,
  IconLink,
  IconCopy,
  IconChevronRight,
  IconExternalLink,
  IconArrowRight,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  Intel,
  IntelType,
  IntelContent,
  IntelContentPattern,
  IntelContentDetectionRule,
  IntelContentIoc,
  IntelContentCampaign,
  IntelContentAdvisory,
  IntelContentPolicyPatch,
  IntelShareability,
  MitreMapping,
} from "@/lib/workbench/sentinel-types";
import type { SigilType } from "@/lib/workbench/sentinel-manager";
import {
  verifyIntel,
  INTEL_TYPE_LABELS,
  SHAREABILITY_LABELS,
} from "@/lib/workbench/intel-forge";

const TYPE_ICONS: Record<IntelType, typeof IconShieldCheck> = {
  detection_rule: IconShieldCheck,
  pattern: IconVectorTriangle,
  ioc: IconBug,
  campaign: IconSpeakerphone,
  advisory: IconFileDescription,
  policy_patch: IconGitPullRequest,
};

const TYPE_COLORS: Record<IntelType, string> = {
  detection_rule: "#5b8def",
  pattern: "#d4784b",
  ioc: "#c45c5c",
  campaign: "#8b5cf6",
  advisory: "#d4a84b",
  policy_patch: "#3dbf84",
};

const SHAREABILITY_ICONS: Record<IntelShareability, typeof IconLock> = {
  private: IconLock,
  swarm: IconUsers,
  public: IconWorld,
};

const SHAREABILITY_COLORS: Record<IntelShareability, string> = {
  private: "#6f7f9a",
  swarm: "#d4a84b",
  public: "#3dbf84",
};

const SIGIL_ICONS: Record<SigilType, typeof IconDiamond> = {
  diamond: IconDiamond,
  eye: IconEyeCheck,
  wave: IconWaveSine,
  crown: IconCrown,
  spiral: IconSpiral,
  key: IconKey,
  star: IconStar,
  moon: IconMoon,
};

export interface IntelDetailProps {
  intel: Intel;
  authorInfo?: {
    name: string;
    sigil: SigilType;
    fingerprint: string;
  };
  onBack?: () => void;
  onNavigateToFinding?: (findingId: string) => void;
  onShareToSwarm?: (intel: Intel) => void;
  onChangeShareability?: (
    intel: Intel,
    shareability: IntelShareability,
  ) => void;
  shareStatus?: "publishing" | "error";
  shareStatusMessage?: string;
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function truncateHex(hex: string, prefixLen = 8, suffixLen = 8): string {
  if (hex.length <= prefixLen + suffixLen + 3) return hex;
  return `${hex.slice(0, prefixLen)}...${hex.slice(-suffixLen)}`;
}

function PatternContent({ content }: { content: IntelContentPattern }) {
  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Pattern Sequence
      </h3>
      <p className="text-[11px] text-[#ece7dc]/80 mb-4 leading-relaxed">
        {content.narrative}
      </p>

      {/* Horizontal flow visualization */}
      {content.sequence.length > 0 && (
        <div className="flex items-center gap-1 overflow-x-auto pb-2">
          {content.sequence.map((step, idx) => (
            <div key={idx} className="flex items-center gap-1 shrink-0">
              {idx > 0 && (
                <IconArrowRight
                  size={12}
                  stroke={1.5}
                  className="text-[#d4a84b]/50 shrink-0"
                />
              )}
              <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/50 px-3 py-2 min-w-[120px]">
                <p className="text-[10px] font-mono font-medium text-[#d4a84b] mb-0.5">
                  Step {step.step}
                </p>
                <p className="text-[10px] text-[#ece7dc] truncate">
                  {step.actionType}
                </p>
                <p className="text-[9px] text-[#6f7f9a] truncate mt-0.5">
                  {step.targetPattern}
                </p>
                {step.timeWindow != null && (
                  <p className="text-[9px] text-[#5b8def] truncate mt-0.5">
                    {step.timeWindow}ms window
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <p className="text-[9px] font-mono text-[#6f7f9a] mt-2">
        {content.matchCount} match{content.matchCount !== 1 ? "es" : ""}{" "}
        observed
      </p>
    </div>
  );
}

function DetectionRuleContent({
  content,
}: {
  content: IntelContentDetectionRule;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(content.sourceText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may fail
    }
  }, [content.sourceText]);

  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Detection Rule
      </h3>
      <p className="text-[11px] text-[#ece7dc]/80 mb-3 leading-relaxed">
        {content.narrative}
      </p>

      <div className="flex items-center gap-2 mb-2">
        <span className="text-[9px] font-mono text-[#6f7f9a]">
          Format:{" "}
          <span className="text-[#d4a84b]">{content.sourceFormat}</span>
        </span>
      </div>

      <div className="relative rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]">
        <pre className="p-3 text-[10px] font-mono text-[#ece7dc]/70 overflow-x-auto max-h-[300px] overflow-y-auto whitespace-pre leading-relaxed">
          {content.sourceText}
        </pre>
        <button
          onClick={handleCopy}
          className="absolute top-2 right-2 flex items-center justify-center w-6 h-6 rounded-md bg-[#131721]/80 border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#d4a84b] hover:border-[#d4a84b]/30 transition-colors"
          title="Copy rule source"
        >
          {copied ? (
            <IconCheck size={10} className="text-[#3dbf84]" />
          ) : (
            <IconCopy size={10} />
          )}
        </button>
      </div>
    </div>
  );
}

function IocContent({ content }: { content: IntelContentIoc }) {
  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Indicators of Compromise
      </h3>
      <p className="text-[11px] text-[#ece7dc]/80 mb-4 leading-relaxed">
        {content.narrative}
      </p>

      {content.indicators.length > 0 && (
        <div className="rounded-lg border border-[#2d3240]/60 overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[80px_1fr_1fr] gap-2 px-3 py-2 bg-[#131721]/50 border-b border-[#2d3240]/40">
            <span className="text-[9px] font-mono font-medium text-[#6f7f9a] uppercase">
              Type
            </span>
            <span className="text-[9px] font-mono font-medium text-[#6f7f9a] uppercase">
              Value
            </span>
            <span className="text-[9px] font-mono font-medium text-[#6f7f9a] uppercase">
              Context
            </span>
          </div>

          {/* Table rows */}
          {content.indicators.map((ioc, idx) => (
            <div
              key={idx}
              className={cn(
                "grid grid-cols-[80px_1fr_1fr] gap-2 px-3 py-2",
                idx % 2 === 0 ? "bg-[#0b0d13]/30" : "bg-transparent",
              )}
            >
              <span className="text-[10px] font-mono text-[#d4a84b]">
                {ioc.type}
              </span>
              <span className="text-[10px] font-mono text-[#ece7dc] break-all">
                {ioc.value}
              </span>
              <span className="text-[10px] text-[#6f7f9a] truncate">
                {ioc.context ?? "-"}
              </span>
            </div>
          ))}
        </div>
      )}

      <p className="text-[9px] font-mono text-[#6f7f9a] mt-2">
        {content.indicators.length} indicator
        {content.indicators.length !== 1 ? "s" : ""}
      </p>
    </div>
  );
}

function CampaignContent({ content }: { content: IntelContentCampaign }) {
  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Campaign: {content.campaignName}
      </h3>
      <p className="text-[11px] text-[#ece7dc]/80 mb-4 leading-relaxed whitespace-pre-wrap">
        {content.narrative}
      </p>

      {content.findingIds.length > 0 && (
        <div>
          <p className="text-[9px] font-mono text-[#6f7f9a] mb-2">
            Related Findings:
          </p>
          <div className="space-y-1">
            {content.findingIds.map((fid) => (
              <div
                key={fid}
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-[#131721]/50 border border-[#2d3240]/40 text-[10px] font-mono text-[#d4a84b] mr-1"
              >
                <IconLink size={9} stroke={1.5} />
                {fid}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function AdvisoryContent({ content }: { content: IntelContentAdvisory }) {
  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Advisory
      </h3>
      <p className="text-[11px] text-[#ece7dc]/80 mb-4 leading-relaxed whitespace-pre-wrap">
        {content.narrative}
      </p>

      {content.recommendations.length > 0 && (
        <div>
          <p className="text-[9px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-2">
            Recommendations
          </p>
          <ul className="space-y-1.5">
            {content.recommendations.map((rec, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2 text-[11px] text-[#ece7dc]/80"
              >
                <IconChevronRight
                  size={10}
                  stroke={2}
                  className="text-[#d4a84b] mt-0.5 shrink-0"
                />
                {rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function PolicyPatchContent({
  content,
}: {
  content: IntelContentPolicyPatch;
}) {
  const patchJson = JSON.stringify(content.guardsPatch, null, 2);
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(patchJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may fail
    }
  }, [patchJson]);

  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Policy Patch
      </h3>
      <p className="text-[11px] text-[#ece7dc]/80 mb-3 leading-relaxed">
        {content.narrative}
      </p>

      {content.targetRuleset && (
        <p className="text-[9px] font-mono text-[#6f7f9a] mb-2">
          Target ruleset:{" "}
          <span className="text-[#d4a84b]">{content.targetRuleset}</span>
        </p>
      )}

      <div className="relative rounded-lg border border-[#2d3240]/60 bg-[#0b0d13]">
        <div className="px-3 py-1.5 border-b border-[#2d3240]/40 flex items-center gap-2">
          <span className="text-[9px] font-mono text-[#3dbf84]">
            + guards patch (JSON Merge Patch RFC 7396)
          </span>
        </div>
        <pre className="p-3 text-[10px] font-mono text-[#3dbf84]/80 overflow-x-auto max-h-[200px] overflow-y-auto whitespace-pre leading-relaxed">
          {patchJson}
        </pre>
        <button
          onClick={handleCopy}
          className="absolute top-1.5 right-2 flex items-center justify-center w-6 h-6 rounded-md bg-[#131721]/80 border border-[#2d3240]/40 text-[#6f7f9a] hover:text-[#d4a84b] hover:border-[#d4a84b]/30 transition-colors"
          title="Copy patch JSON"
        >
          {copied ? (
            <IconCheck size={10} className="text-[#3dbf84]" />
          ) : (
            <IconCopy size={10} />
          )}
        </button>
      </div>
    </div>
  );
}

function ContentRenderer({ content }: { content: IntelContent }) {
  switch (content.kind) {
    case "pattern":
      return <PatternContent content={content} />;
    case "detection_rule":
      return <DetectionRuleContent content={content} />;
    case "ioc":
      return <IocContent content={content} />;
    case "campaign":
      return <CampaignContent content={content} />;
    case "advisory":
      return <AdvisoryContent content={content} />;
    case "policy_patch":
      return <PolicyPatchContent content={content} />;
  }
}

function ProvenanceViewer({
  intel,
  authorInfo,
  onNavigateToFinding,
}: {
  intel: Intel;
  authorInfo?: IntelDetailProps["authorInfo"];
  onNavigateToFinding?: (findingId: string) => void;
}) {
  const [sigExpanded, setSigExpanded] = useState(false);
  const [verification, setVerification] = useState<
    Awaited<ReturnType<typeof verifyIntel>> | null
  >(null);
  const [isVerifying, setIsVerifying] = useState(true);

  useEffect(() => {
    let cancelled = false;

    setIsVerifying(true);
    setVerification(null);

    void verifyIntel(intel)
      .then((result) => {
        if (cancelled) return;
        setVerification(result);
      })
      .catch(() => {
        if (cancelled) return;
        setVerification({
          valid: false,
          reason: "verification_error",
        });
      })
      .finally(() => {
        if (cancelled) return;
        setIsVerifying(false);
      });

    return () => {
      cancelled = true;
    };
  }, [intel]);

  return (
    <div className="space-y-5">
      {/* Signature Block */}
      <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-4">
        <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
          Signature
        </h3>

        {/* Verification status */}
        <div className="flex items-center gap-2 mb-3">
          {isVerifying ? (
            <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-[#5b8def]/10 border border-[#5b8def]/20 text-[10px] font-mono text-[#5b8def]">
              <IconClock size={10} stroke={2} />
              Verifying
            </span>
          ) : verification?.valid ? (
            <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-[#3dbf84]/10 border border-[#3dbf84]/20 text-[10px] font-mono text-[#3dbf84]">
              <IconCheck size={10} stroke={2} />
              Verified
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-[#c45c5c]/10 border border-[#c45c5c]/20 text-[10px] font-mono text-[#c45c5c]">
              <IconAlertTriangle size={10} stroke={2} />
              Unverified
            </span>
          )}
          <span className="text-[9px] text-[#6f7f9a]">
            {isVerifying ? "Verifying signature..." : verification?.reason}
          </span>
        </div>

        {/* Author identity */}
        <div className="space-y-2 mb-3">
          <div className="flex items-center gap-2">
            <IconFingerprint
              size={12}
              stroke={1.5}
              className="text-[#6f7f9a]"
            />
            <span className="text-[9px] font-mono text-[#6f7f9a]">
              Author
            </span>
          </div>
          <div className="flex items-center gap-2 pl-5">
            {authorInfo ? (
              <>
                {(() => {
                  const SigilIcon = SIGIL_ICONS[authorInfo.sigil];
                  return (
                    <SigilIcon
                      size={14}
                      stroke={1.5}
                      className="text-[#d4a84b]"
                    />
                  );
                })()}
                <span className="text-[11px] text-[#ece7dc]">
                  {authorInfo.name}
                </span>
                <span className="text-[9px] font-mono text-[#6f7f9a]">
                  {truncateHex(authorInfo.fingerprint)}
                </span>
              </>
            ) : (
              <span className="text-[11px] font-mono text-[#ece7dc]">
                {truncateHex(intel.author)}
              </span>
            )}
          </div>
        </div>

        {/* Public key */}
        <div className="space-y-1 mb-3">
          <span className="text-[9px] font-mono text-[#6f7f9a] block">
            Public Key
          </span>
          <code className="text-[9px] font-mono text-[#d4a84b]/70 break-all">
            {intel.signerPublicKey
              ? truncateHex(intel.signerPublicKey, 12, 12)
              : "(unsigned)"}
          </code>
        </div>

        {/* Signature bytes */}
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-mono text-[#6f7f9a]">
              Ed25519 Signature
            </span>
            {intel.signature.length > 0 && (
              <button
                onClick={() => setSigExpanded(!sigExpanded)}
                className="text-[9px] font-mono text-[#d4a84b] hover:text-[#ece7dc] transition-colors"
              >
                {sigExpanded ? "Collapse" : "Expand"}
              </button>
            )}
          </div>
          {intel.signature.length > 0 ? (
            <code className="text-[9px] font-mono text-[#ece7dc]/50 break-all block">
              {sigExpanded
                ? intel.signature
                : truncateHex(intel.signature, 16, 16)}
            </code>
          ) : (
            <span className="text-[9px] font-mono text-[#6f7f9a]/50">
              (no signature)
            </span>
          )}
        </div>
      </div>

      {/* Receipt Chain */}
      <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-4">
        <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
          Receipt Chain
        </h3>

        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div
              className={cn(
                "w-2 h-2 rounded-full",
                intel.receipt.valid ? "bg-[#3dbf84]" : "bg-[#c45c5c]",
              )}
            />
            <span className="text-[10px] font-mono text-[#ece7dc]">
              Intel Receipt
            </span>
          </div>
          <div className="ml-3 pl-3 border-l border-[#2d3240]/40 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[#6f7f9a] w-14">
                ID
              </span>
              <code className="text-[9px] font-mono text-[#d4a84b]/70">
                {truncateHex(intel.receipt.id, 8, 8)}
              </code>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[#6f7f9a] w-14">
                Verdict
              </span>
              <span
                className={cn(
                  "text-[9px] font-mono",
                  intel.receipt.verdict === "allow"
                    ? "text-[#3dbf84]"
                    : intel.receipt.verdict === "deny"
                      ? "text-[#c45c5c]"
                      : "text-[#d4a84b]",
                )}
              >
                {intel.receipt.verdict}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[#6f7f9a] w-14">
                Time
              </span>
              <span className="text-[9px] font-mono text-[#ece7dc]/60">
                {intel.receipt.timestamp}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[#6f7f9a] w-14">
                Valid
              </span>
              {intel.receipt.valid ? (
                <IconCheck
                  size={10}
                  stroke={2}
                  className="text-[#3dbf84]"
                />
              ) : (
                <IconAlertTriangle
                  size={10}
                  stroke={2}
                  className="text-[#c45c5c]"
                />
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Derived From */}
      {intel.derivedFrom.length > 0 && (
        <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-4">
          <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
            Derived From
          </h3>
          <div className="space-y-1.5">
            {intel.derivedFrom.map((findingId) => (
              <button
                key={findingId}
                onClick={() => onNavigateToFinding?.(findingId)}
                className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md bg-[#131721]/30 border border-[#2d3240]/40 hover:border-[#d4a84b]/30 hover:bg-[#131721]/50 transition-colors group text-left"
              >
                <IconLink
                  size={10}
                  stroke={1.5}
                  className="text-[#6f7f9a] group-hover:text-[#d4a84b] transition-colors shrink-0"
                />
                <span className="text-[10px] font-mono text-[#ece7dc] truncate group-hover:text-[#d4a84b] transition-colors">
                  {findingId}
                </span>
                <IconExternalLink
                  size={9}
                  stroke={1.5}
                  className="text-[#6f7f9a]/50 ml-auto shrink-0"
                />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Timestamps */}
      <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-4">
        <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
          Timestamps
        </h3>
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <IconClock size={10} stroke={1.5} className="text-[#6f7f9a]" />
            <span className="text-[9px] font-mono text-[#6f7f9a]">
              Created
            </span>
            <span className="text-[10px] font-mono text-[#ece7dc]/70 ml-auto">
              {formatTimestamp(intel.createdAt)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <IconCircleDot size={10} stroke={1.5} className="text-[#6f7f9a]" />
            <span className="text-[9px] font-mono text-[#6f7f9a]">
              Version
            </span>
            <span className="text-[10px] font-mono text-[#ece7dc]/70 ml-auto">
              v{intel.version}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function MitreMappingSection({ mappings }: { mappings: MitreMapping[] }) {
  if (mappings.length === 0) return null;

  // Group by tactic
  const byTactic = new Map<string, MitreMapping[]>();
  for (const m of mappings) {
    const existing = byTactic.get(m.tactic) ?? [];
    existing.push(m);
    byTactic.set(m.tactic, existing);
  }

  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        MITRE ATT&CK Mapping
      </h3>
      <div className="space-y-2">
        {Array.from(byTactic.entries()).map(([tactic, techniques]) => (
          <div key={tactic}>
            <p className="text-[9px] font-mono text-[#8b5cf6] mb-1">
              {tactic}
            </p>
            <div className="flex flex-wrap gap-1 ml-2">
              {techniques.map((t) => (
                <span
                  key={t.techniqueId}
                  className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono text-[#ece7dc]/80 bg-[#8b5cf6]/10 border border-[#8b5cf6]/20"
                  title={t.techniqueName}
                >
                  {t.techniqueId}
                  <span className="text-[#6f7f9a]">
                    {t.techniqueName}
                  </span>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function TagsSection({ tags }: { tags: string[] }) {
  if (tags.length === 0) return null;

  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-2">
        Tags
      </h3>
      <div className="flex flex-wrap gap-1.5">
        {tags.map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 rounded-md text-[10px] font-mono text-[#ece7dc]/70 bg-[#2d3240]/40 border border-[#2d3240]/50"
          >
            {tag}
          </span>
        ))}
      </div>
    </div>
  );
}

function ShareabilityControls({
  intel,
  onChangeShareability,
  onShareToSwarm,
  shareStatus,
  shareStatusMessage,
}: {
  intel: Intel;
  onChangeShareability?: (
    intel: Intel,
    shareability: IntelShareability,
  ) => void;
  onShareToSwarm?: (intel: Intel) => void;
  shareStatus?: "publishing" | "error";
  shareStatusMessage?: string;
}) {
  const levels: IntelShareability[] = ["private", "swarm", "public"];

  return (
    <div>
      <h3 className="text-[11px] font-mono font-medium text-[#6f7f9a] uppercase tracking-wider mb-3">
        Shareability
      </h3>
      <div className="flex items-center gap-1 mb-3">
        {levels.map((level) => {
          const Icon = SHAREABILITY_ICONS[level];
          const color = SHAREABILITY_COLORS[level];
          const isActive = intel.shareability === level;

          return (
            <button
              key={level}
              onClick={() => onChangeShareability?.(intel, level)}
              disabled={!onChangeShareability}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-mono border transition-colors",
                isActive
                  ? "border-opacity-40 bg-opacity-10"
                  : "border-[#2d3240] text-[#6f7f9a] hover:text-[#ece7dc]",
                !onChangeShareability && "cursor-default",
              )}
              style={
                isActive
                  ? {
                      color,
                      backgroundColor: `${color}15`,
                      borderColor: `${color}40`,
                    }
                  : undefined
              }
            >
              <Icon size={11} stroke={1.5} />
              {SHAREABILITY_LABELS[level]}
            </button>
          );
        })}
      </div>

      {/* Share to Swarm button */}
      <button
        onClick={() => onShareToSwarm?.(intel)}
        disabled={
          intel.shareability === "private" || !onShareToSwarm || shareStatus === "publishing"
        }
        className={cn(
          "w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-md text-[11px] font-medium border transition-colors",
          intel.shareability === "private" || !onShareToSwarm || shareStatus === "publishing"
            ? "text-[#6f7f9a]/40 border-[#2d3240]/30 bg-transparent cursor-not-allowed"
            : "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10 hover:bg-[#d4a84b]/20",
        )}
      >
        <IconUsers size={13} stroke={1.5} />
        {shareStatus === "publishing"
          ? "Publishing\u2026"
          : intel.shareability === "private"
            ? "Change to Swarm or Public to share"
            : "Share to Swarm"}
      </button>
      {shareStatus === "error" && shareStatusMessage && (
        <p className="text-[9px] text-red-400/80 mt-1.5 text-center">
          {shareStatusMessage}
        </p>
      )}
      {!onShareToSwarm && shareStatus !== "publishing" && intel.shareability !== "private" && (
        <p className="text-[9px] text-[#6f7f9a]/50 mt-1.5 text-center">
          Swarm sharing is unavailable in this view
        </p>
      )}
    </div>
  );
}

export function IntelDetail({
  intel,
  authorInfo,
  onBack,
  onNavigateToFinding,
  onShareToSwarm,
  onChangeShareability,
  shareStatus,
  shareStatusMessage,
}: IntelDetailProps) {
  const TypeIcon = TYPE_ICONS[intel.type];
  const typeColor = TYPE_COLORS[intel.type];

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Back button */}
      {onBack && (
        <button
          onClick={onBack}
          className="inline-flex items-center gap-1.5 text-[11px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors mb-4"
        >
          <IconArrowLeft size={12} stroke={1.5} />
          Back to Intel Library
        </button>
      )}

      {/* Two-column layout */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left column (65%) -- Content */}
        <div className="flex-1 lg:w-[65%] space-y-6">
          {/* Header */}
          <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
            <div className="flex items-start gap-3 mb-3">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                style={{
                  backgroundColor: `${typeColor}15`,
                  border: `1px solid ${typeColor}30`,
                }}
              >
                <TypeIcon size={18} stroke={1.5} style={{ color: typeColor }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span
                    className="text-[9px] font-mono font-medium px-1.5 py-0.5 rounded"
                    style={{
                      color: typeColor,
                      backgroundColor: `${typeColor}15`,
                      border: `1px solid ${typeColor}30`,
                    }}
                  >
                    {INTEL_TYPE_LABELS[intel.type]}
                  </span>
                  <span className="text-[9px] font-mono text-[#6f7f9a]">
                    {intel.id}
                  </span>
                </div>
                <h1 className="text-lg font-syne font-bold text-[#ece7dc] mb-1">
                  {intel.title}
                </h1>
                <p className="text-[12px] text-[#6f7f9a] leading-relaxed">
                  {intel.description}
                </p>
              </div>
            </div>

            {/* Author info bar */}
            <div className="flex items-center gap-3 pt-3 border-t border-[#2d3240]/30">
              {authorInfo ? (
                <div className="flex items-center gap-1.5">
                  {(() => {
                    const SigilIcon = SIGIL_ICONS[authorInfo.sigil];
                    return (
                      <SigilIcon
                        size={14}
                        stroke={1.5}
                        className="text-[#d4a84b]"
                      />
                    );
                  })()}
                  <span className="text-[11px] text-[#ece7dc]">
                    {authorInfo.name}
                  </span>
                  <span className="text-[9px] font-mono text-[#6f7f9a]">
                    {truncateHex(authorInfo.fingerprint)}
                  </span>
                </div>
              ) : (
                <div className="flex items-center gap-1.5">
                  <IconFingerprint
                    size={12}
                    stroke={1.5}
                    className="text-[#d4a84b]"
                  />
                  <span className="text-[10px] font-mono text-[#ece7dc]">
                    {truncateHex(intel.author)}
                  </span>
                </div>
              )}
              <span className="text-[9px] text-[#6f7f9a] ml-auto flex items-center gap-1">
                <IconClock size={9} stroke={1.5} />
                {formatTimestamp(intel.createdAt)}
              </span>
            </div>
          </div>

          {/* Content Section */}
          <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
            <ContentRenderer content={intel.content} />
          </div>

          {/* MITRE Mapping */}
          {intel.mitre.length > 0 && (
            <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
              <MitreMappingSection mappings={intel.mitre} />
            </div>
          )}

          {/* Tags */}
          {intel.tags.length > 0 && (
            <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
              <TagsSection tags={intel.tags} />
            </div>
          )}

          {/* Shareability Controls */}
          <div className="rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/30 p-5">
            <ShareabilityControls
              intel={intel}
              onChangeShareability={onChangeShareability}
              onShareToSwarm={onShareToSwarm}
              shareStatus={shareStatus}
              shareStatusMessage={shareStatusMessage}
            />
          </div>
        </div>

        {/* Right column (35%) -- Provenance */}
        <div className="lg:w-[35%]">
          <ProvenanceViewer
            intel={intel}
            authorInfo={authorInfo}
            onNavigateToFinding={onNavigateToFinding}
          />
        </div>
      </div>
    </div>
  );
}
