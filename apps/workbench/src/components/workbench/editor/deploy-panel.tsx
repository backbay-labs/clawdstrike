import { useState, useCallback } from "react";
import {
  IconRocket,
  IconDownload,
  IconAlertTriangle,
  IconCheck,
  IconX,
  IconLoader2,
  IconCircleDot,
  IconShieldCheck,
  IconArrowRight,
} from "@tabler/icons-react";
import { emitAuditEvent } from "@/lib/workbench/local-audit";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import {
  deployPolicy,
  validateRemotely,
  fetchRemotePolicy,
  type DeployResponse,
  type ValidateResponse,
} from "@/lib/workbench/fleet-client";
import { useToast } from "@/components/ui/toast";

// ---- Deploy confirmation text ----
const CONFIRM_TEXT = "deploy";

export function DeployPanel() {
  const { connection, agents, remotePolicyInfo, refreshRemotePolicy } = useFleetConnection();
  const { state } = useWorkbench();

  const [deployOpen, setDeployOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);

  if (!connection.connected) return null;

  const onlineAgents = agents.filter((a) => a.online).length;

  // ---- Diff indicator ----
  const hasRemotePolicy = !!remotePolicyInfo?.yaml;
  const localYaml = state.yaml;
  const isDifferent = hasRemotePolicy && localYaml !== remotePolicyInfo.yaml;

  return (
    <div className="flex flex-col gap-3 p-4 border-t border-[#2d3240]/60">
      {/* ---- Section header ---- */}
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
          Fleet Deployment
        </h3>
        <div className="flex items-center gap-1.5 text-[10px] text-[#3dbf84]">
          <IconCircleDot size={10} stroke={2} />
          <span>{onlineAgents} online</span>
        </div>
      </div>

      {/* ---- Diff status ---- */}
      {hasRemotePolicy && (
        <div
          className={cn(
            "flex items-center gap-2 px-3 py-2 rounded-md text-[10px] border",
            isDifferent
              ? "bg-[#d4a84b]/5 border-[#d4a84b]/15 text-[#d4a84b]"
              : "bg-[#3dbf84]/5 border-[#3dbf84]/15 text-[#3dbf84]",
          )}
        >
          {isDifferent ? (
            <>
              <IconAlertTriangle size={12} stroke={1.5} />
              <span>Local policy differs from production</span>
            </>
          ) : (
            <>
              <IconCheck size={12} stroke={2} />
              <span>Policy matches production</span>
            </>
          )}
        </div>
      )}

      {/* ---- Remote policy info ---- */}
      {remotePolicyInfo && (
        <div className="text-[10px] text-[#6f7f9a]">
          Remote: {remotePolicyInfo.name ?? "unnamed"}
          {remotePolicyInfo.policyHash && (
            <span className="font-mono ml-1">
              ({remotePolicyInfo.policyHash.slice(0, 8)}...)
            </span>
          )}
        </div>
      )}

      {/* ---- Action buttons ---- */}
      <div className="flex items-center gap-2">
        <Dialog open={deployOpen} onOpenChange={setDeployOpen}>
          <button
            onClick={() => setDeployOpen(true)}
            className="flex-1 flex items-center justify-center gap-1.5 h-8 rounded-lg text-[11px] font-medium bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a] transition-colors"
          >
            <IconRocket size={13} stroke={2} />
            Deploy to Fleet
          </button>
          <DeployConfirmDialog
            onClose={() => setDeployOpen(false)}
            onSuccess={() => {
              setDeployOpen(false);
              refreshRemotePolicy();
            }}
          />
        </Dialog>

        <Dialog open={importOpen} onOpenChange={setImportOpen}>
          <button
            onClick={() => setImportOpen(true)}
            className="flex items-center justify-center gap-1.5 h-8 px-3 rounded-lg text-[11px] font-medium text-[#ece7dc] bg-[#131721] border border-[#2d3240] hover:border-[#d4a84b]/30 transition-colors"
          >
            <IconDownload size={13} stroke={1.5} />
            Import
          </button>
          <ImportConfirmDialog
            onClose={() => setImportOpen(false)}
          />
        </Dialog>
      </div>
    </div>
  );
}


function DeployConfirmDialog({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const { connection, agents, getAuthenticatedConnection: getAuthedConn } = useFleetConnection();
  const { state } = useWorkbench();
  const { toast } = useToast();

  const [confirmText, setConfirmText] = useState("");
  const [isDeploying, setIsDeploying] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidateResponse | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [deployResult, setDeployResult] = useState<DeployResponse | null>(null);

  const canDeploy = confirmText.toLowerCase() === CONFIRM_TEXT && !isDeploying;
  const onlineAgents = agents.filter((a) => a.online);

  // ---- Validate first ----
  const handleValidate = useCallback(async () => {
    setIsValidating(true);
    try {
      const result = await validateRemotely(getAuthedConn(), state.yaml);
      setValidationResult(result);
    } catch (err) {
      setValidationResult({
        valid: false,
        errors: [err instanceof Error ? err.message : "Validation request failed"],
      });
    } finally {
      setIsValidating(false);
    }
  }, [getAuthedConn, state.yaml]);

  // ---- Deploy ----
  const handleDeploy = useCallback(async () => {
    setIsDeploying(true);
    setDeployResult(null);
    try {
      const result = await deployPolicy(getAuthedConn(), state.yaml);
      setDeployResult(result);
      if (result.success) {
        toast({
          type: "success",
          title: "Policy deployed",
          description: result.hash
            ? `Hash: ${result.hash.slice(0, 12)}...`
            : "Policy is now active on the fleet",
        });
        emitAuditEvent({
          eventType: "fleet.deploy.success",
          source: "deploy",
          summary: `Deployed policy to ${onlineAgents.length} agent(s)`,
          details: {
            policyName: state.activePolicy?.name,
            hash: result.hash,
            agentCount: onlineAgents.length,
          },
        });
        onSuccess();
      } else {
        toast({
          type: "error",
          title: "Deploy failed",
          description: result.error ?? "Unknown error",
          duration: 5000,
        });
        emitAuditEvent({
          eventType: "fleet.deploy.failure",
          source: "deploy",
          summary: `Deploy failed: ${result.error ?? "Unknown error"}`,
          details: { error: result.error },
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Deploy request failed";
      setDeployResult({ success: false, error: msg });
      toast({ type: "error", title: "Deploy failed", description: msg, duration: 5000 });
      emitAuditEvent({
        eventType: "fleet.deploy.failure",
        source: "deploy",
        summary: `Deploy failed: ${msg}`,
        details: { error: msg },
      });
    } finally {
      setIsDeploying(false);
    }
  }, [getAuthedConn, state.yaml, toast, onSuccess]);

  return (
    <DialogContent
      className="sm:max-w-md bg-[#0b0d13] border-[#2d3240]"
      showCloseButton={false}
    >
      <DialogHeader>
        <DialogTitle className="text-[#ece7dc] flex items-center gap-2">
          <IconAlertTriangle size={18} stroke={2} className="text-[#c45c5c]" />
          Deploy to Production Fleet
        </DialogTitle>
        <DialogDescription className="text-[#6f7f9a]">
          This will push your local policy to{" "}
          <span className="font-mono text-[#d4a84b]">{onlineAgents.length}</span> online agents.
          This action takes effect immediately.
        </DialogDescription>
      </DialogHeader>

      {/* ---- Warning box ---- */}
      <div className="flex flex-col gap-3 my-2">
        <div className="p-3 rounded-lg bg-[#c45c5c]/5 border border-[#c45c5c]/20">
          <p className="text-[11px] text-[#c45c5c] font-medium mb-1">
            Production deployment warning
          </p>
          <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
            Deploying an incorrect policy can block legitimate agent operations or create
            security gaps. Ensure you have validated this policy and tested it in the Threat Lab
            before deploying.
          </p>
        </div>

        {/* ---- Agent list (collapsed) ---- */}
        <div className="flex flex-col gap-1">
          <p className="text-[10px] font-medium text-[#6f7f9a] uppercase tracking-wider">
            Receiving Agents ({onlineAgents.length})
          </p>
          <div className="max-h-24 overflow-y-auto rounded-md bg-[#131721] border border-[#2d3240]/60 p-2">
            {onlineAgents.length === 0 ? (
              <p className="text-[10px] text-[#6f7f9a] italic">No online agents</p>
            ) : (
              <div className="flex flex-col gap-1">
                {onlineAgents.slice(0, 20).map((agent) => (
                  <div
                    key={agent.endpoint_agent_id}
                    className="flex items-center gap-2 text-[10px]"
                  >
                    <IconCircleDot size={8} stroke={2} className="text-[#3dbf84] shrink-0" />
                    <span className="font-mono text-[#ece7dc] truncate">
                      {agent.endpoint_agent_id}
                    </span>
                    {agent.posture && (
                      <span className="text-[#6f7f9a] ml-auto shrink-0">{agent.posture}</span>
                    )}
                  </div>
                ))}
                {onlineAgents.length > 20 && (
                  <p className="text-[10px] text-[#6f7f9a] italic mt-1">
                    ...and {onlineAgents.length - 20} more
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ---- Remote validation ---- */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleValidate}
            disabled={isValidating}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-medium text-[#ece7dc] bg-[#131721] border border-[#2d3240] hover:border-[#d4a84b]/30 transition-colors"
          >
            {isValidating ? (
              <IconLoader2 size={11} stroke={1.5} className="animate-spin" />
            ) : (
              <IconShieldCheck size={11} stroke={1.5} />
            )}
            Validate Remotely
          </button>
          {validationResult && (
            <span
              className={cn(
                "text-[10px] flex items-center gap-1",
                validationResult.valid ? "text-[#3dbf84]" : "text-[#c45c5c]",
              )}
            >
              {validationResult.valid ? (
                <>
                  <IconCheck size={10} stroke={2} /> Valid
                </>
              ) : (
                <>
                  <IconX size={10} stroke={2} /> {validationResult.errors[0]}
                </>
              )}
            </span>
          )}
        </div>

        {/* ---- Type to confirm ---- */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] text-[#6f7f9a]">
            Type <span className="font-mono text-[#c45c5c] font-bold">{CONFIRM_TEXT}</span> to
            confirm deployment:
          </label>
          <input
            type="text"
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder={CONFIRM_TEXT}
            autoComplete="off"
            spellCheck={false}
            className={cn(
              "h-8 px-2.5 rounded-lg border text-xs font-mono focus:outline-none focus:ring-1 transition-colors",
              confirmText.toLowerCase() === CONFIRM_TEXT
                ? "border-[#c45c5c]/40 bg-[#c45c5c]/5 text-[#c45c5c] focus:ring-[#c45c5c]/20"
                : "border-[#2d3240] bg-[#131721] text-[#ece7dc] focus:border-[#d4a84b]/50 focus:ring-[#d4a84b]/20",
            )}
          />
        </div>
      </div>

      {/* ---- Deploy result ---- */}
      {deployResult && !deployResult.success && (
        <div className="p-2 rounded-md bg-[#c45c5c]/5 border border-[#c45c5c]/20 text-[10px] text-[#c45c5c]">
          {deployResult.error}
        </div>
      )}

      <DialogFooter className="bg-[#0b0d13] border-[#2d3240]/60">
        <DialogClose
          render={
            <button className="flex items-center justify-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium text-[#6f7f9a] hover:text-[#ece7dc] bg-[#131721] border border-[#2d3240] transition-colors" />
          }
        >
          Cancel
        </DialogClose>
        <button
          onClick={handleDeploy}
          disabled={!canDeploy}
          className={cn(
            "flex items-center justify-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium transition-all",
            canDeploy
              ? "bg-[#c45c5c] text-white hover:bg-[#d46b6b]"
              : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] opacity-50 cursor-not-allowed",
          )}
        >
          {isDeploying ? (
            <>
              <IconLoader2 size={13} stroke={2} className="animate-spin" />
              Deploying...
            </>
          ) : (
            <>
              <IconRocket size={13} stroke={2} />
              Deploy Now
            </>
          )}
        </button>
      </DialogFooter>
    </DialogContent>
  );
}


function ImportConfirmDialog({ onClose }: { onClose: () => void }) {
  const { connection, getAuthenticatedConnection: getAuthedImport } = useFleetConnection();
  const { state, dispatch } = useWorkbench();
  const { toast } = useToast();

  const [isImporting, setIsImporting] = useState(false);

  const handleImport = useCallback(async () => {
    setIsImporting(true);
    try {
      const remote = await fetchRemotePolicy(getAuthedImport());
      if (!remote.yaml) {
        toast({ type: "warning", title: "No remote policy", description: "The remote daemon has no active policy." });
        return;
      }
      dispatch({ type: "SET_YAML", yaml: remote.yaml });
      toast({
        type: "success",
        title: "Policy imported",
        description: `Loaded ${remote.name ?? "remote policy"} into editor`,
      });
      onClose();
    } catch (err) {
      toast({
        type: "error",
        title: "Import failed",
        description: err instanceof Error ? err.message : "Failed to fetch remote policy",
        duration: 5000,
      });
    } finally {
      setIsImporting(false);
    }
  }, [getAuthedImport, dispatch, toast, onClose]);

  return (
    <DialogContent
      className="sm:max-w-sm bg-[#0b0d13] border-[#2d3240]"
      showCloseButton={false}
    >
      <DialogHeader>
        <DialogTitle className="text-[#ece7dc] flex items-center gap-2">
          <IconDownload size={18} stroke={1.5} className="text-[#d4a84b]" />
          Import from Production
        </DialogTitle>
        <DialogDescription className="text-[#6f7f9a]">
          This will replace your current editor content with the policy running in production.
          {state.dirty && (
            <span className="block mt-1 text-[#d4a84b]">
              You have unsaved local changes that will be lost.
            </span>
          )}
        </DialogDescription>
      </DialogHeader>

      <DialogFooter className="bg-[#0b0d13] border-[#2d3240]/60">
        <DialogClose
          render={
            <button className="flex items-center justify-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium text-[#6f7f9a] hover:text-[#ece7dc] bg-[#131721] border border-[#2d3240] transition-colors" />
          }
        >
          Cancel
        </DialogClose>
        <button
          onClick={handleImport}
          disabled={isImporting}
          className={cn(
            "flex items-center justify-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium transition-all",
            isImporting
              ? "bg-[#d4a84b]/20 text-[#d4a84b] cursor-wait"
              : "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]",
          )}
        >
          {isImporting ? (
            <>
              <IconLoader2 size={13} stroke={2} className="animate-spin" />
              Importing...
            </>
          ) : (
            <>
              <IconArrowRight size={13} stroke={2} />
              Import Policy
            </>
          )}
        </button>
      </DialogFooter>
    </DialogContent>
  );
}
