/**
 * ClawdStrike Gate - Security policy enforcement via hushd
 *
 * Posts diffs to hushd /api/v1/check with action_type "patch".
 * Uses PatchIntegrityGuard + SecretLeakGuard on agent output.
 * Non-critical by default (warns, doesn't block).
 * Skipped if hushd is unavailable.
 */

import type { Gate } from "../index"
import type { GateResult, WorkcellInfo, Diagnostic } from "../../types"
import { Hushd } from "../../hushd"

/**
 * ClawdStrike security gate implementation
 */
export const ClawdStrikeGate: Gate = {
  info: {
    id: "clawdstrike",
    name: "ClawdStrike",
    description: "Security policy check via hushd (PatchIntegrity + SecretLeak)",
    critical: false, // Non-critical by default - warns, doesn't block
  },

  async isAvailable(_workcell: WorkcellInfo): Promise<boolean> {
    try {
      const client = Hushd.getClient()
      return await client.probe()
    } catch {
      return false
    }
  },

  async run(workcell: WorkcellInfo, signal: AbortSignal): Promise<GateResult> {
    const startTime = Date.now()
    const diagnostics: Diagnostic[] = []

    try {
      const client = Hushd.getClient()

      // Check if hushd is available
      const available = await client.probe()
      if (!available) {
        return {
          gate: "clawdstrike",
          passed: true, // Fail-open: pass if hushd unavailable
          critical: false,
          output: "hushd unavailable - skipped",
          timing: { startedAt: startTime, completedAt: Date.now() },
        }
      }

      if (signal.aborted) {
        return {
          gate: "clawdstrike",
          passed: false,
          critical: false,
          output: "Cancelled",
          timing: { startedAt: startTime, completedAt: Date.now() },
        }
      }

      // Get diff from workcell
      const { getWorktreeDiff } = await import("../../workcell/git")
      const diff = await getWorktreeDiff(workcell.directory)

      if (!diff || diff.trim().length === 0) {
        return {
          gate: "clawdstrike",
          passed: true,
          critical: false,
          output: "No changes to check",
          timing: { startedAt: startTime, completedAt: Date.now() },
        }
      }

      // Submit patch for security check
      const result = await client.check({
        action_type: "patch",
        target: workcell.directory,
        context: {
          diff,
          workcell_id: workcell.id,
          branch: workcell.branch,
        },
      })

      if (!result) {
        return {
          gate: "clawdstrike",
          passed: true, // Fail-open on connectivity error
          critical: false,
          output: "hushd check failed - skipped",
          timing: { startedAt: startTime, completedAt: Date.now() },
        }
      }

      // Parse guard results into diagnostics
      for (const guard of result.guards) {
        if (guard.decision === "deny") {
          diagnostics.push({
            severity: guard.severity === "critical" ? "error" : "warning",
            message: `${guard.guard}: ${guard.reason ?? "denied"}`,
            source: "clawdstrike",
          })
        }
      }

      const passed = result.decision === "allow"
      const guardSummary = result.guards
        .map(g => `${g.guard}: ${g.decision}`)
        .join(", ")

      return {
        gate: "clawdstrike",
        passed,
        critical: false,
        output: `Policy: ${result.policy} v${result.policy_version} | ${guardSummary}`,
        diagnostics: diagnostics.length > 0 ? diagnostics : undefined,
        timing: { startedAt: startTime, completedAt: Date.now() },
      }
    } catch (err) {
      return {
        gate: "clawdstrike",
        passed: true, // Fail-open on errors
        critical: false,
        output: `Error: ${err instanceof Error ? err.message : String(err)}`,
        timing: { startedAt: startTime, completedAt: Date.now() },
      }
    }
  },
}

export default ClawdStrikeGate
