import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

const SETTINGS_PATH_ENV = "CLAWDSTRIKE_AGENT_SETTINGS_PATH"
const WATCH_NATS_URL_ENV = "CLAWDSTRIKE_TUI_HUNT_NATS_URL"
const WATCH_NATS_CREDS_ENV = "CLAWDSTRIKE_TUI_HUNT_NATS_CREDS"
const WATCH_NATS_TOKEN_ENV = "CLAWDSTRIKE_TUI_HUNT_NATS_TOKEN"
const WATCH_NATS_NKEY_SEED_ENV = "CLAWDSTRIKE_TUI_HUNT_NATS_NKEY_SEED"

export interface DesktopAgentSnapshot {
  found: boolean
  settingsPath: string | null
  enabled: boolean
  daemonPort: number | null
  mcpPort: number | null
  agentApiPort: number | null
  dashboardUrl: string | null
  localAgentId: string | null
  enrolled: boolean
  enrollmentInProgress: boolean
  tenantId: string | null
  natsEnabled: boolean
  natsUrl: string | null
  natsCredsFile: string | null
  natsToken: string | null
  nkeySeed: string | null
  natsTokenConfigured: boolean
  nkeySeedConfigured: boolean
  subjectPrefix: string | null
  error: string | null
}

export interface DesktopAgentWatchConfig {
  kind:
    | "manual"
    | "configured"
    | "not_found"
    | "not_enrolled"
    | "nats_disabled"
    | "missing_nats_url"
    | "missing_creds"
    | "read_error"
  natsUrl?: string
  natsCreds?: string
  natsToken?: string
  natsNkeySeed?: string
  authType?: "creds" | "token" | "nkey" | "unauthenticated"
  message: string
}

function normalizeString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null
}

function normalizeNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

function defaultSnapshot(settingsPath: string | null, error: string | null = null): DesktopAgentSnapshot {
  return {
    found: false,
    settingsPath,
    enabled: false,
    daemonPort: null,
    mcpPort: null,
    agentApiPort: null,
    dashboardUrl: null,
    localAgentId: null,
    enrolled: false,
    enrollmentInProgress: false,
    tenantId: null,
    natsEnabled: false,
    natsUrl: null,
    natsCredsFile: null,
    natsToken: null,
    nkeySeed: null,
    natsTokenConfigured: false,
    nkeySeedConfigured: false,
    subjectPrefix: null,
    error,
  }
}

function candidateSettingsPaths(): string[] {
  const explicit = normalizeString(process.env[SETTINGS_PATH_ENV])
  if (explicit) {
    return [explicit]
  }

  const home = os.homedir()
  return [
    path.join(home, "Library", "Application Support", "clawdstrike", "agent.json"),
    path.join(home, ".config", "clawdstrike", "agent.json"),
  ]
}

export function loadDesktopAgentSnapshotSync(): DesktopAgentSnapshot {
  const candidates = candidateSettingsPaths()

  for (const candidate of candidates) {
    try {
      if (!fs.existsSync(candidate)) {
        continue
      }

      const raw = JSON.parse(fs.readFileSync(candidate, "utf8")) as Record<string, unknown>
      const nats = (raw.nats ?? {}) as Record<string, unknown>
      const enrollment = (raw.enrollment ?? {}) as Record<string, unknown>

      return {
        found: true,
        settingsPath: candidate,
        enabled: raw.enabled !== false,
        daemonPort: normalizeNumber(raw.daemon_port),
        mcpPort: normalizeNumber(raw.mcp_port),
        agentApiPort: normalizeNumber(raw.agent_api_port),
        dashboardUrl: normalizeString(raw.dashboard_url),
        localAgentId: normalizeString(raw.local_agent_id),
        enrolled: enrollment.enrolled === true,
        enrollmentInProgress: enrollment.enrollment_in_progress === true,
        tenantId: normalizeString(enrollment.tenant_id) ?? normalizeString(nats.tenant_id),
        natsEnabled: nats.enabled === true,
        natsUrl: normalizeString(nats.nats_url),
        natsCredsFile: normalizeString(nats.creds_file),
        natsToken: normalizeString(nats.token),
        nkeySeed: normalizeString(nats.nkey_seed),
        natsTokenConfigured: normalizeString(nats.token) != null,
        nkeySeedConfigured: normalizeString(nats.nkey_seed) != null,
        subjectPrefix: normalizeString(nats.subject_prefix),
        error: null,
      }
    } catch (err) {
      return defaultSnapshot(
        candidate,
        err instanceof Error ? err.message : String(err),
      )
    }
  }

  return defaultSnapshot(candidates[0] ?? null)
}

export function resolveDesktopAgentWatchConfig(
  snapshot: DesktopAgentSnapshot | null,
): DesktopAgentWatchConfig {
  const manualNatsUrl = normalizeString(process.env[WATCH_NATS_URL_ENV])
  if (manualNatsUrl) {
    const manualNatsCreds = normalizeString(process.env[WATCH_NATS_CREDS_ENV]) ?? undefined
    const manualNatsToken = normalizeString(process.env[WATCH_NATS_TOKEN_ENV]) ?? undefined
    const manualNatsNkeySeed = normalizeString(process.env[WATCH_NATS_NKEY_SEED_ENV]) ?? undefined
    return {
      kind: "manual",
      natsUrl: manualNatsUrl,
      natsCreds: manualNatsCreds,
      natsToken: manualNatsToken,
      natsNkeySeed: manualNatsNkeySeed,
      authType: manualNatsCreds
        ? "creds"
        : manualNatsToken
          ? "token"
          : manualNatsNkeySeed
            ? "nkey"
            : "unauthenticated",
      message: `Using manual watch stream override ${manualNatsUrl}.`,
    }
  }

  if (!snapshot || !snapshot.found) {
    return {
      kind: "not_found",
      message: "Desktop agent settings were not found. Live Watch will use the default direct NATS target.",
    }
  }

  if (snapshot.error) {
    return {
      kind: "read_error",
      message: `Desktop agent settings could not be read: ${snapshot.error}`,
    }
  }

  if (!snapshot.enrolled && !snapshot.natsEnabled) {
    return {
      kind: "not_enrolled",
      message: "Desktop agent cluster streaming is not configured on this workstation (enrollment.enrolled=false, nats.enabled=false).",
    }
  }

  if (!snapshot.enrolled) {
    return {
      kind: "not_enrolled",
      message: "Desktop agent enrollment is incomplete, so no cluster stream is available for Live Watch.",
    }
  }

  if (!snapshot.natsEnabled) {
    return {
      kind: "nats_disabled",
      message: "Desktop agent cluster streaming is disabled in local settings (nats.enabled=false).",
    }
  }

  if (!snapshot.natsUrl) {
    return {
      kind: "missing_nats_url",
      message: "Desktop agent cluster streaming is enabled, but no NATS URL is configured.",
    }
  }

  if (snapshot.natsCredsFile) {
    return {
      kind: "configured",
      natsUrl: snapshot.natsUrl,
      natsCreds: snapshot.natsCredsFile,
      authType: "creds",
      message: `Using desktop agent cluster stream ${snapshot.natsUrl} with creds-file auth.`,
    }
  }

  if (snapshot.natsToken) {
    return {
      kind: "configured",
      natsUrl: snapshot.natsUrl,
      natsToken: snapshot.natsToken,
      authType: "token",
      message: `Using desktop agent cluster stream ${snapshot.natsUrl} with token auth.`,
    }
  }

  if (snapshot.nkeySeed) {
    return {
      kind: "configured",
      natsUrl: snapshot.natsUrl,
      natsNkeySeed: snapshot.nkeySeed,
      authType: "nkey",
      message: `Using desktop agent cluster stream ${snapshot.natsUrl} with nkey auth.`,
    }
  }

  return {
    kind: "missing_creds",
    message: "Desktop agent cluster streaming is enabled, but no NATS auth material is configured for Live Watch.",
  }
}
