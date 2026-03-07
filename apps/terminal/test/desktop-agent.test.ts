import { afterEach, describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import {
  loadDesktopAgentSnapshotSync,
  resolveDesktopAgentWatchConfig,
} from "../src/desktop-agent"

const SETTINGS_PATH_ENV = "CLAWDSTRIKE_AGENT_SETTINGS_PATH"

afterEach(() => {
  delete process.env[SETTINGS_PATH_ENV]
})

describe("desktop agent discovery", () => {
  test("loads agent settings from an explicit path override", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-desktop-agent-"))
    const settingsPath = path.join(tempDir, "agent.json")

    await fs.writeFile(settingsPath, JSON.stringify({
      enabled: true,
      daemon_port: 9876,
      mcp_port: 9877,
      agent_api_port: 9878,
      dashboard_url: "http://127.0.0.1:9878/ui",
      local_agent_id: "endpoint-test",
      nats: {
        enabled: true,
        nats_url: "nats://cluster.example:4222",
        creds_file: "/tmp/cluster.creds",
        token: null,
        nkey_seed: null,
        subject_prefix: "tenant.demo",
      },
      enrollment: {
        enrolled: true,
        enrollment_in_progress: false,
        tenant_id: "tenant-demo",
      },
    }))

    process.env[SETTINGS_PATH_ENV] = settingsPath
    const snapshot = loadDesktopAgentSnapshotSync()

    expect(snapshot.found).toBe(true)
    expect(snapshot.settingsPath).toBe(settingsPath)
    expect(snapshot.enrolled).toBe(true)
    expect(snapshot.natsEnabled).toBe(true)
    expect(snapshot.natsUrl).toBe("nats://cluster.example:4222")
    expect(snapshot.natsCredsFile).toBe("/tmp/cluster.creds")
  })

  test("accepts token-backed watch configuration without a creds file", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-desktop-agent-"))
    const settingsPath = path.join(tempDir, "agent.json")

    await fs.writeFile(settingsPath, JSON.stringify({
      enabled: true,
      nats: {
        enabled: true,
        nats_url: "nats://cluster.example:4222",
        creds_file: null,
        token: "secret-token",
        nkey_seed: null,
      },
      enrollment: {
        enrolled: true,
        enrollment_in_progress: false,
      },
    }))

    process.env[SETTINGS_PATH_ENV] = settingsPath
    const watch = resolveDesktopAgentWatchConfig(loadDesktopAgentSnapshotSync())

    expect(watch.kind).toBe("configured")
    expect(watch.authType).toBe("token")
    expect(watch.natsToken).toBe("secret-token")
    expect(watch.message).toContain("token auth")
  })
})
