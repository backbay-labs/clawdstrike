/**
 * MCP module tests
 *
 * Tests for the Model Context Protocol server.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { MCP } from "../src/mcp"
import { Health } from "../src/health"
import * as fs from "node:fs/promises"
import * as path from "node:path"
import * as os from "node:os"
import { Socket } from "node:net"

// Create temp directory for tests
let tempDir: string

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-mcp-test-"))
  // Ensure MCP is stopped
  try {
    await MCP.stop()
  } catch {
    // Ignore if not running
  }
})

afterEach(async () => {
  try {
    await MCP.stop()
  } catch {
    // Ignore if not running
  }
  await fs.rm(tempDir, { recursive: true, force: true })
})

describe("MCP Server", () => {
  describe("start", () => {
    test("starts server and returns port", async () => {
      const port = await MCP.start({ cwd: tempDir })

      expect(typeof port).toBe("number")
      expect(port).toBeGreaterThan(0)
    })

    test("creates discovery file", async () => {
      await MCP.start({ cwd: tempDir })

      const discoveryPath = path.join(tempDir, ".clawdstrike", "mcp.json")
      const exists = await Bun.file(discoveryPath).exists()
      expect(exists).toBe(true)

      const content = await Bun.file(discoveryPath).json()
      expect(content).toHaveProperty("port")
      expect(content).toHaveProperty("host")
      expect(content).toHaveProperty("pid")
      expect(content).toHaveProperty("tools")
      expect(Array.isArray(content.tools)).toBe(true)
    })

    test("updates Health MCP status", async () => {
      const port = await MCP.start({ cwd: tempDir })

      const status = Health.getMcpStatus()
      expect(status.running).toBe(true)
      expect(status.port).toBe(port)
    })

    test("throws if already running", async () => {
      await MCP.start({ cwd: tempDir })

      await expect(MCP.start({ cwd: tempDir })).rejects.toThrow("already running")
    })
  })

  describe("stop", () => {
    test("stops running server", async () => {
      await MCP.start({ cwd: tempDir })
      expect(MCP.isRunning()).toBe(true)

      await MCP.stop()
      expect(MCP.isRunning()).toBe(false)
    })

    test("updates Health MCP status", async () => {
      await MCP.start({ cwd: tempDir })
      await MCP.stop()

      const status = Health.getMcpStatus()
      expect(status.running).toBe(false)
    })

    test("does not throw if not running", async () => {
      await expect(MCP.stop()).resolves.toBeUndefined()
    })
  })

  describe("isRunning", () => {
    test("returns false when not started", () => {
      expect(MCP.isRunning()).toBe(false)
    })

    test("returns true when running", async () => {
      await MCP.start({ cwd: tempDir })
      expect(MCP.isRunning()).toBe(true)
    })

    test("returns false after stop", async () => {
      await MCP.start({ cwd: tempDir })
      await MCP.stop()
      expect(MCP.isRunning()).toBe(false)
    })
  })

  describe("getPort", () => {
    test("returns undefined when not running", () => {
      expect(MCP.getPort()).toBeUndefined()
    })

    test("returns port when running", async () => {
      const port = await MCP.start({ cwd: tempDir })
      expect(MCP.getPort()).toBe(port)
    })
  })

  describe("getClientCount", () => {
    test("returns 0 when no clients connected", async () => {
      await MCP.start({ cwd: tempDir })
      expect(MCP.getClientCount()).toBe(0)
    })
  })

  describe("getStatus", () => {
    test("returns status summary", async () => {
      await MCP.start({ cwd: tempDir })

      const status = MCP.getStatus()
      expect(status.server.running).toBe(true)
      expect(typeof status.server.port).toBe("number")
      expect(status.server.clients).toBe(0)
      expect(Array.isArray(status.connectedServers)).toBe(true)
    })
  })
})

describe("MCP Protocol", () => {
  test("responds to initialize request", async () => {
    const port = await MCP.start({ cwd: tempDir })

    const response = await sendJsonRpc(port, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        clientInfo: { name: "test", version: "1.0.0" },
        capabilities: {},
      },
    })

    expect(response.result).toBeDefined()
    expect(response.result.protocolVersion).toBe("2024-11-05")
    expect(response.result.serverInfo.name).toBe("clawdstrike")
  })

  test("responds to tools/list request", async () => {
    const port = await MCP.start({ cwd: tempDir })

    const response = await sendJsonRpc(port, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    })

    expect(response.result).toBeDefined()
    expect(Array.isArray(response.result.tools)).toBe(true)

    const toolNames = response.result.tools.map((t: { name: string }) => t.name)
    expect(toolNames).toContain("dispatch")
    expect(toolNames).toContain("speculate")
    expect(toolNames).toContain("gate")
  })

  test("responds to ping request", async () => {
    const port = await MCP.start({ cwd: tempDir })

    const response = await sendJsonRpc(port, {
      jsonrpc: "2.0",
      id: 3,
      method: "ping",
      params: {},
    })

    expect(response.result).toEqual({ pong: true })
  })

  test("returns error for unknown method", async () => {
    const port = await MCP.start({ cwd: tempDir })

    const response = await sendJsonRpc(port, {
      jsonrpc: "2.0",
      id: 4,
      method: "unknown/method",
      params: {},
    })

    expect(response.error).toBeDefined()
    expect(response.error.code).toBe(-32601)
    expect(response.error.message).toContain("not found")
  })

  test("returns error for unknown tool", async () => {
    const port = await MCP.start({ cwd: tempDir })

    const response = await sendJsonRpc(port, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "nonexistent-tool",
        arguments: {},
      },
    })

    expect(response.error).toBeDefined()
    expect(response.error.code).toBe(-32602)
    expect(response.error.message).toContain("Unknown tool")
  })
})

/**
 * Helper to send JSON-RPC request and get response
 */
function sendJsonRpc(port: number, request: object): Promise<any> {
  return new Promise((resolve, reject) => {
    const socket = new Socket()
    let buffer = ""

    socket.connect(port, "127.0.0.1", () => {
      socket.write(JSON.stringify(request) + "\n")
    })

    socket.on("data", (data) => {
      buffer += data.toString()
      const lines = buffer.split("\n")
      buffer = lines.pop() ?? ""

      for (const line of lines) {
        if (line.trim()) {
          try {
            const response = JSON.parse(line)
            socket.destroy()
            resolve(response)
          } catch {
            // Continue waiting
          }
        }
      }
    })

    socket.on("error", (err) => {
      reject(err)
    })

    // Timeout after 5 seconds
    setTimeout(() => {
      socket.destroy()
      reject(new Error("Timeout"))
    }, 5000)
  })
}
