/**
 * MCP Server - Model Context Protocol server for ClawdStrike
 *
 * Exposes ClawdStrike tools (dispatch, speculate, gate) over MCP protocol.
 * Also supports connecting to external MCP servers (bidirectional hub).
 *
 * Discovery: Writes port to `.clawdstrike/mcp.json` for other tools to find.
 */

import { createServer, type Server, Socket } from "node:net"
import * as fs from "node:fs/promises"
import * as path from "node:path"
import { tools, type ToolContext } from "../tools"
import { Health } from "../health"

// =============================================================================
// TYPES
// =============================================================================

interface JsonRpcRequest {
  jsonrpc: "2.0"
  id: string | number
  method: string
  params?: unknown
}

interface JsonRpcResponse {
  jsonrpc: "2.0"
  id: string | number
  result?: unknown
  error?: {
    code: number
    message: string
    data?: unknown
  }
}

interface McpServerConfig {
  port?: number
  host?: string
  cwd?: string
  projectId?: string
}

interface McpDiscovery {
  port: number
  host: string
  pid: number
  startedAt: string
  tools: string[]
}

interface ConnectedClient {
  id: string
  socket: Socket
  connectedAt: number
}

// =============================================================================
// MCP SERVER
// =============================================================================

class McpServerImpl {
  private server: Server | null = null
  private clients: Map<string, ConnectedClient> = new Map()
  private config: McpServerConfig = {}
  private discoveryPath: string = ""

  /**
   * Start the MCP server
   */
  async start(config: McpServerConfig = {}): Promise<number> {
    if (this.server) {
      throw new Error("MCP server already running")
    }

    this.config = config
    const host = config.host ?? "127.0.0.1"
    const preferredPort = config.port ?? 0 // 0 = auto-assign

    return new Promise((resolve, reject) => {
      this.server = createServer((socket) => this.handleConnection(socket))

      this.server.on("error", (err) => {
        reject(err)
      })

      this.server.listen(preferredPort, host, async () => {
        const address = this.server?.address()
        if (!address || typeof address === "string") {
          reject(new Error("Failed to get server address"))
          return
        }

        const port = address.port

        // Write discovery file
        await this.writeDiscovery(port, host)

        // Update health status
        Health.setMcpStatus(true, port)

        resolve(port)
      })
    })
  }

  /**
   * Stop the MCP server
   */
  async stop(): Promise<void> {
    const server = this.server
    if (!server) {
      Health.setMcpStatus(false)
      await this.removeDiscovery().catch(() => {})
      return
    }

    this.server = null

    // Close all client connections
    for (const client of this.clients.values()) {
      client.socket.destroy()
    }
    this.clients.clear()

    const finalizeStop = async () => {
      Health.setMcpStatus(false)
      await this.removeDiscovery().catch(() => {})
    }

    if (!server.listening) {
      await finalizeStop()
      return
    }

    // Close server
    return new Promise((resolve, reject) => {
      const finish = (err?: Error | null) => {
        finalizeStop()
          .then(() => {
            const code = (err as NodeJS.ErrnoException | null | undefined)?.code
            if (err && code !== "ERR_SERVER_NOT_RUNNING") {
              reject(err)
              return
            }
            resolve()
          })
          .catch(() => {
            const code = (err as NodeJS.ErrnoException | null | undefined)?.code
            if (err && code !== "ERR_SERVER_NOT_RUNNING") {
              reject(err)
              return
            }
            resolve()
          })
      }

      try {
        server.close((err) => finish(err))
      } catch (err) {
        finish(err instanceof Error ? err : new Error(String(err)))
      }
    })
  }

  /**
   * Check if server is running
   */
  isRunning(): boolean {
    return this.server !== null
  }

  /**
   * Get server port (or undefined if not running)
   */
  getPort(): number | undefined {
    const address = this.server?.address()
    if (address && typeof address !== "string") {
      return address.port
    }
    return undefined
  }

  /**
   * Get connected client count
   */
  getClientCount(): number {
    return this.clients.size
  }

  /**
   * Handle new client connection
   */
  private handleConnection(socket: Socket): void {
    const clientId = `${socket.remoteAddress}:${socket.remotePort}-${Date.now()}`
    const client: ConnectedClient = {
      id: clientId,
      socket,
      connectedAt: Date.now(),
    }

    this.clients.set(clientId, client)

    let buffer = ""

    socket.on("data", async (data) => {
      buffer += data.toString()

      // Process complete JSON-RPC messages (newline-delimited)
      const lines = buffer.split("\n")
      buffer = lines.pop() ?? "" // Keep incomplete line in buffer

      for (const line of lines) {
        if (line.trim()) {
          try {
            const request = JSON.parse(line) as JsonRpcRequest
            const response = await this.handleRequest(request)
            socket.write(JSON.stringify(response) + "\n")
          } catch (err) {
            const errorResponse: JsonRpcResponse = {
              jsonrpc: "2.0",
              id: 0,
              error: {
                code: -32700,
                message: "Parse error",
                data: err instanceof Error ? err.message : String(err),
              },
            }
            socket.write(JSON.stringify(errorResponse) + "\n")
          }
        }
      }
    })

    socket.on("close", () => {
      this.clients.delete(clientId)
    })

    socket.on("error", () => {
      this.clients.delete(clientId)
    })
  }

  /**
   * Handle JSON-RPC request
   */
  private async handleRequest(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    const { id, method, params } = request

    try {
      switch (method) {
        case "initialize":
          return {
            jsonrpc: "2.0",
            id,
            result: {
              protocolVersion: "2024-11-05",
              serverInfo: {
                name: "clawdstrike",
                version: "0.1.0",
              },
              capabilities: {
                tools: {},
              },
            },
          }

        case "tools/list":
          return {
            jsonrpc: "2.0",
            id,
            result: {
              tools: tools.map((t) => ({
                name: t.name,
                description: t.description,
                inputSchema: t.parameters,
              })),
            },
          }

        case "tools/call": {
          const callParams = params as { name: string; arguments?: unknown }
          const tool = tools.find((t) => t.name === callParams.name)

          if (!tool) {
            return {
              jsonrpc: "2.0",
              id,
              error: {
                code: -32602,
                message: `Unknown tool: ${callParams.name}`,
              },
            }
          }

          const context: ToolContext = {
            cwd: this.config.cwd ?? process.cwd(),
            projectId: this.config.projectId ?? "default",
          }

          const result = await tool.handler(callParams.arguments ?? {}, context)

          return {
            jsonrpc: "2.0",
            id,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            },
          }
        }

        case "ping":
          return {
            jsonrpc: "2.0",
            id,
            result: { pong: true },
          }

        default:
          return {
            jsonrpc: "2.0",
            id,
            error: {
              code: -32601,
              message: `Method not found: ${method}`,
            },
          }
      }
    } catch (err) {
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32603,
          message: err instanceof Error ? err.message : String(err),
        },
      }
    }
  }

  /**
   * Write discovery file
   */
  private async writeDiscovery(port: number, host: string): Promise<void> {
    const cwd = this.config.cwd ?? process.cwd()
    const dir = path.join(cwd, ".clawdstrike")
    this.discoveryPath = path.join(dir, "mcp.json")

    await fs.mkdir(dir, { recursive: true })

    const discovery: McpDiscovery = {
      port,
      host,
      pid: process.pid,
      startedAt: new Date().toISOString(),
      tools: tools.map((t) => t.name),
    }

    await fs.writeFile(this.discoveryPath, JSON.stringify(discovery, null, 2))
  }

  /**
   * Remove discovery file
   */
  private async removeDiscovery(): Promise<void> {
    if (this.discoveryPath) {
      try {
        await fs.unlink(this.discoveryPath)
      } catch {
        // Ignore errors
      }
    }
  }
}

// =============================================================================
// MCP CLIENT (for connecting to external servers)
// =============================================================================

interface ExternalMcpServer {
  id: string
  host: string
  port: number
  socket?: Socket
  connected: boolean
  tools: string[]
}

class McpClientManager {
  private servers: Map<string, ExternalMcpServer> = new Map()

  /**
   * Connect to an external MCP server
   */
  async connect(id: string, host: string, port: number): Promise<string[]> {
    if (this.servers.has(id)) {
      throw new Error(`Already connected to server: ${id}`)
    }

    return new Promise((resolve, reject) => {
      const socket = new Socket()

      socket.connect(port, host, async () => {
        const server: ExternalMcpServer = {
          id,
          host,
          port,
          socket,
          connected: true,
          tools: [],
        }

        this.servers.set(id, server)

        try {
          // Initialize and get tools list
          await this.sendRequest(socket, "initialize", {
            protocolVersion: "2024-11-05",
            clientInfo: { name: "clawdstrike", version: "0.1.0" },
            capabilities: {},
          })

          const toolsResult = (await this.sendRequest(socket, "tools/list", {})) as {
            tools: Array<{ name: string }>
          }
          server.tools = toolsResult.tools.map((t) => t.name)

          resolve(server.tools)
        } catch (err) {
          socket.destroy()
          this.servers.delete(id)
          reject(err)
        }
      })

      socket.on("error", (err) => {
        this.servers.delete(id)
        reject(err)
      })
    })
  }

  /**
   * Disconnect from an external MCP server
   */
  disconnect(id: string): void {
    const server = this.servers.get(id)
    if (server?.socket) {
      server.socket.destroy()
    }
    this.servers.delete(id)
  }

  /**
   * Call a tool on an external server
   */
  async callTool(serverId: string, toolName: string, args: unknown): Promise<unknown> {
    const server = this.servers.get(serverId)
    if (!server?.socket || !server.connected) {
      throw new Error(`Not connected to server: ${serverId}`)
    }

    const result = await this.sendRequest(server.socket, "tools/call", {
      name: toolName,
      arguments: args,
    })

    return result
  }

  /**
   * Get list of connected servers
   */
  getConnectedServers(): Array<{ id: string; host: string; port: number; tools: string[] }> {
    return Array.from(this.servers.values()).map((s) => ({
      id: s.id,
      host: s.host,
      port: s.port,
      tools: s.tools,
    }))
  }

  /**
   * Send JSON-RPC request and wait for response
   */
  private sendRequest(socket: Socket, method: string, params: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = Date.now()
      const request: JsonRpcRequest = {
        jsonrpc: "2.0",
        id,
        method,
        params,
      }

      let buffer = ""

      const onData = (data: Buffer) => {
        buffer += data.toString()
        const lines = buffer.split("\n")
        buffer = lines.pop() ?? ""

        for (const line of lines) {
          if (line.trim()) {
            try {
              const response = JSON.parse(line) as JsonRpcResponse
              if (response.id === id) {
                socket.off("data", onData)
                if (response.error) {
                  reject(new Error(response.error.message))
                } else {
                  resolve(response.result)
                }
              }
            } catch {
              // Ignore parse errors for non-matching responses
            }
          }
        }
      }

      socket.on("data", onData)
      socket.write(JSON.stringify(request) + "\n")

      // Timeout after 10 seconds
      setTimeout(() => {
        socket.off("data", onData)
        reject(new Error("Request timeout"))
      }, 10000)
    })
  }
}

// =============================================================================
// SINGLETON INSTANCES
// =============================================================================

const serverInstance = new McpServerImpl()
const clientManager = new McpClientManager()

// =============================================================================
// MCP NAMESPACE
// =============================================================================

/**
 * MCP namespace - Model Context Protocol server and client
 */
export namespace MCP {
  // Server functions
  export const start = serverInstance.start.bind(serverInstance)
  export const stop = serverInstance.stop.bind(serverInstance)
  export const isRunning = serverInstance.isRunning.bind(serverInstance)
  export const getPort = serverInstance.getPort.bind(serverInstance)
  export const getClientCount = serverInstance.getClientCount.bind(serverInstance)

  // Client functions (for connecting to external MCP servers)
  export const connect = clientManager.connect.bind(clientManager)
  export const disconnect = clientManager.disconnect.bind(clientManager)
  export const callTool = clientManager.callTool.bind(clientManager)
  export const getConnectedServers = clientManager.getConnectedServers.bind(clientManager)

  /**
   * Get server status summary
   */
  export function getStatus(): {
    server: { running: boolean; port?: number; clients: number }
    connectedServers: Array<{ id: string; tools: string[] }>
  } {
    return {
      server: {
        running: serverInstance.isRunning(),
        port: serverInstance.getPort(),
        clients: serverInstance.getClientCount(),
      },
      connectedServers: clientManager.getConnectedServers().map((s) => ({
        id: s.id,
        tools: s.tools,
      })),
    }
  }
}

export default MCP
