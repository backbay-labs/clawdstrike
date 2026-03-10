#!/usr/bin/env bun
/**
 * fleet-fixture.ts -- Seeds a realistic fleet of agents for e2e testing.
 *
 * Usage:
 *   bun run scripts/fleet-fixture.ts               # full seed + heartbeat loop
 *   bun run scripts/fleet-fixture.ts --seed-only    # seed and exit
 *   bun run scripts/fleet-fixture.ts --heartbeat-only  # heartbeat loop only
 *   bun run scripts/fleet-fixture.ts --cleanup      # delete test agents
 *   bun run scripts/fleet-fixture.ts --print-auth-json # emit derived live auth/env JSON
 */

import { createHmac, generateKeyPairSync } from "crypto";

const HUSHD_URL = process.env.HUSHD_URL ?? "http://localhost:9876";
const CONTROL_API_URL = process.env.CONTROL_API_URL ?? "http://localhost:8080";
const HUSHD_API_KEY =
  process.env.HUSHD_API_KEY ?? "3cg5Q2lAY-Xnf9N_-D3L90d-QYbIsBhd8g9b8Iur3Pw";
const JWT_SECRET =
  process.env.JWT_SECRET ??
  "Y0mxbIqhVY8AW73p02sIyRLITcSWUTg4lE-6XdtpEe9AlJC0XfhD0CJDm2-9Iaz5";
const TENANT_ID =
  process.env.TENANT_ID ?? "874d572c-709c-49b7-8ecf-64b569e16710";

const HEARTBEAT_INTERVAL_MS = 15_000;
const PREFIX = "[fleet-fixture]";

function log(msg: string) {
  console.log(`${PREFIX} ${msg}`);
}

function b64url(data: string): string {
  return Buffer.from(data).toString("base64url");
}

function signJwt(payload: object, secret: string): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const sig = createHmac("sha256", secret)
    .update(`${header}.${body}`)
    .digest("base64url");
  return `${header}.${body}.${sig}`;
}

function makeJwt(): string {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
      sub: "00000000-0000-0000-0000-000000000001",
      tenant_id: TENANT_ID,
      role: "owner",
      iat: now,
      exp: now + 86400,
    },
    JWT_SECRET,
  );
}

function genEd25519PublicKeyHex(): string {
  const { publicKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" });
  return Buffer.from(raw).subarray(-32).toString("hex");
}

async function controlPost(
  path: string,
  jwt: string,
  body: unknown,
): Promise<Response> {
  return fetch(`${CONTROL_API_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify(body),
  });
}

async function hushdPost(path: string, body: unknown): Promise<Response> {
  return fetch(`${HUSHD_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${HUSHD_API_KEY}`,
    },
    body: JSON.stringify(body),
  });
}

async function controlDelete(
  path: string,
  jwt: string,
): Promise<Response> {
  return fetch(`${CONTROL_API_URL}${path}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${jwt}` },
  });
}

async function controlGet(path: string, jwt: string): Promise<Response> {
  return fetch(`${CONTROL_API_URL}${path}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${jwt}` },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

interface AgentDef {
  agent_id: string;
  name: string;
  role: string;
  trust_level: string;
  metadata: Record<string, string>;
}

const AGENTS: AgentDef[] = [
  {
    agent_id: "agent-orchestrator-001",
    name: "System Orchestrator",
    role: "coder",
    trust_level: "high",
    metadata: { environment: "production", service: "orchestrator", team: "platform" },
  },
  {
    agent_id: "agent-planner-002",
    name: "Task Planner",
    role: "coder",
    trust_level: "high",
    metadata: { environment: "production", service: "planner", team: "ai-core" },
  },
  {
    agent_id: "agent-coder-003",
    name: "Code Generator",
    role: "coder",
    trust_level: "medium",
    metadata: { environment: "staging", service: "codegen", team: "ai-core" },
  },
  {
    agent_id: "agent-tester-004",
    name: "Test Runner",
    role: "coder",
    trust_level: "medium",
    metadata: { environment: "ci", service: "test-runner", team: "quality" },
  },
  {
    agent_id: "agent-researcher-005",
    name: "Research Agent",
    role: "coder",
    trust_level: "low",
    metadata: { environment: "sandbox", service: "research", team: "ai-core" },
  },
  {
    agent_id: "agent-deployer-006",
    name: "Deploy Agent",
    role: "coder",
    trust_level: "high",
    metadata: { environment: "production", service: "deployer", team: "platform" },
  },
  {
    agent_id: "agent-monitor-007",
    name: "Security Monitor",
    role: "coder",
    trust_level: "high",
    metadata: { environment: "production", service: "monitor", team: "security" },
  },
  {
    agent_id: "agent-reviewer-008",
    name: "Code Reviewer",
    role: "coder",
    trust_level: "medium",
    metadata: { environment: "staging", service: "reviewer", team: "quality" },
  },
];

interface HeartbeatDef {
  endpoint_agent_id: string;
  posture: string;
  daemon_version: string;
  policy_version: string;
}

const HEARTBEATS: HeartbeatDef[] = [
  { endpoint_agent_id: "agent-orchestrator-001", posture: "strict", daemon_version: "0.2.5", policy_version: "sha256:fleet-test" },
  { endpoint_agent_id: "agent-planner-002", posture: "strict", daemon_version: "0.2.5", policy_version: "sha256:fleet-test" },
  { endpoint_agent_id: "agent-coder-003", posture: "default", daemon_version: "0.2.4", policy_version: "sha256:fleet-test" },
  { endpoint_agent_id: "agent-tester-004", posture: "strict", daemon_version: "0.2.5", policy_version: "sha256:fleet-test" },
  { endpoint_agent_id: "agent-researcher-005", posture: "permissive", daemon_version: "0.2.3", policy_version: "sha256:old-version" },
  { endpoint_agent_id: "agent-deployer-006", posture: "strict", daemon_version: "0.2.5", policy_version: "sha256:fleet-test" },
  { endpoint_agent_id: "agent-monitor-007", posture: "strict", daemon_version: "0.2.5", policy_version: "sha256:fleet-test" },
  { endpoint_agent_id: "agent-reviewer-008", posture: "default", daemon_version: "0.2.5", policy_version: "sha256:fleet-test" },
];

interface RuntimeHeartbeatDef {
  endpoint_agent_id: string;
  runtime_agent_id: string;
  runtime_agent_kind: string;
}

const RUNTIME_HEARTBEATS: RuntimeHeartbeatDef[] = [
  { endpoint_agent_id: "agent-coder-003", runtime_agent_id: "rt-claude-code-staging", runtime_agent_kind: "claude-code" },
  { endpoint_agent_id: "agent-coder-003", runtime_agent_id: "rt-mcp-fs-staging", runtime_agent_kind: "mcp-server" },
  { endpoint_agent_id: "agent-tester-004", runtime_agent_id: "rt-vitest-runner", runtime_agent_kind: "test-runner" },
  { endpoint_agent_id: "agent-researcher-005", runtime_agent_id: "rt-web-crawler", runtime_agent_kind: "crawler" },
  { endpoint_agent_id: "agent-reviewer-008", runtime_agent_id: "rt-claude-code-review", runtime_agent_kind: "claude-code" },
];

const FLEET_POLICY_YAML = `schema_version: "1.2.0"
name: fleet-e2e-test-policy
version: "2.0.0"
description: "E2E test fleet policy -- deployed by fixture script"
extends: strict
guards:
  forbidden_paths:
    enabled: true
    paths:
      - "/etc/shadow"
      - "/etc/passwd"
      - "~/.ssh/id_*"
      - "~/.aws/credentials"
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "api.anthropic.com"
      - "api.openai.com"
      - "github.com"
      - "*.amazonaws.com"
  shell_command:
    enabled: true
    blocked_commands:
      - "rm -rf /"
      - "curl | bash"
      - "wget | sh"
  secret_leak:
    enabled: true
  mcp_tool:
    enabled: true
    allowed_tools:
      - "read_file"
      - "write_file"
      - "execute_code"
`;

interface AuditCheck {
  action_type: string;
  target: string;
  agent_id: string;
  session_id: string;
  description: string;
  expect: "deny" | "allow" | "warn";
}

const AUDIT_CHECKS: AuditCheck[] = [
  { action_type: "file_read", target: "/etc/shadow", agent_id: "agent-researcher-005", session_id: "sess-test-001", description: "read /etc/shadow (forbidden)", expect: "deny" },
  { action_type: "file_read", target: "/etc/passwd", agent_id: "agent-coder-003", session_id: "sess-test-002", description: "read /etc/passwd (forbidden)", expect: "deny" },
  { action_type: "file_read", target: "/home/user/project/src/main.rs", agent_id: "agent-coder-003", session_id: "sess-test-003", description: "read project source (allowed)", expect: "allow" },
  { action_type: "file_write", target: "/home/user/project/src/lib.rs", agent_id: "agent-coder-003", session_id: "sess-test-004", description: "write project source (allowed)", expect: "allow" },
  { action_type: "file_read", target: "/home/user/.ssh/id_rsa", agent_id: "agent-researcher-005", session_id: "sess-test-005", description: "read SSH key (forbidden)", expect: "deny" },
  { action_type: "file_read", target: "/home/user/.aws/credentials", agent_id: "agent-deployer-006", session_id: "sess-test-006", description: "read AWS creds (forbidden)", expect: "deny" },
  { action_type: "network", target: "https://api.anthropic.com/v1/messages", agent_id: "agent-planner-002", session_id: "sess-test-007", description: "egress to Anthropic API (allowed)", expect: "allow" },
  { action_type: "network", target: "https://evil-c2.example.com/exfil", agent_id: "agent-researcher-005", session_id: "sess-test-008", description: "egress to unknown domain (denied)", expect: "deny" },
  { action_type: "shell", target: "rm -rf /", agent_id: "agent-coder-003", session_id: "sess-test-009", description: "destructive shell command (blocked)", expect: "deny" },
  { action_type: "mcp_tool", target: "execute_code", agent_id: "agent-tester-004", session_id: "sess-test-010", description: "MCP execute_code (allowed)", expect: "allow" },
];

type HierarchyNodeType = "org" | "team" | "agent";

interface FixtureHierarchyNode {
  stable_key: string;
  name: string;
  node_type: HierarchyNodeType;
  parent_key?: string;
}

interface RemoteHierarchyNode {
  id: string;
  name: string;
  node_type: string;
  parent_id?: string | null;
  metadata?: Record<string, unknown>;
}

const HIERARCHY_FIXTURE_TAG = "fleet-fixture";

const FIXTURE_HIERARCHY: FixtureHierarchyNode[] = [
  { stable_key: "fixture-root", name: "Fleet Fixture Org", node_type: "org" },
  {
    stable_key: "fixture-eng",
    name: "Fixture Engineering",
    node_type: "team",
    parent_key: "fixture-root",
  },
  {
    stable_key: "fixture-sec",
    name: "Fixture Security",
    node_type: "team",
    parent_key: "fixture-root",
  },
  {
    stable_key: "fixture-agent-coder",
    name: "agent-coder-003",
    node_type: "agent",
    parent_key: "fixture-eng",
  },
  {
    stable_key: "fixture-agent-tester",
    name: "agent-tester-004",
    node_type: "agent",
    parent_key: "fixture-eng",
  },
  {
    stable_key: "fixture-agent-monitor",
    name: "agent-monitor-007",
    node_type: "agent",
    parent_key: "fixture-sec",
  },
];

// -- Phases --

async function registerAgents(jwt: string): Promise<void> {
  log("Registering 8 agents...");
  let registered = 0;
  let skipped = 0;
  let failed = 0;

  for (const agent of AGENTS) {
    const publicKey = genEd25519PublicKeyHex();
    try {
      const res = await controlPost("/api/v1/agents", jwt, {
        ...agent,
        public_key: publicKey,
      });
      if (res.ok) {
        registered++;
      } else if (res.status === 409) {
        skipped++;
      } else {
        const text = await res.text().catch(() => "");
        log(`  FAIL ${agent.agent_id} -- ${res.status} ${text}`);
        failed++;
      }
    } catch (err) {
      log(`  FAIL ${agent.agent_id} -- ${(err as Error).message}`);
      failed++;
    }
  }

  log(`  registered=${registered} skipped=${skipped} failed=${failed}`);
}

async function sendHeartbeats(): Promise<void> {
  let endpointOk = 0;
  let endpointFail = 0;
  let runtimeOk = 0;
  let runtimeFail = 0;

  for (const hb of HEARTBEATS) {
    try {
      const res = await hushdPost("/api/v1/agent/heartbeat", hb);
      if (res.ok) {
        endpointOk++;
      } else {
        const text = await res.text().catch(() => "");
        log(`  FAIL endpoint ${hb.endpoint_agent_id} -- ${res.status} ${text}`);
        endpointFail++;
      }
    } catch (err) {
      log(`  FAIL endpoint ${hb.endpoint_agent_id} -- ${(err as Error).message}`);
      endpointFail++;
    }
  }

  for (const rt of RUNTIME_HEARTBEATS) {
    try {
      const res = await hushdPost("/api/v1/agent/heartbeat", rt);
      if (res.ok) {
        runtimeOk++;
      } else {
        const text = await res.text().catch(() => "");
        log(`  FAIL runtime ${rt.runtime_agent_id} -- ${res.status} ${text}`);
        runtimeFail++;
      }
    } catch (err) {
      log(`  FAIL runtime ${rt.runtime_agent_id} -- ${(err as Error).message}`);
      runtimeFail++;
    }
  }

  const failures = endpointFail + runtimeFail;
  log(
    `  heartbeats: ${endpointOk} endpoints + ${runtimeOk} runtimes` +
      (failures > 0 ? ` (${failures} failures)` : ""),
  );
}

async function deployPolicy(jwt: string): Promise<void> {
  log("Deploying policy fleet-e2e-test-policy v2.0.0...");
  try {
    const res = await controlPost("/api/v1/policies/deploy", jwt, {
      policy_yaml: FLEET_POLICY_YAML,
      description: `Fleet e2e test policy for ${AGENTS.length} agents`,
    });
    if (res.ok) {
      log(`  OK -- deployed to ${AGENTS.length} agents`);
    } else {
      const text = await res.text().catch(() => "");
      log(`  FAIL -- ${res.status} ${text}`);
    }
  } catch (err) {
    log(`  FAIL -- ${(err as Error).message}`);
  }
}

async function generateAuditEvents(): Promise<void> {
  log("Generating audit events...");
  let sent = 0;
  let failed = 0;

  for (const check of AUDIT_CHECKS) {
    try {
      await hushdPost("/api/v1/check", {
        action_type: check.action_type,
        target: check.target,
        agent_id: check.agent_id,
        session_id: check.session_id,
      });
      // Both 2xx and non-2xx responses generate audit records.
      sent++;
    } catch (err) {
      log(`  FAIL check "${check.description}" -- ${(err as Error).message}`);
      failed++;
    }
  }

  log(
    `  ${sent} checks sent` + (failed > 0 ? ` (${failed} network failures)` : ""),
  );
}

function toHierarchyNodes(payload: unknown): RemoteHierarchyNode[] {
  const list = Array.isArray(payload)
    ? payload
    : isRecord(payload) && Array.isArray(payload.nodes)
      ? payload.nodes
      : [];

  return list
    .filter(isRecord)
    .map((node) => ({
      id: readString(node.id) ?? "",
      name: readString(node.name) ?? "",
      node_type: readString(node.node_type) ?? "",
      parent_id: readString(node.parent_id) ?? null,
      metadata: isRecord(node.metadata) ? node.metadata : undefined,
    }))
    .filter((node) => node.id && node.name && node.node_type);
}

async function listHierarchyNodes(jwt: string): Promise<RemoteHierarchyNode[]> {
  try {
    const res = await controlGet("/api/v1/hierarchy/nodes", jwt);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      log(`  FAIL list hierarchy -- ${res.status} ${text}`);
      return [];
    }

    const payload = await res.json();
    return toHierarchyNodes(payload);
  } catch (err) {
    log(`  FAIL list hierarchy -- ${(err as Error).message}`);
    return [];
  }
}

async function seedHierarchy(jwt: string): Promise<void> {
  log("Seeding fixture hierarchy...");

  const existing = await listHierarchyNodes(jwt);
  const stableIndex = new Map<string, string>();
  for (const node of existing) {
    const stableKey = readString(node.metadata?.stable_key);
    const fixtureTag = readString(node.metadata?.fixture);
    if (fixtureTag === HIERARCHY_FIXTURE_TAG && stableKey) {
      stableIndex.set(stableKey, node.id);
    }
  }

  let created = 0;
  let skipped = 0;
  let failed = 0;

  for (const spec of FIXTURE_HIERARCHY) {
    if (stableIndex.has(spec.stable_key)) {
      skipped++;
      continue;
    }

    const parentId = spec.parent_key ? stableIndex.get(spec.parent_key) ?? null : null;
    try {
      const res = await controlPost("/api/v1/hierarchy/nodes", jwt, {
        name: spec.name,
        node_type: spec.node_type,
        parent_id: parentId,
        metadata: {
          fixture: HIERARCHY_FIXTURE_TAG,
          stable_key: spec.stable_key,
        },
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        log(`  FAIL hierarchy ${spec.stable_key} -- ${res.status} ${text}`);
        failed++;
        continue;
      }

      const node = (await res.json()) as { id?: string };
      if (typeof node.id === "string") {
        stableIndex.set(spec.stable_key, node.id);
      }
      created++;
    } catch (err) {
      log(`  FAIL hierarchy ${spec.stable_key} -- ${(err as Error).message}`);
      failed++;
    }
  }

  log(`  hierarchy: created=${created} skipped=${skipped} failed=${failed}`);
}

async function cleanup(jwt: string): Promise<void> {
  log("Cleaning up test agents...");
  let deleted = 0;
  let failed = 0;
  let agentIndex = new Map<string, string>();

  try {
    const res = await controlGet("/api/v1/agents", jwt);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      log(`  FAIL list agents -- ${res.status} ${text}`);
      return;
    }

    const agents = (await res.json()) as Array<{ id: string; agent_id: string }>;
    agentIndex = new Map(agents.map((agent) => [agent.agent_id, agent.id]));
  } catch (err) {
    log(`  FAIL list agents -- ${(err as Error).message}`);
    return;
  }

  for (const agent of AGENTS) {
    const agentUuid = agentIndex.get(agent.agent_id);
    if (!agentUuid) {
      continue;
    }

    try {
      const res = await controlDelete(`/api/v1/agents/${agentUuid}`, jwt);
      if (res.ok) {
        deleted++;
      } else if (res.status === 404) {
        // already gone
      } else {
        const text = await res.text().catch(() => "");
        log(`  FAIL ${agent.agent_id} -- ${res.status} ${text}`);
        failed++;
      }
    } catch (err) {
      log(`  FAIL ${agent.agent_id} -- ${(err as Error).message}`);
      failed++;
    }
  }

  log(`  deleted=${deleted} failed=${failed}`);

  log("Cleaning up fixture hierarchy...");
  const hierarchyNodes = await listHierarchyNodes(jwt);
  const fixtureNodes = hierarchyNodes.filter(
    (node) => readString(node.metadata?.fixture) === HIERARCHY_FIXTURE_TAG,
  );
  const nodeIndex = new Map(fixtureNodes.map((node) => [node.id, node]));
  const depthFor = (node: RemoteHierarchyNode): number => {
    let depth = 0;
    let cursor = node.parent_id ? nodeIndex.get(node.parent_id) : undefined;
    while (cursor) {
      depth++;
      cursor = cursor.parent_id ? nodeIndex.get(cursor.parent_id) : undefined;
    }
    return depth;
  };

  fixtureNodes.sort((a, b) => depthFor(b) - depthFor(a));

  let hierarchyDeleted = 0;
  let hierarchyFailed = 0;
  for (const node of fixtureNodes) {
    try {
      const res = await controlDelete(`/api/v1/hierarchy/nodes/${node.id}?reparent=false`, jwt);
      if (res.ok) {
        hierarchyDeleted++;
      } else if (res.status !== 404) {
        const text = await res.text().catch(() => "");
        log(`  FAIL hierarchy ${node.name} -- ${res.status} ${text}`);
        hierarchyFailed++;
      }
    } catch (err) {
      log(`  FAIL hierarchy ${node.name} -- ${(err as Error).message}`);
      hierarchyFailed++;
    }
  }

  log(`  hierarchy deleted=${hierarchyDeleted} failed=${hierarchyFailed}`);
}

function printAuthJson(jwt: string): void {
  console.log(JSON.stringify({
    hushdUrl: HUSHD_URL,
    controlApiUrl: CONTROL_API_URL,
    hushdApiKey: HUSHD_API_KEY,
    controlApiToken: jwt,
    tenantId: TENANT_ID,
  }));
}

function startHeartbeatLoop(): void {
  log(
    `Entering heartbeat loop (${HEARTBEAT_INTERVAL_MS / 1000}s interval)... Ctrl+C to stop`,
  );

  const interval = setInterval(() => {
    sendHeartbeats().catch((err) => {
      log(`  heartbeat loop error -- ${(err as Error).message}`);
    });
  }, HEARTBEAT_INTERVAL_MS);

  const shutdown = () => {
    log("\nShutting down heartbeat loop...");
    clearInterval(interval);
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const mode = args[0] ?? "";

  const jwt = makeJwt();

  if (mode === "--print-auth-json") {
    printAuthJson(jwt);
    return;
  }

  log(`JWT generated for tenant ${TENANT_ID.slice(0, 8)}...`);

  if (mode === "--cleanup") {
    await cleanup(jwt);
    return;
  }

  if (mode === "--heartbeat-only") {
    await sendHeartbeats();
    startHeartbeatLoop();
    return;
  }

  if (mode === "--seed-only" || mode === "") {
    await registerAgents(jwt);
    await sendHeartbeats();
    await deployPolicy(jwt);
    await generateAuditEvents();
    await seedHierarchy(jwt);
  }

  if (mode === "--seed-only") {
    log("Seed complete.");
    return;
  }

  if (mode === "") {
    startHeartbeatLoop();
    return;
  }

  console.error(`Unknown mode: ${mode}`);
  console.error(
    "Usage: bun run scripts/fleet-fixture.ts [--seed-only | --heartbeat-only | --cleanup | --print-auth-json]",
  );
  process.exit(1);
}

main().catch((err) => {
  console.error(`${PREFIX} Fatal:`, err);
  process.exit(1);
});
