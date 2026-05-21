import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolCallEvent } from "../../types.js";
import handler, {
  buildPreflightDeveloperActivityForCommand,
  buildPreflightPolicyEventForEdr,
  initialize,
} from "./handler.js";

describe("tool-preflight handler", () => {
  beforeEach(() => {
    // Ensure tests don't accidentally exercise the interactive approval flow.
    delete process.env.CLAWDSTRIKE_APPROVAL_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN;
    delete process.env.CLAWDSTRIKE_POLICY_EVENTS_URL;
    delete process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL;
    delete process.env.CLAWDSTRIKE_AGENT_URL;
    process.env.CLAWDSTRIKE_AGENT_TOKEN_PATH = "/tmp/clawdstrike-openclaw-missing-agent-token";

    initialize({
      policy: "clawdstrike:ai-agent-minimal",
      mode: "deterministic",
      logLevel: "error",
    });
  });

  afterEach(() => {
    delete process.env.CLAWDSTRIKE_APPROVAL_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN;
    delete process.env.CLAWDSTRIKE_POLICY_EVENTS_URL;
    delete process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL;
    delete process.env.CLAWDSTRIKE_AGENT_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN_PATH;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("adds EDR collector metadata to preflight policy events", () => {
    const event = {
      eventId: "preflight-test-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test",
      data: { type: "command", command: "aws", args: ["sts", "get-session-token"] },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const edrEvent = buildPreflightPolicyEventForEdr(
      event,
      "shell",
      {
        status: "deny",
        guard: "egress_allowlist",
        severity: "high",
        reason: "not allowed",
      } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
        toolCallId: "tool-call-1",
      },
    );

    expect(edrEvent).toMatchObject({
      eventId: "preflight-test-1",
      eventType: "command_exec",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        toolName: "shell",
        preflight: true,
        policyAllowed: false,
        policyStatus: "deny",
        policyGuard: "egress_allowlist",
        policySeverity: "high",
        policyReason: "not allowed",
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
        toolCallId: "tool-call-1",
      }),
    });
  });

  it("maps package-manager preflight commands to package-script developer activity", () => {
    const event = {
      eventId: "preflight-package-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test",
      data: {
        type: "command",
        command: "npm",
        args: ["--prefix", "/repo", "run", "postinstall"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "allow", guard: "allow", severity: "info" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
        toolCallId: "tool-call-package-1",
      },
    );

    expect(activity).toMatchObject({
      kind: "package_script",
      sessionId: "sess-test",
      agentId: "agent:openclaw",
      workloadId: "openclaw-tool-preflight",
      manager: "npm",
      phase: "postinstall",
      script: "npm --prefix /repo run postinstall",
      image: "npm",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: true,
        shellClassifier: "package_script",
        toolCallId: "tool-call-package-1",
      }),
    });
  });

  it("maps additional language package-manager preflight commands to package-script developer activity", () => {
    const cases = [
      {
        command: "composer",
        args: ["require", "vendor/package"],
        manager: "composer",
        phase: "install",
        packageName: "vendor/package",
        commandLine: "composer require vendor/package",
      },
      {
        command: "./mvnw",
        args: ["-q", "package"],
        manager: "maven",
        phase: "package",
        commandLine: "./mvnw -q package",
      },
      {
        command: "./gradlew",
        args: ["--no-daemon", "build"],
        manager: "gradle",
        phase: "build",
        commandLine: "./gradlew --no-daemon build",
      },
      {
        command: "uv",
        args: ["pip", "install", "ruff"],
        manager: "uv",
        phase: "install",
        packageName: "ruff",
        commandLine: "uv pip install ruff",
      },
      {
        command: "poetry",
        args: ["add", "requests"],
        manager: "poetry",
        phase: "install",
        packageName: "requests",
        commandLine: "poetry add requests",
      },
      {
        command: "pipenv",
        args: ["install", "requests"],
        manager: "pipenv",
        phase: "install",
        packageName: "requests",
        commandLine: "pipenv install requests",
      },
      {
        command: "dotnet",
        args: ["add", "package", "Newtonsoft.Json"],
        manager: "dotnet",
        phase: "install",
        packageName: "Newtonsoft.Json",
        commandLine: "dotnet add package Newtonsoft.Json",
      },
      {
        command: "nuget",
        args: ["install", "Newtonsoft.Json"],
        manager: "nuget",
        phase: "install",
        packageName: "Newtonsoft.Json",
        commandLine: "nuget install Newtonsoft.Json",
      },
      {
        command: "swift",
        args: ["package", "resolve"],
        manager: "swift",
        phase: "install",
        commandLine: "swift package resolve",
      },
      {
        command: "mix",
        args: ["deps.get", "phoenix"],
        manager: "mix",
        phase: "install",
        packageName: "phoenix",
        commandLine: "mix deps.get phoenix",
      },
    ];

    for (const testCase of cases) {
      const event = {
        eventId: `preflight-package-${testCase.manager}`,
        eventType: "command_exec",
        timestamp: new Date().toISOString(),
        sessionId: `sess-test-${testCase.manager}`,
        data: {
          type: "command",
          command: testCase.command,
          args: testCase.args,
        },
        metadata: { toolName: "shell", preflight: true },
      } as any;

      const activity = buildPreflightDeveloperActivityForCommand(
        event,
        "shell",
        { status: "allow", guard: "allow", severity: "info" } as any,
        {
          agentId: "agent:openclaw",
          workloadId: "openclaw-tool-preflight",
        },
      );

      expect(activity).toMatchObject({
        kind: "package_script",
        sessionId: `sess-test-${testCase.manager}`,
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
        manager: testCase.manager,
        phase: testCase.phase,
        ...(testCase.packageName ? { package: testCase.packageName } : {}),
        script: testCase.commandLine,
        image: testCase.command,
        metadata: expect.objectContaining({
          collectorKind: "openclaw_tool_preflight",
          policyAllowed: true,
          shellClassifier: "package_script",
        }),
      });
    }
  });

  it("maps package-registry token preflight commands to credential activity", () => {
    const event = {
      eventId: "preflight-package-token-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-package-token",
      data: {
        type: "command",
        command: "npm",
        args: ["token", "list", "--json"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "allow", guard: "allow", severity: "info" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
        toolCallId: "tool-call-package-token-1",
      },
    );

    expect(activity).toMatchObject({
      kind: "repo_secret",
      sessionId: "sess-package-token",
      agentId: "agent:openclaw",
      workloadId: "openclaw-tool-preflight",
      path: "npm:token",
      name: "npm-token",
      credentialKind: "package_registry_token",
      commandLine: "npm token list --json",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: true,
        shellClassifier: "package_registry_token_command",
        toolCallId: "tool-call-package-token-1",
      }),
    });
  });

  it("maps sensitive cloud CLI preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-cloud-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test",
      data: {
        type: "command",
        command: "aws",
        args: ["--profile", "prod", "secretsmanager", "get-secret-value", "--secret-id", "db"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "secret read" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test",
      agentId: "agent:openclaw",
      provider: "aws",
      operation: "secretsmanager",
      args: ["get-secret-value", "--secret-id", "db"],
      commandLine: "aws --profile prod secretsmanager get-secret-value --secret-id db",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps GitHub CLI secret preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-gh-secret-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test-gh",
      data: {
        type: "command",
        command: "gh",
        args: ["secret", "set", "PROD_DB_URL", "--body", "redacted", "--repo", "acme/service"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "secret write" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test-gh",
      agentId: "agent:openclaw",
      provider: "gh",
      operation: "secret",
      args: ["set", "PROD_DB_URL", "--body", "redacted", "--repo", "acme/service"],
      commandLine: "gh secret set PROD_DB_URL --body redacted --repo acme/service",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps Vercel env preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-vercel-env-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test-vercel",
      data: {
        type: "command",
        command: "vercel",
        args: ["env", "pull", ".env.local", "--environment", "production"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "env pull" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test-vercel",
      agentId: "agent:openclaw",
      provider: "vercel",
      operation: "env",
      args: ["pull", ".env.local", "--environment", "production"],
      commandLine: "vercel env pull .env.local --environment production",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps Netlify env preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-netlify-env-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test-netlify",
      data: {
        type: "command",
        command: "netlify",
        args: ["env:get", "API_KEY", "--context", "production"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "env get" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test-netlify",
      agentId: "agent:openclaw",
      provider: "netlify",
      operation: "env:get",
      args: ["API_KEY", "--context", "production"],
      commandLine: "netlify env:get API_KEY --context production",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps Wrangler secret preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-wrangler-secret-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test-wrangler",
      data: {
        type: "command",
        command: "wrangler",
        args: ["secret", "put", "API_TOKEN", "--env", "production"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "secret put" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test-wrangler",
      agentId: "agent:openclaw",
      provider: "wrangler",
      operation: "secret",
      args: ["put", "API_TOKEN", "--env", "production"],
      commandLine: "wrangler secret put API_TOKEN --env production",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps DigitalOcean registry credential preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-doctl-registry-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test-doctl",
      data: {
        type: "command",
        command: "doctl",
        args: ["registry", "docker-config", "example-registry", "--read-write"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "registry token" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test-doctl",
      agentId: "agent:openclaw",
      provider: "doctl",
      operation: "registry",
      args: ["docker-config", "example-registry", "--read-write"],
      commandLine: "doctl registry docker-config example-registry --read-write",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps Fly secret preflight commands to cloud-cli developer activity", () => {
    const event = {
      eventId: "preflight-fly-secret-1",
      eventType: "command_exec",
      timestamp: new Date().toISOString(),
      sessionId: "sess-test-fly",
      data: {
        type: "command",
        command: "fly",
        args: ["secrets", "set", "DATABASE_URL=postgres://example", "--app", "api"],
      },
      metadata: { toolName: "shell", preflight: true },
    } as any;

    const activity = buildPreflightDeveloperActivityForCommand(
      event,
      "shell",
      { status: "deny", guard: "cloud_guard", severity: "high", reason: "secret set" } as any,
      {
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
      },
    );

    expect(activity).toMatchObject({
      kind: "cloud_cli",
      sessionId: "sess-test-fly",
      agentId: "agent:openclaw",
      provider: "fly",
      operation: "secrets",
      args: ["set", "DATABASE_URL=postgres://example", "--app", "api"],
      commandLine: "fly secrets set DATABASE_URL=postgres://example --app api",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        policyAllowed: false,
        policyGuard: "cloud_guard",
        shellClassifier: "cloud_cli",
      }),
    });
  });

  it("maps secret-management and platform preflight commands to cloud-cli developer activity", () => {
    const cases = [
      {
        command: "op",
        args: ["item", "get", "prod/api-token"],
        provider: "op",
        operation: "item",
        operationArgs: ["get", "prod/api-token"],
        commandLine: "op item get prod/api-token",
      },
      {
        command: "vault",
        args: ["kv", "get", "secret/prod/api"],
        provider: "vault",
        operation: "kv",
        operationArgs: ["get", "secret/prod/api"],
        commandLine: "vault kv get secret/prod/api",
      },
      {
        command: "doppler",
        args: ["secrets", "download", "--no-file"],
        provider: "doppler",
        operation: "secrets",
        operationArgs: ["download", "--no-file"],
        commandLine: "doppler secrets download --no-file",
      },
      {
        command: "heroku",
        args: ["config:get", "DATABASE_URL", "--app", "prod-api"],
        provider: "heroku",
        operation: "config:get",
        operationArgs: ["DATABASE_URL", "--app", "prod-api"],
        commandLine: "heroku config:get DATABASE_URL --app prod-api",
      },
      {
        command: "supabase",
        args: ["secrets", "list", "--project-ref", "prodref"],
        provider: "supabase",
        operation: "secrets",
        operationArgs: ["list", "--project-ref", "prodref"],
        commandLine: "supabase secrets list --project-ref prodref",
      },
      {
        command: "firebase",
        args: ["functions:secrets:access", "STRIPE_WEBHOOK_SECRET", "--project", "prod-api"],
        provider: "firebase",
        operation: "functions:secrets:access",
        operationArgs: ["STRIPE_WEBHOOK_SECRET", "--project", "prod-api"],
        commandLine: "firebase functions:secrets:access STRIPE_WEBHOOK_SECRET --project prod-api",
      },
      {
        command: "railway",
        args: ["variables", "--service", "api"],
        provider: "railway",
        operation: "variables",
        operationArgs: ["--service", "api"],
        commandLine: "railway variables --service api",
      },
      {
        command: "sentry-cli",
        args: ["login", "--auth-token=sk-SENTRYTOKEN_1234567890abcdef"],
        provider: "sentry",
        operation: "login",
        operationArgs: ["--auth-token=[REDACTED]"],
        commandLine: "sentry-cli login --auth-token=[REDACTED]",
      },
      {
        command: "snyk",
        args: ["auth", "--auth-token=sk-SNYKTOKEN_1234567890abcdef"],
        provider: "snyk",
        operation: "auth",
        operationArgs: ["--auth-token=[REDACTED]"],
        commandLine: "snyk auth --auth-token=[REDACTED]",
      },
      {
        command: "bw",
        args: ["get", "item", "production-database"],
        provider: "bitwarden",
        operation: "get",
        operationArgs: ["item", "production-database"],
        commandLine: "bw get item production-database",
      },
      {
        command: "aws",
        args: ["eks", "update-kubeconfig", "--name", "prod", "--region", "us-east-1"],
        provider: "aws",
        operation: "eks",
        operationArgs: ["update-kubeconfig", "--name", "prod", "--region", "us-east-1"],
        commandLine: "aws eks update-kubeconfig --name prod --region us-east-1",
      },
      {
        command: "aws",
        args: [
          "codeartifact",
          "login",
          "--tool",
          "npm",
          "--domain",
          "prod",
          "--repository",
          "private",
        ],
        provider: "aws",
        operation: "codeartifact",
        operationArgs: ["login", "--tool", "npm", "--domain", "prod", "--repository", "private"],
        commandLine: "aws codeartifact login --tool npm --domain prod --repository private",
      },
      {
        command: "gcloud",
        args: ["auth", "configure-docker", "us-docker.pkg.dev", "--quiet"],
        provider: "gcloud",
        operation: "auth",
        operationArgs: ["configure-docker", "us-docker.pkg.dev", "--quiet"],
        commandLine: "gcloud auth configure-docker us-docker.pkg.dev --quiet",
      },
      {
        command: "gcloud",
        args: ["container", "clusters", "get-credentials", "prod", "--region", "us-central1"],
        provider: "gcloud",
        operation: "container",
        operationArgs: ["clusters", "get-credentials", "prod", "--region", "us-central1"],
        commandLine: "gcloud container clusters get-credentials prod --region us-central1",
      },
      {
        command: "az",
        args: ["acr", "login", "--name", "prodregistry"],
        provider: "az",
        operation: "acr",
        operationArgs: ["login", "--name", "prodregistry"],
        commandLine: "az acr login --name prodregistry",
      },
      {
        command: "az",
        args: ["login", "--tenant", "tenant-123"],
        provider: "az",
        operation: "login",
        operationArgs: ["--tenant", "tenant-123"],
        commandLine: "az login --tenant tenant-123",
      },
      {
        command: "az",
        args: ["aks", "get-credentials", "--resource-group", "rg-prod", "--name", "prod"],
        provider: "az",
        operation: "aks",
        operationArgs: ["get-credentials", "--resource-group", "rg-prod", "--name", "prod"],
        commandLine: "az aks get-credentials --resource-group rg-prod --name prod",
      },
      {
        command: "kubectl",
        args: ["get", "secret", "prod-token", "-o", "yaml"],
        provider: "kubectl",
        operation: "get",
        operationArgs: ["secret", "prod-token", "-o", "yaml"],
        commandLine: "kubectl get secret prod-token -o yaml",
      },
      {
        command: "pulumi",
        args: ["config", "get", "dbPassword", "--show-secrets"],
        provider: "pulumi",
        operation: "config",
        operationArgs: ["get", "dbPassword", "--show-secrets"],
        commandLine: "pulumi config get dbPassword --show-secrets",
      },
      {
        command: "circleci",
        args: ["context", "store-secret", "github", "acme", "production", "DATABASE_URL"],
        provider: "circleci",
        operation: "context",
        operationArgs: ["store-secret", "github", "acme", "production", "DATABASE_URL"],
        commandLine: "circleci context store-secret github acme production DATABASE_URL",
      },
      {
        command: "glab",
        args: ["variable", "set", "DATABASE_URL", "postgres://redacted", "--masked"],
        provider: "glab",
        operation: "variable",
        operationArgs: ["set", "DATABASE_URL", "postgres://redacted", "--masked"],
        commandLine: "glab variable set DATABASE_URL postgres://redacted --masked",
      },
      {
        command: "buildkite-agent",
        args: ["secret", "get", "deploy_key"],
        provider: "buildkite",
        operation: "secret",
        operationArgs: ["get", "deploy_key"],
        commandLine: "buildkite-agent secret get deploy_key",
      },
      {
        command: "terraform",
        args: ["output", "-json"],
        provider: "terraform",
        operation: "output",
        operationArgs: ["-json"],
        commandLine: "terraform output -json",
      },
      {
        command: "terragrunt",
        args: ["state", "pull"],
        provider: "terragrunt",
        operation: "state",
        operationArgs: ["pull"],
        commandLine: "terragrunt state pull",
      },
      {
        command: "tofu",
        args: ["login", "app.terraform.io"],
        provider: "opentofu",
        operation: "login",
        operationArgs: ["app.terraform.io"],
        commandLine: "tofu login app.terraform.io",
      },
    ];

    for (const testCase of cases) {
      const event = {
        eventId: `preflight-${testCase.provider}-secret-1`,
        eventType: "command_exec",
        timestamp: new Date().toISOString(),
        sessionId: `sess-test-${testCase.provider}`,
        data: {
          type: "command",
          command: testCase.command,
          args: testCase.args,
        },
        metadata: { toolName: "shell", preflight: true },
      } as any;

      const activity = buildPreflightDeveloperActivityForCommand(
        event,
        "shell",
        { status: "deny", guard: "cloud_guard", severity: "high", reason: "secret access" } as any,
        {
          agentId: "agent:openclaw",
          workloadId: "openclaw-tool-preflight",
        },
      );

      expect(activity).toMatchObject({
        kind: "cloud_cli",
        sessionId: `sess-test-${testCase.provider}`,
        agentId: "agent:openclaw",
        provider: testCase.provider,
        operation: testCase.operation,
        args: testCase.operationArgs,
        commandLine: testCase.commandLine,
        metadata: expect.objectContaining({
          collectorKind: "openclaw_tool_preflight",
          policyAllowed: false,
          policyGuard: "cloud_guard",
          shellClassifier: "cloud_cli",
        }),
      });
      expect(JSON.stringify(activity)).not.toContain("SENTRYTOKEN");
      expect(JSON.stringify(activity)).not.toContain("SNYKTOKEN");
    }
  });

  it("preflights network tools even when the name looks read-only", async () => {
    const event: ToolCallEvent = {
      type: "tool_call",
      timestamp: new Date().toISOString(),
      context: {
        sessionId: "sess-test",
        toolCall: {
          toolName: "web_search",
          params: { url: "https://example.com" },
        },
      },
      preventDefault: false,
      messages: [],
    };

    await handler(event);

    expect(event.preventDefault).toBe(true);
    expect(event.messages.join("\n")).toMatch(/blocked web_search/i);
  });

  it("posts preflight PolicyEvents to local EDR when a local agent token is configured", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    const event: ToolCallEvent = {
      type: "tool_call",
      timestamp: new Date().toISOString(),
      context: {
        sessionId: "sess-test",
        toolCall: {
          toolName: "shell",
          params: { command: "python script.py" },
        },
      },
      preventDefault: false,
      messages: [],
    };

    await handler(event);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:9878/api/v1/agent/edr/policy-events");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer test-token");
    const body = JSON.parse(String(init.body));
    expect(body.events).toHaveLength(1);
    expect(body.events[0]).toMatchObject({
      eventType: "command_exec",
      sessionId: "sess-test",
      data: {
        type: "command",
        command: "python",
        args: ["script.py"],
      },
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        toolName: "shell",
        preflight: true,
      }),
    });
  });

  it("scrubs raw preflight policy payloads before posting local EDR telemetry", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await handler(
      {
        toolName: "write_file",
        params: {
          path: "/tmp/secret.txt",
          content: "api key sk-abcdefghijklmnopqrstuvwxyz",
        },
      },
      { sessionKey: "sess-privacy-file", toolCallId: "tool-call-privacy-file" },
    );
    await handler(
      {
        toolName: "apply_patch",
        params: {
          path: "/tmp/secret.txt",
          patch: "+ token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        },
      },
      { sessionKey: "sess-privacy-patch", toolCallId: "tool-call-privacy-patch" },
    );
    await handler(
      {
        toolName: "custom_tool",
        params: {
          secretToken: "raw-token-value",
          prompt: "use sk-zyxwvutsrqponmlkjihgfedcba",
        },
      },
      { sessionKey: "sess-privacy-tool", toolCallId: "tool-call-privacy-tool" },
    );
    await handler(
      {
        toolName: "http_get",
        params: {
          url: "https://example.invalid/run?token=raw-token-value&query=ok",
        },
      },
      { sessionKey: "sess-privacy-network", toolCallId: "tool-call-privacy-network" },
    );

    expect(fetchMock).toHaveBeenCalledTimes(4);
    const postedBodies = fetchMock.mock.calls.map(([, init]) =>
      JSON.parse(String((init as RequestInit).body)),
    );
    const serialized = JSON.stringify(postedBodies);
    expect(serialized).not.toContain("api key sk-abcdefghijklmnopqrstuvwxyz");
    expect(serialized).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    expect(serialized).not.toContain("raw-token-value");
    expect(serialized).not.toContain("sk-zyxwvutsrqponmlkjihgfedcba");

    const [fileEvent, patchEvent, toolEvent, networkEvent] = postedBodies.map(
      (body) => body.events[0],
    );
    expect(fileEvent.data.content).toBeUndefined();
    expect(fileEvent.data.contentHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(fileEvent.metadata).toMatchObject({
      telemetryScrubbed: true,
      telemetryRedaction: "hashes_and_summaries",
    });
    expect(fileEvent.metadata.telemetryScrubbedFields).toContain("data.content");

    expect(patchEvent.data.patchContent).toBeUndefined();
    expect(patchEvent.data.patchHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(patchEvent.metadata.telemetryScrubbedFields).toContain("data.patchContent");

    expect(toolEvent.data.parameters.secretToken).toBe("[REDACTED]");
    expect(toolEvent.data.parameters.prompt).toBe("[REDACTED]");
    expect(toolEvent.metadata.telemetryScrubbedFields).toEqual(
      expect.arrayContaining([
        "data.parameters.secretToken",
        "data.parameters.prompt",
      ]),
    );

    expect(networkEvent.data.url).toBe(
      "https://example.invalid/run?token=%5BREDACTED%5D&query=ok",
    );
    expect(networkEvent.metadata.telemetryScrubbedFields).toContain("data.url");
  });

  it("binds modern hook identity into posted preflight PolicyEvents", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await handler(
      {
        toolName: "shell",
        params: { command: "python script.py" },
      },
      {
        agentId: "agent:openclaw",
        sessionKey: "sess-modern",
        toolCallId: "tool-call-modern-1",
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(String(init.body));
    expect(body.events[0]).toMatchObject({
      sessionId: "sess-modern",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        agentId: "agent:openclaw",
        workloadId: "openclaw-tool-preflight",
        toolCallId: "tool-call-modern-1",
      }),
    });
  });

  it("binds modern endpoint identity into posted preflight EDR payloads", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/developer-activity";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await handler(
      {
        toolName: "shell",
        params: { command: "npm run postinstall" },
      },
      {
        agentId: "agent:openclaw",
        sessionKey: "sess-identity",
        toolCallId: "tool-call-identity-1",
        hostId: "endpoint:devbook",
        userId: "principal:alice",
        workloadId: "workload:openclaw-agent",
        approvalId: "approval:change-123",
      } as any,
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const policyEventsCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/policy-events"),
    );
    expect(policyEventsCall).toBeDefined();
    const [, policyInit] = policyEventsCall as [string, RequestInit];
    const policyBody = JSON.parse(String(policyInit.body));
    expect(policyBody.events[0]).toMatchObject({
      sessionId: "sess-identity",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        agentId: "agent:openclaw",
        hostId: "endpoint:devbook",
        userId: "principal:alice",
        sessionId: "sess-identity",
        workloadId: "workload:openclaw-agent",
        approvalId: "approval:change-123",
        toolCallId: "tool-call-identity-1",
      }),
    });

    const developerActivityCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/developer-activity"),
    );
    expect(developerActivityCall).toBeDefined();
    const [, activityInit] = developerActivityCall as [string, RequestInit];
    const activityBody = JSON.parse(String(activityInit.body));
    expect(activityBody.activities[0]).toMatchObject({
      kind: "package_script",
      hostId: "endpoint:devbook",
      userId: "principal:alice",
      sessionId: "sess-identity",
      agentId: "agent:openclaw",
      workloadId: "workload:openclaw-agent",
      approvalId: "approval:change-123",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        toolCallId: "tool-call-identity-1",
      }),
    });
  });

  it("posts classified package-manager developer activity from preflight commands", async () => {
    process.env.CLAWDSTRIKE_AGENT_TOKEN = "test-token";
    process.env.CLAWDSTRIKE_POLICY_EVENTS_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/policy-events";
    process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL =
      "http://127.0.0.1:9878/api/v1/agent/edr/developer-activity";
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await handler(
      {
        toolName: "shell",
        params: { command: "npm run postinstall" },
      },
      {
        agentId: "agent:openclaw",
        sessionKey: "sess-package",
        toolCallId: "tool-call-package-2",
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const developerActivityCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith("/api/v1/agent/edr/developer-activity"),
    );
    expect(developerActivityCall).toBeDefined();
    const [, init] = developerActivityCall as [string, RequestInit];
    const body = JSON.parse(String(init.body));
    expect(body.activities).toHaveLength(1);
    expect(body.activities[0]).toMatchObject({
      kind: "package_script",
      sessionId: "sess-package",
      agentId: "agent:openclaw",
      workloadId: "openclaw-tool-preflight",
      manager: "npm",
      phase: "postinstall",
      script: "npm run postinstall",
      metadata: expect.objectContaining({
        collectorKind: "openclaw_tool_preflight",
        shellClassifier: "package_script",
        toolCallId: "tool-call-package-2",
      }),
    });
  });
});
