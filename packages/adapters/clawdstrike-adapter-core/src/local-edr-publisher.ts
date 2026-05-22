import type { SecurityContext } from "./context.js";
import type { ProcessedOutput } from "./interceptor.js";
import type { Decision, PolicyEvent } from "./types.js";

export interface LocalEdrConfig {
  enabled?: boolean;
  token?: string;
  policyEventsUrl?: string;
  developerActivityUrl?: string;
  packageManagerEventsUrl?: string;
  agentUrl?: string;
  timeoutMs?: number;
  includeAllowed?: boolean;
  includeResults?: boolean;
  includeDeveloperActivity?: boolean;
  packageLifecycleEnforcement?: PackageLifecycleEnforcementMode;
}

type LocalEdrEndpoint = {
  url: string;
  token: string;
  timeoutMs: number;
};

type EdrDeveloperActivity = Record<string, unknown>;
const PACKAGE_MANAGER_LIFECYCLE_MANAGERS = [
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "pip",
  "cargo",
  "gem",
  "go",
  "brew",
  "composer",
  "maven",
  "gradle",
  "uv",
  "poetry",
  "pipenv",
  "dotnet",
  "nuget",
  "swift",
  "mix",
] as const;
type PackageManagerLifecycleManager =
  (typeof PACKAGE_MANAGER_LIFECYCLE_MANAGERS)[number];
type PackageManagerLifecycleHookInput = {
  env?: Record<string, string | undefined>;
  now?: Date;
};
export type PackageLifecycleEnforcementMode = "observe" | "block";
type PackageManagerLifecycleEvent = {
  eventId: string;
  observedAt: string;
  hostId?: string;
  userId?: string;
  sessionId?: string;
  process: {
    image: string;
    commandLine: string;
    cwd?: string;
  };
  metadata: Record<string, unknown>;
  manager: PackageManagerLifecycleManager;
  package?: string;
  phase: string;
  script: string;
  workingDirectory?: string;
};
type CredentialActivityKind =
  | "repo_secret"
  | "ci_token"
  | "local_api_key"
  | "browser_cookie";
type CredentialActivityCredentialKind =
  | "api_token"
  | "browser_cookie"
  | "cloud_credential"
  | "package_registry_token"
  | "ssh_key"
  | "signing_key";
type CredentialActivityTarget = {
  kind: CredentialActivityKind;
  path: string;
  name: string;
  credentialKind: CredentialActivityCredentialKind;
  classifier: string;
  deceptionSignal?: true;
  deceptionArtifactKind?: string;
  detectionRuleId?: string;
};
type BrowserRuntimeActivityKind =
  | "browser_automation"
  | "browser_download"
  | "browser_extension";
export interface LocalEdrBrowserRuntimeActivity {
  kind?: BrowserRuntimeActivityKind;
  runtime?: string;
  observedAt?: string | Date;
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  toolCallId?: string;
  process?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  browser?: string;
  action?: string;
  target?: string;
  toolName?: string;
  parameters?: Record<string, unknown>;
  path?: string;
  sourceUrl?: string;
  contentHash?: string;
  sha256?: string;
  fileHash?: string;
  downloadHash?: string;
  byteCount?: number;
  downloadByteCount?: number;
  fileSize?: number;
  transferSize?: number;
  extensionId?: string;
  source?: string;
  rawResult?: unknown;
  rawPayload?: unknown;
  rawContent?: unknown;
}
export interface LocalEdrRepoScannerCredentialFinding {
  path: string;
  kind?: CredentialActivityKind;
  name?: string;
  credentialKind?: CredentialActivityCredentialKind;
  scannerId?: string;
  ruleId?: string;
  confidence?: number;
  repositoryPath?: string;
  rawValue?: string;
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  metadata?: Record<string, unknown>;
}

const DEFAULT_AGENT_URL = "http://127.0.0.1:9878";
const DEFAULT_TIMEOUT_MS = 250;
const REDACTED = "[REDACTED]";
const SENSITIVE_KEY =
  /(?:secret|token|password|passwd|credential|api[_-]?key|authorization|cookie|session|private[_-]?key|access[_-]?key|refresh[_-]?token|id[_-]?token|client[_-]?secret)/i;
const CONTENT_KEY =
  /(?:content|body|payload|patch|diff|result|output|prompt|input|message|raw)/i;
const SECRET_LIKE_VALUE =
  /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

export function shouldPublishPolicyDecisionToLocalEdr(
  decision: Decision,
  config?: LocalEdrConfig,
): boolean {
  if (decision.status === "allow" && config?.includeAllowed === false) {
    return false;
  }
  return resolvePolicyEventsEndpoint(config) !== null;
}

export function buildAdapterCoreDecisionPolicyEventForEdr(
  policyEvent: PolicyEvent,
  toolName: string,
  decision: Decision,
  context: SecurityContext,
): PolicyEvent {
  const scrubbed = scrubPolicyEvent(policyEvent);
  return {
    ...scrubbed,
    metadata: {
      ...sanitizeMetadata(context.metadata),
      ...sanitizeMetadata(scrubbed.metadata),
      collectorKind: "adapter_core_tool_interceptor",
      phase: "before_execute",
      contextId: context.id,
      toolName,
      payloadScrubbed: true,
      policyAllowed: decision.status !== "deny",
      policyStatus: decision.status,
      policyGuard: sanitizeDecisionText(decision.guard),
      policySeverity: decision.severity,
      policyReasonCode:
        "reason_code" in decision ? decision.reason_code : undefined,
      policyReason: sanitizeDecisionText(decision.reason),
      policyMessage: sanitizeDecisionText(decision.message),
    },
  };
}

export function buildAdapterCoreResultPolicyEventForEdr(
  toolName: string,
  input: unknown,
  processed: ProcessedOutput,
  context: SecurityContext,
): PolicyEvent {
  return {
    eventId: `adapter-core-result-${context.id}-${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 9)}`,
    eventType: "custom",
    timestamp: new Date().toISOString(),
    sessionId: context.sessionId,
    data: {
      type: "custom",
      customType: "adapter_core_tool_result",
      toolName,
      rawInputOmitted: true,
      rawOutputOmitted: true,
      inputSummary: summarizeValue(input),
      outputSummary: summarizeValue(processed.output),
      outputModified: processed.modified,
      redactionCount: processed.redactions?.length ?? 0,
      redactions: processed.redactions?.map((redaction) => ({
        type: redaction.type,
        location: redaction.location,
      })),
    },
    metadata: {
      ...sanitizeMetadata(context.metadata),
      collectorKind: "adapter_core_tool_interceptor",
      phase: "after_execute",
      contextId: context.id,
      toolName,
      payloadScrubbed: true,
    },
  };
}

export function buildAdapterCoreDeveloperActivityForEdr(
  policyEvent: PolicyEvent,
  toolName: string,
  decision: Decision,
  context: SecurityContext,
): EdrDeveloperActivity | null {
  const metadata = {
    ...developerActivityCorrelationMetadata(
      context.metadata,
      policyEvent.metadata,
    ),
    collectorKind: "adapter_core_tool_interceptor",
    policyAllowed: decision.status !== "deny",
    policyStatus: decision.status,
    policyGuard: sanitizeDecisionText(decision.guard),
    policySeverity: decision.severity,
    policyReason: sanitizeDecisionText(decision.reason),
    toolName,
    shellClassifier: undefined as string | undefined,
  };
  const identitySources = [context.metadata, policyEvent.metadata];
  const common = {
    hostId: metadataStringFromSources(identitySources, [
      "hostId",
      "host_id",
      "endpointHostId",
      "endpoint_host_id",
      "endpointId",
      "endpoint_id",
    ]),
    userId:
      trimmedString(context.userId) ??
      metadataStringFromSources(identitySources, [
        "userId",
        "user_id",
        "principal",
        "principalId",
        "principal_id",
      ]),
    sessionId: policyEvent.sessionId ?? context.sessionId,
    agentId: metadataStringFromSources(identitySources, [
      "agentId",
      "agent_id",
      "endpointAgentId",
      "endpoint_agent_id",
    ]),
    workloadId:
      metadataStringFromSources(identitySources, [
        "workloadId",
        "workload_id",
      ]) ?? "adapter-core",
    approvalId: metadataStringFromSources(identitySources, [
      "approvalId",
      "approval_id",
    ]),
    process: developerActivityProcessFromMetadata(identitySources),
  };

  const directPersistenceTarget = classifyPersistencePolicyEvent(policyEvent);
  if (directPersistenceTarget) {
    return {
      ...common,
      kind: "persistence_change",
      mechanism: directPersistenceTarget.mechanism,
      operation: directPersistenceTarget.operation,
      target: directPersistenceTarget.target,
      commandLine: `persistence_change ${directPersistenceTarget.operation} ${directPersistenceTarget.target}`,
      metadata: {
        ...metadata,
        policyEventType: policyEvent.eventType,
        shellClassifier: "persistence_change",
      },
    };
  }

  const directNetworkEgress = classifyNetworkEgressPolicyEvent(policyEvent);
  if (directNetworkEgress) {
    return {
      ...common,
      kind: "network_egress",
      host: directNetworkEgress.host,
      port: directNetworkEgress.port,
      protocol: directNetworkEgress.protocol,
      method: directNetworkEgress.method,
      url: directNetworkEgress.url,
      commandLine: networkEgressCommandLine(directNetworkEgress),
      metadata: {
        ...metadata,
        policyEventType: policyEvent.eventType,
        shellClassifier: "network_egress",
        rawPayloadOmitted: true,
      },
    };
  }

  const directCredentialTarget = classifyCredentialPolicyEvent(policyEvent);
  if (directCredentialTarget) {
    return {
      ...common,
      kind: directCredentialTarget.kind,
      path: directCredentialTarget.path,
      name: directCredentialTarget.name,
      credentialKind: directCredentialTarget.credentialKind,
      commandLine: `credential_access ${directCredentialTarget.path}`,
      metadata: credentialActivityMetadata(metadata, directCredentialTarget, {
        shellClassifier: directCredentialTarget.classifier,
        policyEventType: policyEvent.eventType,
      }),
    };
  }

  const directFileAccess = classifyFileAccessPolicyEvent(policyEvent);
  if (directFileAccess) {
    return {
      ...common,
      kind: directFileAccess.kind,
      path: directFileAccess.path,
      operation: directFileAccess.operation,
      contentHash: directFileAccess.contentHash,
      commandLine: `${directFileAccess.kind} ${directFileAccess.path}`,
      metadata: {
        ...metadata,
        policyEventType: policyEvent.eventType,
        shellClassifier: directFileAccess.kind,
        rawPayloadOmitted: true,
        contentHash: directFileAccess.contentHash,
      },
    };
  }

  const directPatchApply = classifyPatchApplyPolicyEvent(policyEvent);
  if (directPatchApply) {
    return {
      ...common,
      kind: "patch_apply",
      path: directPatchApply.path,
      patchBytes: directPatchApply.patchBytes,
      patchHash: directPatchApply.patchHash,
      commandLine: `patch_apply ${directPatchApply.path}`,
      metadata: {
        ...metadata,
        policyEventType: policyEvent.eventType,
        shellClassifier: "patch_apply",
        rawPayloadOmitted: true,
      },
    };
  }

  const browserRuntimeActivity = buildBrowserRuntimeActivityForLocalEdr({
    ...browserRuntimeActivityFromCuaPolicyEvent(
      policyEvent,
      toolName,
      metadata,
      identitySources,
    ),
    hostId: common.hostId,
    userId: common.userId,
    sessionId: common.sessionId,
    agentId: common.agentId,
    workloadId: common.workloadId,
    approvalId: common.approvalId,
    toolCallId: metadataStringFromSources(identitySources, [
      "toolCallId",
      "tool_call_id",
    ]),
    process: common.process,
  });
  if (browserRuntimeActivity) {
    return browserRuntimeActivity;
  }

  const toolCall = developerToolCallFromPolicyEvent(policyEvent, toolName);
  if (toolCall) {
    return {
      ...common,
      kind: "mcp_tool",
      toolName: toolCall.toolName,
      parameters: toolCall.parameters,
      metadata: {
        ...metadata,
        policyEventType: policyEvent.eventType,
        shellClassifier: "tool_call",
      },
    };
  }

  if (policyEvent.eventType !== "command_exec") return null;
  const command = commandTokensFromPolicyEvent(policyEvent);
  if (command.length === 0) return null;

  const sanitizedCommand = [
    redactCommandPart(command[0] ?? ""),
    ...scrubCommandArgs(command.slice(1)),
  ];
  const commandLine = sanitizedCommand.join(" ");

  const packageCommand = classifyPackageCommand(command);
  if (packageCommand) {
    return {
      ...common,
      kind: "package_script",
      manager: packageCommand.manager,
      package: packageCommand.packageName,
      phase: packageCommand.phase,
      script: commandLine,
      image: sanitizedCommand[0],
      commandLine,
      metadata: {
        ...metadata,
        shellClassifier: "package_script",
      },
    };
  }

  const packageRegistryTokenCommand =
    classifyPackageRegistryTokenCommand(command);
  if (packageRegistryTokenCommand) {
    return {
      ...common,
      kind: packageRegistryTokenCommand.kind,
      path: packageRegistryTokenCommand.path,
      name: packageRegistryTokenCommand.name,
      credentialKind: packageRegistryTokenCommand.credentialKind,
      image: sanitizedCommand[0],
      commandLine,
      args: scrubCommandArgs(command.slice(1)),
      metadata: credentialActivityMetadata(
        metadata,
        packageRegistryTokenCommand,
        {
          shellClassifier: packageRegistryTokenCommand.classifier,
        },
      ),
    };
  }

  const cloudCommand = classifyCloudCommand(command);
  if (cloudCommand) {
    return {
      ...common,
      kind: "cloud_cli",
      provider: cloudCommand.provider,
      operation: cloudCommand.operation,
      args: scrubCommandArgs(cloudCommand.args),
      image: sanitizedCommand[0],
      commandLine,
      metadata: {
        ...metadata,
        shellClassifier: "cloud_cli",
      },
    };
  }

  const dnsLookup = classifyDnsLookupCommand(command);
  if (dnsLookup) {
    return {
      ...common,
      kind: "dns_lookup",
      query: dnsLookup.query,
      recordType: dnsLookup.recordType,
      image: sanitizedCommand[0],
      commandLine,
      args: scrubCommandArgs(command.slice(1)),
      metadata: {
        ...metadata,
        shellClassifier: "dns_lookup",
        detectionHint: dnsLookup.detectionHint,
      },
    };
  }

  const persistenceCommand = classifyPersistenceCommand(command);
  if (persistenceCommand) {
    return {
      ...common,
      kind: "persistence_change",
      mechanism: persistenceCommand.mechanism,
      operation: persistenceCommand.operation,
      target: persistenceCommand.target,
      image: sanitizedCommand[0],
      commandLine,
      args: scrubCommandArgs(command.slice(1)),
      metadata: {
        ...metadata,
        shellClassifier: "persistence_change",
      },
    };
  }

  const credentialTarget = classifyCredentialCommand(command);
  if (credentialTarget) {
    return {
      ...common,
      kind: credentialTarget.kind,
      path: credentialTarget.path,
      name: credentialTarget.name,
      credentialKind: credentialTarget.credentialKind,
      image: sanitizedCommand[0],
      commandLine,
      args: scrubCommandArgs(command.slice(1)),
      metadata: credentialActivityMetadata(metadata, credentialTarget, {
        shellClassifier: credentialTarget.classifier,
      }),
    };
  }

  return {
    ...common,
    kind: "shell_command",
    image: sanitizedCommand[0],
    args: scrubCommandArgs(command.slice(1)),
    commandLine,
    workingDirectory: commandWorkingDirectory(policyEvent),
    metadata: {
      ...metadata,
      shellClassifier: "shell_command",
    },
  };
}

export async function publishPolicyEventToLocalEdr(
  policyEvent: PolicyEvent,
  config?: LocalEdrConfig,
): Promise<void> {
  const endpoint = resolvePolicyEventsEndpoint(config);
  if (!endpoint) return;

  try {
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(endpoint.timeoutMs),
      body: JSON.stringify({ events: [policyEvent] }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // Local EDR capture is evidence enrichment only. The tool-boundary policy
    // decision above remains authoritative when capture is absent or offline.
  }
}

export async function publishDeveloperActivityToLocalEdr(
  activity: EdrDeveloperActivity,
  config?: LocalEdrConfig,
): Promise<void> {
  const endpoint = resolveLocalEdrEndpoint(config, "developer_activity");
  if (!endpoint) return;

  try {
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(endpoint.timeoutMs),
      body: JSON.stringify({ activities: [activity] }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // Developer-activity capture is enrichment only. Policy evaluation remains
    // authoritative when the local agent is unavailable.
  }
}

export function buildBrowserRuntimeActivityForLocalEdr(
  activity: LocalEdrBrowserRuntimeActivity,
): EdrDeveloperActivity | null {
  const kind = browserRuntimeActivityKind(activity);
  if (!kind) return null;

  const path = trimmedString(activity.path);
  const explicitBrowser = trimmedString(activity.browser);
  const inferredBrowser = explicitBrowser
    ? undefined
    : browserNameFromPath(path);
  const browser = explicitBrowser ?? inferredBrowser;
  const metadata = {
    ...sanitizeMetadata(activity.metadata),
    collectorKind: "browser_runtime",
    runtime: trimmedString(activity.runtime),
    payloadScrubbed: true,
    rawPayloadOmitted: true,
    browserInferredFromPath: inferredBrowser ? true : undefined,
  };
  const common = {
    observedAt: observedAtString(activity.observedAt),
    hostId: trimmedString(activity.hostId),
    userId: trimmedString(activity.userId),
    sessionId: trimmedString(activity.sessionId),
    agentId: trimmedString(activity.agentId),
    workloadId: trimmedString(activity.workloadId),
    approvalId: trimmedString(activity.approvalId),
    toolCallId: trimmedString(activity.toolCallId),
    process: sanitizedBrowserProcess(activity.process),
    metadata,
  };

  if (kind === "browser_automation") {
    const action = trimmedString(activity.action);
    if (!action) return null;
    return {
      ...common,
      kind,
      browser,
      action,
      target: trimmedString(activity.target),
      toolName: trimmedString(activity.toolName) ?? `browser.${action}`,
      parameters:
        asRecord(
          sanitizeGenericValue(activity.parameters ?? {}, "parameters"),
        ) ?? {},
    };
  }

  if (kind === "browser_download") {
    if (!browser || !path) return null;
    return {
      ...common,
      kind,
      browser,
      path,
      sourceUrl:
        redactUrl(trimmedString(activity.sourceUrl) ?? "") || undefined,
      contentHash: browserRuntimeContentHash(activity),
      metadata: {
        ...metadata,
        downloadByteCount: browserRuntimeByteCount(activity),
      },
    };
  }

  if (!browser || !path) return null;
  return {
    ...common,
    kind,
    browser,
    path,
    extensionId: trimmedString(activity.extensionId),
    source: redactUrl(trimmedString(activity.source) ?? "") || undefined,
    contentHash: browserRuntimeContentHash(activity),
  };
}

export async function publishBrowserRuntimeActivityToLocalEdr(
  activity: LocalEdrBrowserRuntimeActivity,
  config?: LocalEdrConfig,
): Promise<void> {
  const developerActivity = buildBrowserRuntimeActivityForLocalEdr(activity);
  if (!developerActivity) return;
  await publishDeveloperActivityToLocalEdr(developerActivity, config);
}

export function buildRepoScannerCredentialActivityForLocalEdr(
  finding: LocalEdrRepoScannerCredentialFinding,
): EdrDeveloperActivity | null {
  const path = trimmedString(finding.path);
  if (!path) return null;

  const classified = classifyCredentialTarget(path, finding.name ?? "");
  const kind = finding.kind ?? classified?.kind ?? "repo_secret";
  const credentialKind =
    finding.credentialKind ??
    classified?.credentialKind ??
    credentialKindFromPath(path.toLowerCase());
  const name =
    trimmedString(finding.name) ??
    classified?.name ??
    credentialNameFromPath(path, kind);

  return {
    hostId: trimmedString(finding.hostId),
    userId: trimmedString(finding.userId),
    sessionId: trimmedString(finding.sessionId),
    agentId: trimmedString(finding.agentId),
    workloadId: trimmedString(finding.workloadId),
    approvalId: trimmedString(finding.approvalId),
    kind,
    path,
    name,
    credentialKind,
    commandLine: `repo_scan ${path}`,
    metadata: {
      ...sanitizeMetadata(finding.metadata),
      collectorKind: "repo_scanner",
      scannerId: trimmedString(finding.scannerId),
      ruleId: trimmedString(finding.ruleId),
      confidence:
        typeof finding.confidence === "number" &&
        Number.isFinite(finding.confidence)
          ? finding.confidence
          : undefined,
      repositoryPath: trimmedString(finding.repositoryPath),
      rawValueOmitted: true,
      payloadScrubbed: true,
      shellClassifier: `${kind}_repo_scan`,
    },
  };
}

export async function publishRepoScannerCredentialFindingToLocalEdr(
  finding: LocalEdrRepoScannerCredentialFinding,
  config?: LocalEdrConfig,
): Promise<void> {
  const activity = buildRepoScannerCredentialActivityForLocalEdr(finding);
  if (!activity) return;
  await publishDeveloperActivityToLocalEdr(activity, config);
}

export function buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr(
  input: PackageManagerLifecycleHookInput = {},
): PackageManagerLifecycleEvent | null {
  const env = input.env ?? processEnv();
  const manager = packageLifecycleManagerFromEnvironment(env);
  const phase = packageLifecyclePhaseFromEnvironment(env, manager);
  if (!manager || !phase) return null;

  const now = input.now ?? new Date();
  const workingDirectory =
    trimmedString(env.CLAWDSTRIKE_PACKAGE_WORKING_DIR) ??
    trimmedString(env.INIT_CWD) ??
    trimmedString(env.PWD) ??
    trimmedString(env.INITPWD) ??
    trimmedString(env.CARGO_MANIFEST_DIR);
  const script = redactSensitiveString(
    trimmedString(env.CLAWDSTRIKE_PACKAGE_SCRIPT) ??
      trimmedString(env.npm_lifecycle_script) ??
      packageLifecycleCommandLine(manager, phase),
  );
  const packageName =
    trimmedString(env.CLAWDSTRIKE_PACKAGE_NAME) ??
    trimmedString(env.npm_package_name) ??
    trimmedString(env.CARGO_PKG_NAME);
  const execPath =
    trimmedString(env.CLAWDSTRIKE_PACKAGE_MANAGER_EXEC_PATH) ??
    trimmedString(env.npm_execpath) ??
    trimmedString(env.CARGO) ??
    manager;
  const metadata = sanitizeMetadata({
    collectorKind: "package_manager_lifecycle_hook",
    npmLifecycleEvent: phase,
    packageLifecyclePhase: phase,
    packageManager: manager,
    packageManagerUserAgent: trimmedString(env.npm_config_user_agent),
    npmCommand: trimmedString(env.npm_command),
    packageManagerExecPath: execPath,
    payloadScrubbed: true,
  });

  return {
    eventId: packageLifecycleEventId(
      manager,
      phase,
      packageName,
      workingDirectory,
      now,
    ),
    observedAt: now.toISOString(),
    hostId:
      trimmedString(env.CLAWDSTRIKE_HOST_ID) ?? trimmedString(env.HOSTNAME),
    userId:
      trimmedString(env.CLAWDSTRIKE_USER_ID) ??
      trimmedString(env.USER) ??
      trimmedString(env.USERNAME),
    sessionId: trimmedString(env.CLAWDSTRIKE_SESSION_ID),
    process: {
      image: execPath,
      commandLine: packageLifecycleCommandLine(manager, phase),
      cwd: workingDirectory,
    },
    metadata,
    manager,
    package: packageName,
    phase,
    script,
    workingDirectory,
  };
}

export async function publishPackageManagerLifecycleEventToLocalEdr(
  input: PackageManagerLifecycleHookInput = {},
  config?: LocalEdrConfig,
): Promise<void> {
  const env = input.env ?? processEnv();
  const enforcementMode = packageLifecycleEnforcementMode(config, env);
  const event = buildPackageManagerLifecycleEventFromEnvironmentForLocalEdr({
    ...input,
    env,
  });
  if (!event) {
    if (enforcementMode === "block") {
      throw new Error(
        "Clawdstrike package-manager lifecycle enforcement is enabled, but the hook could not infer a package-manager lifecycle event from the environment",
      );
    }
    return;
  }

  const endpoint = resolveLocalEdrEndpoint(config, "package_manager_events");
  if (!endpoint) {
    if (enforcementMode === "block") {
      throw new Error(
        "Clawdstrike package-manager lifecycle enforcement is enabled, but local EDR is unavailable",
      );
    }
    return;
  }

  try {
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(endpoint.timeoutMs),
      body: JSON.stringify({ events: [event] }),
    });
    if (!response.ok) {
      if (enforcementMode === "block") {
        throw new Error(
          `Clawdstrike package-manager lifecycle enforcement rejected unavailable local EDR response: HTTP ${response.status}`,
        );
      }
      return;
    }
    if (enforcementMode === "block") {
      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error(
          "Clawdstrike package-manager lifecycle enforcement rejected malformed local EDR response",
        );
      }
      if (!packageLifecycleResponseHasRecognizedVerdict(payload)) {
        throw new Error(
          "Clawdstrike package-manager lifecycle enforcement rejected unrecognized local EDR response",
        );
      }
      if (packageLifecycleResponseHasFindings(payload)) {
        throw new Error(
          "Clawdstrike package-manager lifecycle enforcement blocked package script findings",
        );
      }
    }
  } catch (error) {
    if (enforcementMode === "block") {
      throw error;
    }
    // Package-manager lifecycle capture must never break dependency installation.
  }
}

function packageLifecycleEnforcementMode(
  config: LocalEdrConfig | undefined,
  env: Record<string, string | undefined>,
): PackageLifecycleEnforcementMode {
  const configured = config?.packageLifecycleEnforcement?.trim().toLowerCase();
  const fromEnv =
    env.CLAWDSTRIKE_PACKAGE_LIFECYCLE_ENFORCEMENT?.trim().toLowerCase();
  const value = configured ?? fromEnv;
  return value === "block" || value === "enforce" || value === "fail_closed"
    ? "block"
    : "observe";
}

function packageLifecycleResponseHasRecognizedVerdict(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") return false;
  const record = payload as Record<string, unknown>;
  return (
    typeof numericRecordValue(record, "findingCount") === "number" ||
    typeof numericRecordValue(record, "finding_count") === "number" ||
    Array.isArray(record.findings)
  );
}

function packageLifecycleResponseHasFindings(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") return false;
  const record = payload as Record<string, unknown>;
  const findingCount =
    numericRecordValue(record, "findingCount") ??
    numericRecordValue(record, "finding_count");
  if (typeof findingCount === "number" && findingCount > 0) return true;
  return Array.isArray(record.findings) && record.findings.length > 0;
}

function numericRecordValue(
  record: Record<string, unknown>,
  key: string,
): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function resolvePolicyEventsEndpoint(
  config?: LocalEdrConfig,
): LocalEdrEndpoint | null {
  return resolveLocalEdrEndpoint(config, "policy_events");
}

function resolveLocalEdrEndpoint(
  config: LocalEdrConfig | undefined,
  endpointKind:
    | "policy_events"
    | "developer_activity"
    | "package_manager_events",
): LocalEdrEndpoint | null {
  if (!localEdrEnabled(config)) return null;
  if (typeof fetch !== "function") return null;

  const token = config?.token?.trim() ?? envValue("CLAWDSTRIKE_AGENT_TOKEN");
  if (!token) return null;

  const explicitUrl = explicitLocalEdrUrl(config, endpointKind);
  const baseUrl =
    config?.agentUrl?.trim() ??
    envValue("CLAWDSTRIKE_AGENT_URL") ??
    envValue("CLAWDSTRIKE_APPROVAL_URL") ??
    DEFAULT_AGENT_URL;
  const timeoutMs =
    boundedTimeout(config?.timeoutMs) ??
    boundedTimeout(
      Number.parseInt(
        envValue("CLAWDSTRIKE_ADAPTER_CORE_EDR_TIMEOUT_MS") ?? "",
        10,
      ),
    ) ??
    DEFAULT_TIMEOUT_MS;

  return {
    url:
      explicitUrl ??
      `${baseUrl.replace(/\/+$/, "")}/api/v1/agent/edr/${endpointPath(endpointKind)}`,
    token,
    timeoutMs,
  };
}

function explicitLocalEdrUrl(
  config: LocalEdrConfig | undefined,
  endpointKind:
    | "policy_events"
    | "developer_activity"
    | "package_manager_events",
): string | undefined {
  switch (endpointKind) {
    case "developer_activity":
      return (
        config?.developerActivityUrl?.trim() ??
        envValue("CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL")
      );
    case "package_manager_events":
      return (
        config?.packageManagerEventsUrl?.trim() ??
        envValue("CLAWDSTRIKE_PACKAGE_MANAGER_EVENTS_URL")
      );
    case "policy_events":
      return (
        config?.policyEventsUrl?.trim() ??
        envValue("CLAWDSTRIKE_POLICY_EVENTS_URL")
      );
  }
}

function endpointPath(
  endpointKind:
    | "policy_events"
    | "developer_activity"
    | "package_manager_events",
): string {
  switch (endpointKind) {
    case "developer_activity":
      return "developer-activity";
    case "package_manager_events":
      return "package-manager/events";
    case "policy_events":
      return "policy-events";
  }
}

function localEdrEnabled(config?: LocalEdrConfig): boolean {
  if (config?.enabled === false) return false;
  if (config?.enabled === true) return true;
  return truthyEnv(envValue("CLAWDSTRIKE_ADAPTER_CORE_EDR"));
}

function truthyEnv(value: string | undefined): boolean {
  if (!value) return false;
  return !["0", "false", "off", "no"].includes(value.toLowerCase());
}

function envValue(name: string): string | undefined {
  const processLike = (
    globalThis as typeof globalThis & {
      process?: { env?: Record<string, string | undefined> };
    }
  ).process;
  const value = processLike?.env?.[name];
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function processEnv(): Record<string, string | undefined> {
  const processLike = (
    globalThis as typeof globalThis & {
      process?: { env?: Record<string, string | undefined> };
    }
  ).process;
  return processLike?.env ?? {};
}

function browserRuntimeActivityKind(
  activity: LocalEdrBrowserRuntimeActivity,
): BrowserRuntimeActivityKind | null {
  if (activity.kind) return activity.kind;
  if (trimmedString(activity.extensionId) || trimmedString(activity.source)) {
    return "browser_extension";
  }
  if (trimmedString(activity.path) || trimmedString(activity.sourceUrl)) {
    return "browser_download";
  }
  if (trimmedString(activity.action) || trimmedString(activity.toolName)) {
    return "browser_automation";
  }
  return null;
}

function browserRuntimeActivityFromCuaPolicyEvent(
  policyEvent: PolicyEvent,
  toolName: string,
  metadata: Record<string, unknown>,
  identitySources: Array<Record<string, unknown> | undefined>,
): LocalEdrBrowserRuntimeActivity {
  const data = asRecord(policyEvent.data);
  if (!data || data.type !== "cua") return {};

  const action =
    stringRecordField(data, ["cuaAction", "cua_action", "action"]) ??
    policyEvent.eventType;
  const direction = stringRecordField(data, ["direction"]);
  const path = stringRecordField(data, [
    "path",
    "downloadPath",
    "download_path",
    "destinationPath",
    "destination_path",
    "localPath",
    "local_path",
  ]);
  const sourceUrl = stringRecordField(data, [
    "sourceUrl",
    "source_url",
    "url",
    "href",
  ]);
  const extensionId = stringRecordField(data, ["extensionId", "extension_id"]);
  const browser =
    metadataStringFromSources(identitySources, [
      "browser",
      "browserName",
      "browser_name",
    ]) ?? stringRecordField(data, ["browser", "browserName", "browser_name"]);

  const kind: BrowserRuntimeActivityKind =
    extensionId || browserExtensionPath(path)
      ? "browser_extension"
      : direction === "download" && path
        ? "browser_download"
        : "browser_automation";

  return {
    kind,
    runtime:
      metadataStringFromSources(identitySources, [
        "framework",
        "runtime",
        "provider",
      ]) ?? "adapter-core",
    browser,
    action,
    target: stringRecordField(data, [
      "target",
      "selector",
      "element",
      "host",
      "url",
      "href",
    ]),
    toolName,
    path,
    sourceUrl,
    contentHash: stringRecordField(data, [
      "contentHash",
      "content_hash",
      "sha256",
      "fileHash",
      "file_hash",
      "downloadHash",
      "download_hash",
    ]),
    byteCount: numberRecordField(data, [
      "byteCount",
      "byte_count",
      "fileSize",
      "file_size",
      "transferSize",
      "transfer_size",
    ]),
    extensionId,
    source: stringRecordField(data, [
      "source",
      "sourceUrl",
      "source_url",
      "url",
      "href",
    ]),
    parameters: browserRuntimeParametersFromCuaData(data),
    metadata: {
      ...metadata,
      policyEventType: policyEvent.eventType,
      cuaAction: action,
      shellClassifier: "browser_runtime",
    },
  };
}

function browserRuntimeParametersFromCuaData(
  data: Record<string, unknown>,
): Record<string, unknown> {
  const parameters: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (["type", "cuaAction", "cua_action"].includes(key)) continue;
    parameters[key] = value;
  }
  return parameters;
}

function stringRecordField(
  record: Record<string, unknown>,
  keys: string[],
): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value !== "string") continue;
    const trimmed = trimmedString(value);
    if (trimmed) return trimmed;
  }
  return undefined;
}

function numberRecordField(
  record: Record<string, unknown>,
  keys: string[],
): number | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value) && value >= 0)
      return value;
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) continue;
    const parsed = Number(trimmed);
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed;
  }
  return undefined;
}

function browserExtensionPath(path: string | undefined): boolean {
  return Boolean(path && /[\\/]extensions[\\/][a-z0-9_-]{8,}[\\/]/i.test(path));
}

function browserNameFromPath(path: string | undefined): string | undefined {
  const lower = path?.replace(/\\/g, "/").toLowerCase();
  if (!lower) return undefined;
  if (lower.includes("/application support/google/chrome/")) return "chrome";
  if (lower.includes("/application support/chromium/")) return "chromium";
  if (lower.includes("/application support/brave software/brave-browser/"))
    return "brave";
  if (lower.includes("/application support/microsoft edge/")) return "edge";
  if (lower.includes("/application support/firefox/")) return "firefox";
  if (lower.includes("/safari/extensions/")) return "safari";
  return undefined;
}

function browserRuntimeContentHash(
  activity: LocalEdrBrowserRuntimeActivity,
): string | undefined {
  const value =
    trimmedString(activity.contentHash) ??
    trimmedString(activity.sha256) ??
    trimmedString(activity.fileHash) ??
    trimmedString(activity.downloadHash);
  if (!value) return undefined;
  const sha256 = value.match(/^(?:sha256:)?([a-f0-9]{64})$/i);
  if (sha256?.[1]) return `sha256:${sha256[1].toLowerCase()}`;
  return redactSensitiveString(value);
}

function browserRuntimeByteCount(
  activity: LocalEdrBrowserRuntimeActivity,
): number | undefined {
  for (const value of [
    activity.byteCount,
    activity.downloadByteCount,
    activity.fileSize,
    activity.transferSize,
  ]) {
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
      return value;
  }
  return undefined;
}

function observedAtString(
  value: string | Date | undefined,
): string | undefined {
  if (value instanceof Date)
    return Number.isNaN(value.getTime()) ? undefined : value.toISOString();
  return trimmedString(value);
}

function sanitizedBrowserProcess(
  process: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  const sanitized = sanitizeGenericValue(process, "process");
  return asRecord(sanitized) ?? undefined;
}

function packageLifecycleManagerFromEnvironment(
  env: Record<string, string | undefined>,
): PackageManagerLifecycleManager | null {
  const explicitManager = trimmedString(
    env.CLAWDSTRIKE_PACKAGE_MANAGER,
  )?.toLowerCase();
  if (isPackageLifecycleManager(explicitManager)) return explicitManager;

  const userAgentManager = trimmedString(env.npm_config_user_agent)
    ?.split(/[\/\s]/, 1)[0]
    ?.toLowerCase();
  if (isPackageLifecycleManager(userAgentManager)) return userAgentManager;

  const execPath = trimmedString(env.npm_execpath)?.toLowerCase() ?? "";
  for (const manager of [
    "pnpm",
    "yarn",
    "npm",
    "bun",
    "cargo",
    "pip",
    "gem",
    "go",
    "brew",
  ] as const) {
    if (execPath.includes(manager)) return manager;
  }
  if (
    trimmedString(env.CARGO_MANIFEST_DIR) ||
    trimmedString(env.CARGO_PKG_NAME)
  )
    return "cargo";
  return null;
}

function packageLifecyclePhaseFromEnvironment(
  env: Record<string, string | undefined>,
  manager: PackageManagerLifecycleManager | null,
): string | undefined {
  return (
    trimmedString(env.CLAWDSTRIKE_PACKAGE_PHASE) ??
    trimmedString(env.npm_lifecycle_event) ??
    (manager === "cargo" &&
    (trimmedString(env.CARGO_MANIFEST_DIR) || trimmedString(env.OUT_DIR))
      ? "build.rs"
      : undefined)
  );
}

function isPackageLifecycleManager(
  value: string | undefined,
): value is PackageManagerLifecycleManager {
  return Boolean(
    value &&
    (PACKAGE_MANAGER_LIFECYCLE_MANAGERS as readonly string[]).includes(value),
  );
}

function packageLifecycleCommandLine(
  manager: PackageManagerLifecycleManager,
  phase: string,
): string {
  switch (manager) {
    case "npm":
    case "pnpm":
    case "yarn":
    case "bun":
      return `${manager} run ${phase}`;
    case "cargo":
      return phase === "build.rs" ? "cargo build-script" : `cargo ${phase}`;
    case "pip":
      return `pip ${phase}`;
    case "gem":
      return `gem ${phase}`;
    case "go":
      return `go ${phase}`;
    case "brew":
      return `brew ${phase}`;
    case "maven":
      return `mvn ${phase}`;
    case "composer":
    case "gradle":
    case "uv":
    case "poetry":
    case "pipenv":
    case "dotnet":
    case "nuget":
    case "swift":
    case "mix":
      return `${manager} ${phase}`;
  }
}

function packageLifecycleEventId(
  manager: PackageManagerLifecycleManager,
  phase: string,
  packageName: string | undefined,
  workingDirectory: string | undefined,
  now: Date,
): string {
  return stableLocalId("pkgmgr", [
    manager,
    phase,
    packageName ?? "",
    workingDirectory ?? "",
    now.toISOString(),
  ]);
}

function stableLocalId(prefix: string, parts: string[]): string {
  let hash = 0x811c9dc5;
  for (const part of parts) {
    for (const char of part) {
      hash ^= char.charCodeAt(0);
      hash = Math.imul(hash, 0x01000193);
    }
    hash ^= 0xff;
  }
  return `${prefix}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

function boundedTimeout(value: number | undefined): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const timeoutMs = Math.trunc(value);
  if (timeoutMs < 1) return null;
  return Math.min(timeoutMs, 10_000);
}

function scrubPolicyEvent(policyEvent: PolicyEvent): PolicyEvent {
  return {
    ...policyEvent,
    data: scrubPolicyEventData(policyEvent.data),
    metadata: sanitizeMetadata(policyEvent.metadata),
  };
}

function scrubPolicyEventData(data: PolicyEvent["data"]): PolicyEvent["data"] {
  const record = asRecord(data);
  if (!record) return data;

  switch (record.type) {
    case "file":
      return {
        type: "file",
        path: stringValue(record.path),
        operation: record.operation === "write" ? "write" : "read",
        contentHash:
          stringValue(record.contentHash ?? record.content_hash) || undefined,
      };
    case "network":
      return {
        type: "network",
        host: stringValue(record.host),
        port: coercePort(record.port),
        protocol: stringValue(record.protocol) || undefined,
        url: redactUrl(stringValue(record.url)) || undefined,
      };
    case "command":
      return {
        type: "command",
        command: redactCommandPart(stringValue(record.command)),
        args: scrubCommandArgs(Array.isArray(record.args) ? record.args : []),
        workingDir:
          stringValue(record.workingDir ?? record.working_dir) || undefined,
      };
    case "patch":
      return {
        type: "patch",
        filePath: stringValue(record.filePath ?? record.file_path),
        patchContent: "",
        patchHash:
          stringValue(record.patchHash ?? record.patch_hash) || undefined,
      };
    case "tool":
      return {
        type: "tool",
        toolName: stringValue(record.toolName ?? record.tool_name),
        parameters:
          asRecord(sanitizeGenericValue(record.parameters, "parameters")) ?? {},
      };
    case "secret":
      return {
        type: "secret",
        secretName: redactSensitiveString(
          stringValue(record.secretName ?? record.secret_name),
        ),
        scope: redactSensitiveString(stringValue(record.scope)),
      };
    case "custom":
    case "cua":
      return sanitizeGenericValue(record) as PolicyEvent["data"];
    default:
      return sanitizeGenericValue(record) as PolicyEvent["data"];
  }
}

function sanitizeMetadata(metadata: unknown): Record<string, unknown> {
  const sanitized = sanitizeGenericValue(metadata);
  return asRecord(sanitized) ?? {};
}

function sanitizeGenericValue(value: unknown, key = "", depth = 0): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    if (
      SENSITIVE_KEY.test(key) ||
      CONTENT_KEY.test(key) ||
      SECRET_LIKE_VALUE.test(value)
    ) {
      return {
        omitted: true,
        reason: omissionReason(key, value),
        length: value.length,
      };
    }
    if (value.length > 256) {
      return { omitted: true, reason: "large_string", length: value.length };
    }
    return redactSensitiveString(value);
  }

  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value !== "object") return String(value);
  if (depth >= 4) return { omitted: true, reason: "max_depth" };

  if (Array.isArray(value)) {
    return value
      .slice(0, 25)
      .map((item) => sanitizeGenericValue(item, key, depth + 1));
  }

  const sanitized: Record<string, unknown> = {};
  for (const [entryKey, entryValue] of Object.entries(
    value as Record<string, unknown>,
  )) {
    sanitized[entryKey] = sanitizeGenericValue(entryValue, entryKey, depth + 1);
  }
  return sanitized;
}

function summarizeValue(value: unknown): Record<string, unknown> {
  if (value === null) return { valueType: "null" };
  if (value === undefined) return { valueType: "undefined" };
  if (typeof value === "string")
    return { valueType: "string", length: value.length };
  if (typeof value === "number" || typeof value === "boolean") {
    return { valueType: typeof value };
  }
  if (Array.isArray(value)) {
    return { valueType: "array", itemCount: value.length };
  }
  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>);
    return {
      valueType: "object",
      keyCount: keys.length,
      keys: keys.slice(0, 25),
    };
  }
  return { valueType: typeof value };
}

function omissionReason(key: string, value: string): string {
  if (SENSITIVE_KEY.test(key) || SECRET_LIKE_VALUE.test(value))
    return "sensitive";
  return "content";
}

function scrubCommandArgs(args: unknown[]): string[] {
  let redactNext = false;
  return args.map((arg) => {
    const text = stringValue(arg);
    if (redactNext) {
      redactNext = false;
      return REDACTED;
    }
    const lower = text.toLowerCase();
    if (isSensitiveFlag(lower)) {
      if (text.includes("="))
        return `${text.slice(0, text.indexOf("="))}=${REDACTED}`;
      redactNext = true;
      return text;
    }
    if (isSensitivePositionalKey(lower)) {
      redactNext = true;
      return redactCommandPart(text);
    }
    return redactCommandPart(text);
  });
}

function isSensitiveFlag(value: string): boolean {
  return (
    value === "-p" ||
    /^(?:--|-)(?:password|passwd|token|secret|api-key|apikey|client-secret|cookie|body|value|data|from-literal|data-file)(?:=|$)/.test(
      value,
    )
  );
}

function isSensitivePositionalKey(value: string): boolean {
  return /(?:[:./-]_?|^_)(?:auth[_-]?token|api[_-]?key|client[_-]?secret|access[_-]?key|refresh[_-]?token|id[_-]?token)$/.test(
    value,
  );
}

function redactCommandPart(value: string): string {
  const withoutUrlUserinfo = redactUrlUserinfo(value);
  const redacted = withoutUrlUserinfo.replace(
    /((?:token|secret|password|passwd|api[_-]?key|authorization|cookie)=)[^\s&]+/gi,
    `$1${REDACTED}`,
  );
  if (redacted !== value) return redacted;
  if (SECRET_LIKE_VALUE.test(withoutUrlUserinfo)) return REDACTED;
  return withoutUrlUserinfo;
}

function redactUrlUserinfo(value: string): string {
  return value.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s@]+)@/gi,
    `$1${REDACTED}@`,
  );
}

function redactCommandLine(value: string): string {
  return scrubCommandArgs(value.trim().split(/\s+/)).join(" ");
}

function sanitizeDecisionText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  if (SECRET_LIKE_VALUE.test(value)) return REDACTED;
  const redacted = redactSensitiveString(value);
  return redacted.length > 512 ? `${redacted.slice(0, 512)}...` : redacted;
}

function redactSensitiveString(value: string): string {
  if (SECRET_LIKE_VALUE.test(value)) return REDACTED;
  return value.replace(
    /((?:token|secret|password|passwd|api[_-]?key|authorization|cookie)=)[^\s&]+/gi,
    `$1${REDACTED}`,
  );
}

function redactUrl(value: string): string {
  if (!value) return "";
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return redactSensitiveString(value);
  }
}

function coercePort(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value))
    return Math.trunc(value);
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return Number.parseInt(value, 10);
  }
  return 0;
}

function stringValue(value: unknown): string {
  return typeof value === "string"
    ? value
    : value === undefined || value === null
      ? ""
      : String(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return null;
  return value as Record<string, unknown>;
}

function commandTokensFromPolicyEvent(policyEvent: PolicyEvent): string[] {
  const data = asRecord(policyEvent.data);
  if (
    !data ||
    data.type !== "command" ||
    typeof data.command !== "string" ||
    !data.command.trim()
  ) {
    return [];
  }
  const args = Array.isArray(data.args)
    ? data.args.filter(
        (value): value is string =>
          typeof value === "string" && value.trim() !== "",
      )
    : [];
  return [data.command.trim(), ...args.map((value) => value.trim())];
}

function commandWorkingDirectory(policyEvent: PolicyEvent): string | undefined {
  const data = asRecord(policyEvent.data);
  const workingDir = data?.workingDir ?? data?.working_dir;
  return typeof workingDir === "string" && workingDir.trim()
    ? workingDir.trim()
    : undefined;
}

function developerToolCallFromPolicyEvent(
  policyEvent: PolicyEvent,
  fallbackToolName: string,
): { toolName: string; parameters: Record<string, unknown> } | null {
  if (policyEvent.eventType !== "tool_call") return null;
  const data = asRecord(policyEvent.data);
  if (!data || data.type !== "tool") return null;

  const toolName =
    stringValue(data.toolName ?? data.tool_name) || fallbackToolName;
  if (!toolName) return null;

  return {
    toolName,
    parameters:
      asRecord(sanitizeGenericValue(data.parameters, "parameters")) ?? {},
  };
}

function credentialActivityMetadata(
  metadata: Record<string, unknown>,
  target: CredentialActivityTarget,
  extra: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...metadata,
    ...extra,
    deceptionSignal: target.deceptionSignal,
    deceptionArtifactKind: target.deceptionArtifactKind,
    detectionRuleId: target.detectionRuleId,
  };
}

function classifyCredentialPolicyEvent(
  policyEvent: PolicyEvent,
): CredentialActivityTarget | null {
  const data = asRecord(policyEvent.data);
  if (!data) return null;

  if (data.type === "file") {
    const path = stringValue(data.path);
    if (!path) return null;
    return classifyCredentialPath(path);
  }

  if (data.type === "secret") {
    const scope = stringValue(data.scope);
    const secretName = stringValue(data.secretName ?? data.secret_name);
    const target = [scope, secretName].filter(Boolean).join("/");
    if (!target) return null;
    return classifyCredentialTarget(target, secretName || scope);
  }

  return null;
}

function classifyPackageCommand(command: string[]): {
  manager: string;
  phase: string;
  packageName?: string;
} | null {
  const [image, ...rawArgs] = command;
  const executable = executableName(image ?? "");
  let manager: string;
  let args = rawArgs;
  if (
    ["python", "python2", "python3"].includes(executable) &&
    rawArgs[0] === "-m" &&
    executableName(rawArgs[1] ?? "") === "pip"
  ) {
    manager = "pip";
    args = rawArgs.slice(2);
  } else if (
    [
      "npm",
      "pnpm",
      "yarn",
      "bun",
      "pip",
      "pip3",
      "cargo",
      "brew",
      "go",
      "gem",
      "composer",
      "mvn",
      "mvnw",
      "gradle",
      "gradlew",
      "uv",
      "poetry",
      "pipenv",
      "dotnet",
      "nuget",
      "swift",
      "mix",
    ].includes(executable)
  ) {
    if (executable === "pip3") {
      manager = "pip";
    } else if (["mvn", "mvnw"].includes(executable)) {
      manager = "maven";
    } else if (["gradle", "gradlew"].includes(executable)) {
      manager = "gradle";
    } else {
      manager = executable;
    }
  } else {
    return null;
  }

  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const commandName = args[commandIndex]?.toLowerCase();
  if (!commandName) return null;
  const afterCommand = args.slice(commandIndex + 1);
  const phase = packagePhase(manager, commandName, afterCommand);
  if (!phase) return null;

  return {
    manager,
    phase,
    packageName: packageNameFromPackageCommand(
      manager,
      commandName,
      afterCommand,
    ),
  };
}

function classifyPackageRegistryTokenCommand(
  command: string[],
): CredentialActivityTarget | null {
  const normalizedCommand = normalizePackageRegistryCommand(command);
  const [image, ...args] = normalizedCommand;
  const manager = packageRegistryManager(image ?? "");
  if (!manager) return null;

  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const commandName = args[commandIndex]?.toLowerCase();
  if (!commandName) return null;
  const commandArgs = args.slice(commandIndex + 1);
  if (
    !packageRegistryTokenCommandIsSensitive(manager, commandName, commandArgs)
  )
    return null;

  return {
    kind: "repo_secret",
    path: `${manager}:token`,
    name: `${manager}-token`,
    credentialKind: "package_registry_token",
    classifier: "package_registry_token_command",
  };
}

function normalizePackageRegistryCommand(command: string[]): string[] {
  const executable = executableName(command[0] ?? "");
  if (
    ["python", "python2", "python3"].includes(executable) &&
    command[1] === "-m" &&
    executableName(command[2] ?? "") === "pip"
  ) {
    return ["pip", ...command.slice(3)];
  }
  return command;
}

function classifyCloudCommand(command: string[]): {
  provider: string;
  operation: string;
  args: string[];
} | null {
  const [image, ...args] = command;
  const executable = executableName(image ?? "");
  const provider =
    executable === "flyctl"
      ? "fly"
      : executable === "sentry-cli"
        ? "sentry"
        : executable === "bw"
          ? "bitwarden"
          : executable === "buildkite-agent" || executable === "bk"
            ? "buildkite"
            : executable === "tofu"
              ? "opentofu"
              : executable === "sem"
                ? "semaphore"
                : executable;
  if (
    ![
      "aws",
      "gcloud",
      "az",
      "gh",
      "vercel",
      "netlify",
      "wrangler",
      "doctl",
      "fly",
      "op",
      "vault",
      "doppler",
      "heroku",
      "supabase",
      "firebase",
      "railway",
      "stripe",
      "sentry",
      "snyk",
      "bitwarden",
      "kubectl",
      "pulumi",
      "circleci",
      "glab",
      "buildkite",
      "drone",
      "semaphore",
      "appveyor",
      "woodpecker",
      "codefresh",
      "terraform",
      "terragrunt",
      "opentofu",
    ].includes(provider)
  )
    return null;
  const operationIndex = firstNonOptionArgIndex(args);
  if (operationIndex === null) return null;
  const operation = args[operationIndex];
  if (!operation) return null;
  const operationArgs = args.slice(operationIndex + 1);
  const sensitiveArgs = [operation, ...operationArgs];
  if (!cloudCliArgsAreSensitive(provider, sensitiveArgs)) return null;
  return { provider, operation, args: operationArgs };
}

function classifyDnsLookupCommand(command: string[]): {
  query: string;
  recordType?: string;
  detectionHint?: string;
} | null {
  const [image, ...args] = command;
  const executable = executableName(image ?? "");
  if (
    ![
      "curl",
      "wget",
      "http",
      "https",
      "httpie",
      "dig",
      "host",
      "nslookup",
      "ping",
      "ssh",
      "scp",
    ].includes(executable)
  ) {
    return null;
  }

  const query = args
    .map(hostnameFromNetworkTarget)
    .find((host): host is string => Boolean(host));
  if (!query) return null;

  return {
    query,
    recordType: dnsRecordTypeFromCommand(executable, args),
    detectionHint: standardHoneyHostname(query)
      ? "deception.honey_artifact_touched"
      : undefined,
  };
}

function hostnameFromNetworkTarget(value: string): string | null {
  const trimmed = value.trim().replace(/^['"]|['"]$/g, "");
  if (!trimmed || trimmed.startsWith("-") || shellAssignment(trimmed))
    return null;

  const urlHost = hostnameFromUrlLike(trimmed);
  if (urlHost) return urlHost;

  const withoutUser = trimmed.includes("@")
    ? trimmed.split("@").pop()
    : trimmed;
  const hostPortOrPath = withoutUser
    ?.split(/[/?#]/, 1)[0]
    ?.replace(/:\d+$/, "");
  const host = normalizedDnsHostname(hostPortOrPath ?? "");
  return dnsHostnameIsUseful(host) ? host : null;
}

function hostnameFromUrlLike(value: string): string | null {
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(value)
    ? value
    : `https://${value}`;
  try {
    return normalizedDnsHostname(new URL(candidate).hostname);
  } catch {
    return null;
  }
}

function normalizedDnsHostname(value: string): string | null {
  const host = value.trim().replace(/\.+$/, "").toLowerCase();
  if (!dnsHostnameIsUseful(host)) return null;
  return host;
}

function dnsHostnameIsUseful(value: string | null): value is string {
  return Boolean(
    value &&
    value.length <= 253 &&
    /^[a-z0-9.-]+$/.test(value) &&
    (value.includes(".") || value === "localhost") &&
    !/^[0-9.]+$/.test(value),
  );
}

function dnsRecordTypeFromCommand(
  executable: string,
  args: string[],
): string | undefined {
  if (!["dig", "host", "nslookup"].includes(executable)) return undefined;
  return args
    .map((arg) => arg.trim().toUpperCase())
    .find((arg) =>
      ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"].includes(arg),
    );
}

function standardHoneyHostname(host: string): boolean {
  return /^prod-admin-[a-z0-9-]+\.corp\.invalid$/i.test(host);
}

function classifyNetworkEgressPolicyEvent(policyEvent: PolicyEvent): {
  host: string;
  port: number;
  protocol?: string;
  method?: string;
  url?: string;
} | null {
  if (policyEvent.eventType !== "network_egress") return null;
  const data = asRecord(policyEvent.data);
  if (!data || data.type !== "network") return null;
  const host = stringRecordField(data, ["host"]);
  if (!host) return null;
  const rawUrl = stringRecordField(data, ["url"]);
  const redactedUrl = rawUrl ? redactUrl(rawUrl) : undefined;
  return {
    host,
    port: coercePort(data.port),
    protocol: stringRecordField(data, ["protocol"]),
    method: stringRecordField(data, ["method"])?.toUpperCase(),
    url: redactedUrl,
  };
}

function networkEgressCommandLine(network: {
  method?: string;
  url?: string;
  host: string;
  port: number;
}): string {
  const target = network.url ?? `${network.host}:${network.port}`;
  return network.method
    ? `network_egress ${network.method} ${target}`
    : `network_egress ${target}`;
}

function classifyFileAccessPolicyEvent(policyEvent: PolicyEvent): {
  kind: "file_read" | "file_write";
  path: string;
  operation: string;
  contentHash?: string;
} | null {
  if (!["file_read", "file_write"].includes(policyEvent.eventType)) return null;
  const data = asRecord(policyEvent.data);
  if (!data || data.type !== "file") return null;
  const path = stringRecordField(data, ["path"]);
  if (!path) return null;
  return {
    kind: policyEvent.eventType === "file_read" ? "file_read" : "file_write",
    path,
    operation:
      stringRecordField(data, ["operation"]) ??
      (policyEvent.eventType === "file_read" ? "read" : "write"),
    contentHash: stringRecordField(data, ["contentHash", "content_hash"]),
  };
}

function classifyPatchApplyPolicyEvent(policyEvent: PolicyEvent): {
  path: string;
  patchBytes: number;
  patchHash?: string;
} | null {
  if (policyEvent.eventType !== "patch_apply") return null;
  const data = asRecord(policyEvent.data);
  if (!data || data.type !== "patch") return null;
  const path = stringRecordField(data, ["filePath", "file_path", "path"]);
  if (!path) return null;
  return {
    path,
    patchBytes: stringValue(data.patchContent).length,
    patchHash: stringRecordField(data, ["patchHash", "patch_hash"]),
  };
}

function classifyPersistencePolicyEvent(policyEvent: PolicyEvent): {
  mechanism: string;
  operation: string;
  target: string;
} | null {
  if (policyEvent.eventType !== "file_write") return null;
  const data = asRecord(policyEvent.data);
  if (!data || data.type !== "file") return null;

  const target = stringValue(data.path);
  if (!target) return null;
  const mechanism = persistenceMechanismFromTarget(target);
  if (!mechanism) return null;

  return {
    mechanism,
    operation: stringValue(data.operation) ?? "write",
    target,
  };
}

function classifyPersistenceCommand(command: string[]): {
  mechanism: string;
  operation: string;
  target?: string;
} | null {
  const [image, ...args] = command;
  const executable = executableName(image ?? "");
  if (executable === "crontab") {
    return classifyCrontabPersistenceCommand(args);
  }
  if (executable === "systemctl") {
    return classifySystemctlPersistenceCommand(args);
  }
  if (executable !== "launchctl") return null;

  const operationIndex = firstNonOptionArgIndex(args);
  if (operationIndex === null) return null;
  const operation = args[operationIndex]?.toLowerCase();
  if (!operation || !launchctlOperationChangesPersistence(operation))
    return null;

  const operationArgs = args.slice(operationIndex + 1);
  const target = lastNonOptionArg(operationArgs);
  return {
    mechanism: persistenceMechanismFromTarget(target) ?? "launchctl",
    operation,
    target,
  };
}

function classifySystemctlPersistenceCommand(args: string[]): {
  mechanism: string;
  operation: string;
  target?: string;
} | null {
  const operationIndex = firstNonOptionArgIndex(args);
  if (operationIndex === null) return null;
  const operation = args[operationIndex]?.toLowerCase();
  if (!operation || !systemctlOperationChangesPersistence(operation))
    return null;
  return {
    mechanism: args.includes("--user")
      ? "systemd_user_service"
      : "systemd_service",
    operation,
    target: lastNonOptionArg(args.slice(operationIndex + 1)),
  };
}

function systemctlOperationChangesPersistence(operation: string): boolean {
  return ["enable", "disable", "link", "preset", "mask", "unmask"].includes(
    operation,
  );
}

function classifyCrontabPersistenceCommand(args: string[]): {
  mechanism: string;
  operation: string;
  target?: string;
} | null {
  if (args.some((arg) => arg === "-l")) return null;
  const target = crontabTarget(args);
  if (args.some((arg) => arg === "-r")) {
    return { mechanism: "user_crontab", operation: "remove", target };
  }
  if (args.some((arg) => arg === "-e")) {
    return { mechanism: "user_crontab", operation: "edit", target };
  }
  if (target) {
    return { mechanism: "user_crontab", operation: "install", target };
  }
  return null;
}

function crontabTarget(args: string[]): string | undefined {
  const target = lastNonOptionArg(args);
  return target && target !== "-u" ? target : "user_crontab";
}

function launchctlOperationChangesPersistence(operation: string): boolean {
  return [
    "bootstrap",
    "bootout",
    "load",
    "unload",
    "enable",
    "disable",
    "kickstart",
    "remove",
    "submit",
  ].includes(operation);
}

function persistenceMechanismFromTarget(
  target: string | undefined,
): string | undefined {
  const lower = target?.toLowerCase();
  if (!lower) return undefined;
  if (lower.includes("launchagents")) return "launch_agent";
  if (lower.includes("launchdaemons")) return "launch_daemon";
  if (
    /(?:^|[\\/])\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zlogin|config[\\/]fish[\\/]config\.fish)$/.test(
      lower,
    )
  ) {
    return "shell_startup";
  }
  return undefined;
}

function lastNonOptionArg(args: string[]): string | undefined {
  return [...args]
    .reverse()
    .find((arg) => arg && !arg.startsWith("-") && !shellAssignment(arg));
}

function classifyCredentialCommand(
  command: string[],
): CredentialActivityTarget | null {
  const executable = executableName(command[0] ?? "");
  if (executable === "security") {
    return classifyMacosKeychainCommand(command.slice(1));
  }
  if (executable === "pass") {
    return classifyPasswordStoreCommand(command.slice(1));
  }
  if (executable === "ssh-add") {
    return classifySshAgentCommand(command.slice(1));
  }
  if (executable === "git") {
    return classifyGitCredentialCommand(command.slice(1));
  }
  if (executable.startsWith("docker-credential-")) {
    return classifyDockerCredentialCommand(executable, command.slice(1));
  }

  if (
    ![
      "cat",
      "cp",
      "grep",
      "head",
      "less",
      "more",
      "open",
      "read_file",
      "rg",
      "sed",
      "tail",
      "type",
    ].includes(executable)
  ) {
    return null;
  }

  for (const arg of command.slice(1)) {
    const target = classifyCredentialPath(arg);
    if (target) return target;
  }

  return null;
}

function classifyDockerCredentialCommand(
  executable: string,
  args: string[],
): CredentialActivityTarget | null {
  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const operation = args[commandIndex]?.toLowerCase();
  if (operation !== "get") return null;

  const helperName = executable.replace(/^docker-credential-/, "") || "helper";
  return {
    kind: "local_api_key",
    path: `docker-credential:${helperName}`,
    name: executable,
    credentialKind: "package_registry_token",
    classifier: "docker_credential_command",
  };
}

function classifyGitCredentialCommand(
  args: string[],
): CredentialActivityTarget | null {
  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  if (args[commandIndex]?.toLowerCase() !== "credential") return null;

  const operation = args[commandIndex + 1]?.toLowerCase();
  if (!["fill", "approve"].includes(operation ?? "")) return null;

  return {
    kind: "local_api_key",
    path: `git-credential:${operation}`,
    name: "git-credential",
    credentialKind: "api_token",
    classifier: "git_credential_command",
  };
}

function classifySshAgentCommand(
  args: string[],
): CredentialActivityTarget | null {
  if (!args.some((arg) => arg === "-L" || arg === "-l")) return null;
  return {
    kind: "local_api_key",
    path: "ssh-agent:loaded-keys",
    name: "ssh-agent",
    credentialKind: "ssh_key",
    classifier: "ssh_agent_command",
  };
}

function classifyPasswordStoreCommand(
  args: string[],
): CredentialActivityTarget | null {
  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const operation = args[commandIndex]?.toLowerCase();
  if (operation !== "show") return null;

  const itemName = args
    .slice(commandIndex + 1)
    .find((arg) => arg && !arg.startsWith("-"));
  if (!itemName) return null;

  return {
    kind: "local_api_key",
    path: `pass:${itemName}`,
    name: itemName,
    credentialKind: "api_token",
    classifier: "password_store_command",
  };
}

function classifyMacosKeychainCommand(
  args: string[],
): CredentialActivityTarget | null {
  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const operation = args[commandIndex]?.toLowerCase();
  if (
    !["find-generic-password", "find-internet-password"].includes(
      operation ?? "",
    )
  )
    return null;

  const operationArgs = args.slice(commandIndex + 1);
  if (!operationArgs.some((arg) => arg === "-w" || arg === "-g")) return null;

  const itemName =
    optionValue(operationArgs, "-s", "--service") ??
    optionValue(operationArgs, "-a", "--account") ??
    operation ??
    "keychain-item";

  return {
    kind: "local_api_key",
    path: `macos-keychain:${itemName}`,
    name: itemName,
    credentialKind: "api_token",
    classifier: "macos_keychain_command",
  };
}

function optionValue(
  args: string[],
  shortFlag: string,
  longFlag: string,
): string | undefined {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) continue;
    if (arg === shortFlag || arg === longFlag) {
      const value = args[index + 1];
      return value && !value.startsWith("-") ? value : undefined;
    }
    const longPrefix = `${longFlag}=`;
    if (arg.startsWith(longPrefix)) return arg.slice(longPrefix.length);
  }
  return undefined;
}

function classifyCredentialPath(
  value: string,
): CredentialActivityTarget | null {
  const trimmed = value.trim().replace(/^['"]|['"]$/g, "");
  if (!trimmed || trimmed.startsWith("-")) return null;
  const lower = trimmed.toLowerCase();
  const honeyTarget = classifyStandardHoneyArtifactPath(trimmed, lower);
  if (honeyTarget) return honeyTarget;
  const developerCliCredentialTarget = classifyDeveloperCliCredentialPath(
    trimmed,
    lower,
  );
  if (developerCliCredentialTarget) return developerCliCredentialTarget;
  const cloudCredentialStoreTarget = classifyCloudCredentialStorePath(trimmed);
  if (cloudCredentialStoreTarget) return cloudCredentialStoreTarget;
  const signingKeyTarget = classifySigningKeyPath(trimmed, lower);
  if (signingKeyTarget) return signingKeyTarget;

  const looksPath =
    /^(?:\/|~\/|\.{1,2}\/|[a-z]:\\)/i.test(trimmed) ||
    /^(?:\.ssh[\\/])/i.test(trimmed) ||
    /^\.env(?:\.|$)/i.test(trimmed) ||
    /^(?:\.npmrc|\.pypirc|\.netrc)$/i.test(trimmed) ||
    (/[\\/]/.test(trimmed) &&
      /(secret|token|credential|cookie|\.env|\.npmrc|\.pypirc|id_rsa|id_ed25519)/i.test(
        trimmed,
      ));

  if (!looksPath) return null;

  if (
    /(?:^|[\\/])(cookies(?:\.sqlite)?|login data)(?:$|[\\/])/i.test(trimmed) ||
    /[\\/]application support[\\/](google[\\/]chrome|chromium|brave|microsoft edge|firefox|safari)/i.test(
      lower,
    )
  ) {
    return {
      kind: "browser_cookie",
      path: trimmed,
      name: "browser_cookie_store",
      credentialKind: "browser_cookie",
      classifier: "browser_cookie_path",
    };
  }

  if (
    /(?:^|[\\/])\.github[\\/]/i.test(trimmed) ||
    /[\\/](github-actions|gitlab-ci|circleci|buildkite|jenkins)[\\/]/i.test(
      lower,
    ) ||
    (/(?:\bci\b|ci[_-]?token|github[_-]?token|gh[_-]?token|actions)/i.test(
      lower,
    ) &&
      /(token|secret|credential)/i.test(lower))
  ) {
    return {
      kind: "ci_token",
      path: trimmed,
      name: credentialNameFromPath(trimmed, "ci_token"),
      credentialKind: "api_token",
      classifier: "ci_token_path",
    };
  }

  if (
    /(?:^|[\\/])(\.aws[\\/]credentials|\.azure|\.config[\\/]gcloud|\.docker[\\/]config\.json|\.cargo[\\/](?:credentials|credentials\.toml)|\.gem[\\/]credentials|application_default_credentials\.json|credentials\.json|token\.json|\.npmrc|\.pypirc|\.netrc)(?:$|[\\/])/i.test(
      trimmed,
    ) ||
    pathLooksLikePackageRegistryCredentialStore(lower)
  ) {
    return {
      kind: "local_api_key",
      path: trimmed,
      name: credentialNameFromPath(trimmed, "local_api_key"),
      credentialKind: pathLooksLikePackageRegistryCredentialStore(lower)
        ? "package_registry_token"
        : "cloud_credential",
      classifier: "local_api_key_path",
    };
  }

  if (
    /(?:^|[\\/])\.env(?:\.|$)/i.test(trimmed) ||
    /(secret|credential|private[_-]?key|api[_-]?key|token|id_rsa|id_ed25519)/i.test(
      lower,
    )
  ) {
    return {
      kind: "repo_secret",
      path: trimmed,
      name: credentialNameFromPath(trimmed, "repo_secret"),
      credentialKind: credentialKindFromPath(lower),
      classifier: "repo_secret_path",
    };
  }

  return null;
}

function classifyCloudCredentialStorePath(
  trimmed: string,
): CredentialActivityTarget | null {
  const matchesCloudCredentialStore =
    /(?:^|[\\/])\.kube[\\/]config$/i.test(trimmed) ||
    /(?:^|[\\/])\.terraform\.d[\\/]credentials\.tfrc\.json$/i.test(trimmed) ||
    /(?:^|[\\/])\.terraformrc$/i.test(trimmed) ||
    /(?:^|[\\/])\.config[\\/]pulumi[\\/]credentials\.json$/i.test(trimmed) ||
    /(?:^|[\\/])\.pulumi[\\/]credentials\.json$/i.test(trimmed);

  if (!matchesCloudCredentialStore) return null;

  return {
    kind: "local_api_key",
    path: trimmed,
    name: credentialNameFromPath(trimmed, "cloud-credential-store"),
    credentialKind: "cloud_credential",
    classifier: "cloud_credential_path",
  };
}

function classifySigningKeyPath(
  trimmed: string,
  lower: string,
): CredentialActivityTarget | null {
  const matchesSigningKeyStore =
    /(?:^|[\\/])\.config[\\/]sops[\\/]age[\\/]keys\.txt$/i.test(trimmed) ||
    /(?:^|[\\/])\.age[\\/]key\.txt$/i.test(trimmed) ||
    /(?:^|[\\/])\.gnupg[\\/]private-keys-v1\.d[\\/][^\\/]+\.key$/i.test(
      trimmed,
    ) ||
    /(?:^|[\\/])\.gnupg[\\/]secring\.gpg$/i.test(trimmed);

  if (!matchesSigningKeyStore) return null;

  return {
    kind: "local_api_key",
    path: trimmed,
    name: credentialNameFromPath(
      trimmed,
      lower.includes("gnupg") ? "gpg-private-key" : "age-key",
    ),
    credentialKind: "signing_key",
    classifier: "signing_key_path",
  };
}

function classifyDeveloperCliCredentialPath(
  trimmed: string,
  lower: string,
): CredentialActivityTarget | null {
  const matchesDeveloperCliCredentialStore =
    /(?:^|[\\/])\.config[\\/]gh[\\/](?:hosts|config)\.ya?ml$/i.test(trimmed) ||
    /(?:^|[\\/])\.config[\\/]glab-cli[\\/](?:config|hosts)\.ya?ml$/i.test(
      trimmed,
    ) ||
    /(?:^|[\\/])\.config[\\/]hub(?:$|[\\/])/i.test(trimmed) ||
    /(?:^|[\\/])\.config[\\/]git-credential(?:$|[\\/])/i.test(trimmed);

  if (!matchesDeveloperCliCredentialStore) return null;

  return {
    kind: "local_api_key",
    path: trimmed,
    name: credentialNameFromPath(
      trimmed,
      lower.includes("glab-cli") ? "gitlab-cli" : "github-cli",
    ),
    credentialKind: "api_token",
    classifier: "developer_cli_credential_path",
  };
}

function classifyStandardHoneyArtifactPath(
  trimmed: string,
  lower: string,
): CredentialActivityTarget | null {
  const standardHoney = standardHoneyArtifactKindFromPath(lower);
  if (!standardHoney) return null;
  return {
    kind: standardHoney.kind,
    path: trimmed,
    name:
      standardHoney.name ?? credentialNameFromPath(trimmed, "honey_artifact"),
    credentialKind: standardHoney.credentialKind,
    classifier: "honey_artifact_path",
    deceptionSignal: true,
    deceptionArtifactKind: standardHoney.deceptionArtifactKind,
    detectionRuleId: "deception.honey_artifact_touched",
  };
}

function standardHoneyArtifactKindFromPath(lowerPath: string): {
  kind: CredentialActivityKind;
  credentialKind: CredentialActivityCredentialKind;
  deceptionArtifactKind: string;
  name?: string;
} | null {
  if (
    pathEndsWithNormalizedSuffix(
      lowerPath,
      ".config/clawdstrike/internal-hosts.txt",
    )
  ) {
    return {
      kind: "repo_secret",
      credentialKind: "api_token",
      deceptionArtifactKind: "internal_hostname",
      name: "internal-hosts.txt",
    };
  }
  if (
    pathEndsWithNormalizedSuffix(
      lowerPath,
      ".config/clawdstrike/tokens/prod-api-token.txt",
    )
  ) {
    return {
      kind: "repo_secret",
      credentialKind: "api_token",
      deceptionArtifactKind: "api_token_file",
      name: "prod-api-token.txt",
    };
  }
  if (
    pathEndsWithNormalizedSuffix(
      lowerPath,
      "library/application support/clawdstrike/honey/cookies.json",
    )
  ) {
    return {
      kind: "browser_cookie",
      credentialKind: "browser_cookie",
      deceptionArtifactKind: "browser_cookie_jar",
      name: "browser_cookie_store",
    };
  }
  return null;
}

function pathEndsWithNormalizedSuffix(path: string, suffix: string): boolean {
  const normalized = path.replace(/\\/g, "/").replace(/\/+/g, "/");
  const normalizedSuffix = suffix.replace(/\\/g, "/").replace(/\/+/g, "/");
  return (
    normalized === normalizedSuffix ||
    normalized.endsWith(`/${normalizedSuffix}`)
  );
}

function classifyCredentialTarget(
  value: string,
  fallbackName: string,
): CredentialActivityTarget {
  const lower = value.toLowerCase();
  if (lower.includes("cookie")) {
    return {
      kind: "browser_cookie",
      path: value,
      name: fallbackName || "browser_cookie",
      credentialKind: "browser_cookie",
      classifier: "browser_cookie_secret",
    };
  }
  if (
    lower.includes("ci_token") ||
    lower.includes("github_token") ||
    lower.includes("gh_token") ||
    lower.includes("actions")
  ) {
    return {
      kind: "ci_token",
      path: value,
      name: fallbackName || "ci_token",
      credentialKind: "api_token",
      classifier: "ci_token_secret",
    };
  }
  if (
    lower.includes(".npmrc") ||
    lower.includes(".pypirc") ||
    lower.includes("registry")
  ) {
    return {
      kind: "repo_secret",
      path: value,
      name: fallbackName || "repo_secret",
      credentialKind: "package_registry_token",
      classifier: "repo_secret_secret",
    };
  }
  if (
    lower.includes("aws") ||
    lower.includes("gcloud") ||
    lower.includes("azure")
  ) {
    return {
      kind: "repo_secret",
      path: value,
      name: fallbackName || "repo_secret",
      credentialKind: "cloud_credential",
      classifier: "repo_secret_secret",
    };
  }
  if (
    lower.includes("ssh") ||
    lower.includes("id_rsa") ||
    lower.includes("id_ed25519")
  ) {
    return {
      kind: "repo_secret",
      path: value,
      name: fallbackName || "repo_secret",
      credentialKind: "ssh_key",
      classifier: "repo_secret_secret",
    };
  }
  if (lower.includes("signing") || lower.includes("codesign")) {
    return {
      kind: "repo_secret",
      path: value,
      name: fallbackName || "repo_secret",
      credentialKind: "signing_key",
      classifier: "repo_secret_secret",
    };
  }
  return {
    kind: "repo_secret",
    path: value,
    name: fallbackName || "repo_secret",
    credentialKind: "api_token",
    classifier: "repo_secret_secret",
  };
}

function credentialKindFromPath(
  lowerPath: string,
): Exclude<CredentialActivityCredentialKind, "browser_cookie"> {
  if (pathLooksLikePackageRegistryCredentialStore(lowerPath))
    return "package_registry_token";
  if (
    lowerPath.includes(".kube/config") ||
    lowerPath.includes(".terraform.d/credentials.tfrc.json") ||
    lowerPath.includes(".terraformrc") ||
    lowerPath.includes(".config/pulumi/credentials.json") ||
    lowerPath.includes(".pulumi/credentials.json")
  )
    return "cloud_credential";
  if (
    lowerPath.includes(".config/sops/age/keys.txt") ||
    lowerPath.includes(".age/key.txt") ||
    lowerPath.includes(".gnupg/private-keys-v1.d") ||
    lowerPath.includes(".gnupg/secring.gpg")
  )
    return "signing_key";
  if (
    lowerPath.includes(".aws") ||
    lowerPath.includes("gcloud") ||
    lowerPath.includes("azure")
  ) {
    return "cloud_credential";
  }
  if (lowerPath.includes("id_rsa") || lowerPath.includes("id_ed25519"))
    return "ssh_key";
  if (lowerPath.includes("signing") || lowerPath.includes("codesign"))
    return "signing_key";
  return "api_token";
}

function pathLooksLikePackageRegistryCredentialStore(
  lowerPath: string,
): boolean {
  return [
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".yarnrc.yml",
    ".pnpmrc",
    ".config/pip/pip.conf",
    ".pip/pip.conf",
    "pip/pip.ini",
    ".config/pypoetry/auth.toml",
    "library/application support/pypoetry/auth.toml",
    ".m2/settings.xml",
    ".gradle/gradle.properties",
    ".nuget/nuget/nuget.config",
  ].some((suffix) => pathEndsWithNormalizedSuffix(lowerPath, suffix));
}

function packageRegistryManager(image: string): string | null {
  const executable = executableName(image);
  return [
    "npm",
    "pnpm",
    "yarn",
    "docker",
    "pip",
    "pip3",
    "cargo",
    "gem",
  ].includes(executable)
    ? executable === "pip3"
      ? "pip"
      : executable
    : null;
}

function packageRegistryTokenCommandIsSensitive(
  manager: string,
  commandName: string,
  args: string[],
): boolean {
  if (manager === "docker") {
    return commandName === "login";
  }
  if (manager === "pip") {
    return commandName === "config" && pipConfigReferenceIsSensitive(args);
  }
  if (manager === "cargo") {
    return cargoRegistryCommandIsSensitive(commandName, args);
  }
  if (manager === "gem") {
    return rubyGemsRegistryCommandIsSensitive(commandName, args);
  }
  const joined = args.join(" ").toLowerCase();
  if (commandName === "token") {
    return ["list", "create", "revoke", "delete"].includes(
      args[0]?.toLowerCase() ?? "",
    );
  }
  if (commandName === "config") {
    const subcommand = args[0]?.toLowerCase();
    return (
      ["get", "set", "delete"].includes(subcommand ?? "") &&
      packageRegistryAuthConfigReference(joined)
    );
  }
  return false;
}

function rubyGemsRegistryCommandIsSensitive(
  commandName: string,
  args: string[],
): boolean {
  if (["signin", "signout"].includes(commandName)) return true;
  if (["owner", "push", "yank"].includes(commandName)) {
    return args.some((arg) => arg.toLowerCase().startsWith("--key"));
  }
  return false;
}

function cargoRegistryCommandIsSensitive(
  commandName: string,
  args: string[],
): boolean {
  if (["login", "logout"].includes(commandName)) return true;
  if (["owner", "publish"].includes(commandName)) {
    return args.some((arg) => arg.toLowerCase().startsWith("--token"));
  }
  return false;
}

function pipConfigReferenceIsSensitive(args: string[]): boolean {
  const subcommand = args[0]?.toLowerCase();
  if (!["get", "set", "unset", "list"].includes(subcommand ?? "")) return false;
  return args.some((arg) => {
    const lower = arg.toLowerCase();
    return (
      lower.includes("index-url") ||
      lower.includes("extra-index-url") ||
      lower.includes("trusted-host")
    );
  });
}

function packageRegistryAuthConfigReference(value: string): boolean {
  return (
    value.includes("_authtoken") ||
    value.includes("node_auth_token") ||
    value.includes("npm_token") ||
    value.includes("npm_config_")
  );
}

function packagePhase(
  manager: string,
  commandName: string,
  args: string[],
): string | null {
  switch (manager) {
    case "npm":
    case "pnpm":
      if (["install", "i", "ci", "add", "rebuild"].includes(commandName))
        return "install";
      if (["run", "run-script", "exec", "dlx"].includes(commandName)) {
        return packageScriptName(args) ?? commandName;
      }
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "yarn":
      if (["install", "add", "upgrade"].includes(commandName)) return "install";
      if (commandName === "run") return packageScriptName(args) ?? "run";
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "bun":
      if (["install", "add", "update"].includes(commandName)) return "install";
      if (["run", "x"].includes(commandName))
        return packageScriptName(args) ?? commandName;
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "pip":
      if (commandName === "install") return "install";
      if (commandName === "wheel") return "build";
      return null;
    case "cargo":
      return ["install", "build", "run", "test"].includes(commandName)
        ? commandName
        : null;
    case "brew":
      return ["install", "reinstall", "upgrade", "bundle"].includes(commandName)
        ? "install"
        : null;
    case "go":
      if (["install", "get"].includes(commandName)) return "install";
      return ["run", "build", "test"].includes(commandName)
        ? commandName
        : null;
    case "gem":
      return ["install", "build"].includes(commandName) ? commandName : null;
    case "composer":
      if (
        ["install", "update", "require", "create-project"].includes(commandName)
      ) {
        return "install";
      }
      if (["run-script", "exec"].includes(commandName))
        return packageScriptName(args) ?? commandName;
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "maven":
      return [
        "validate",
        "compile",
        "test",
        "package",
        "verify",
        "install",
        "deploy",
      ].includes(commandName)
        ? commandName
        : null;
    case "gradle":
      return ["build", "test", "check", "assemble", "publish", "run"].includes(
        commandName,
      )
        ? commandName
        : null;
    case "uv":
      if (commandName === "pip") {
        const pipCommand = args[0]?.toLowerCase();
        if (["install", "sync"].includes(pipCommand ?? "")) return "install";
        if (pipCommand === "compile") return "build";
        return null;
      }
      if (["add", "sync"].includes(commandName)) return "install";
      if (["run", "build", "test"].includes(commandName)) return commandName;
      if (commandName === "tool") {
        const toolCommand = args[0]?.toLowerCase();
        if (toolCommand === "install") return "install";
        if (toolCommand === "run") return "run";
      }
      return null;
    case "poetry":
      if (["install", "add", "update"].includes(commandName)) return "install";
      if (commandName === "run") return packageScriptName(args) ?? "run";
      return ["build", "test"].includes(commandName) ? commandName : null;
    case "pipenv":
      if (["install", "sync", "update"].includes(commandName)) return "install";
      if (commandName === "run") return packageScriptName(args) ?? "run";
      return null;
    case "dotnet":
      if (commandName === "restore") return "install";
      if (commandName === "add" && args[0]?.toLowerCase() === "package")
        return "install";
      return ["build", "test", "pack", "publish", "run"].includes(commandName)
        ? commandName
        : null;
    case "nuget":
      if (["install", "restore"].includes(commandName)) return "install";
      if (commandName === "pack") return "build";
      if (commandName === "push") return "publish";
      return null;
    case "swift":
      if (commandName === "package") {
        const packageCommand = args[0]?.toLowerCase();
        if (["resolve", "update"].includes(packageCommand ?? ""))
          return "install";
        return null;
      }
      return ["build", "test", "run"].includes(commandName)
        ? commandName
        : null;
    case "mix":
      if (["deps.get", "deps.update"].includes(commandName)) return "install";
      if (
        commandName === "deps" &&
        ["get", "update"].includes(args[0]?.toLowerCase() ?? "")
      ) {
        return "install";
      }
      if (commandName === "compile") return "build";
      return ["test", "release"].includes(commandName) ? commandName : null;
    default:
      return null;
  }
}

function packageScriptName(args: string[]): string | null {
  return args.find((arg) => !arg.startsWith("-") && !arg.includes("=")) ?? null;
}

function packageLifecyclePhase(value: string): boolean {
  return [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "build",
    "build.rs",
    "setup.py",
    "test",
  ].some((phase) => value.includes(phase));
}

function packageNameFromPackageCommand(
  manager: string,
  commandName: string,
  args: string[],
): string | undefined {
  switch (manager) {
    case "uv":
      if (["pip", "tool"].includes(commandName))
        return packageNameFromArgs(args.slice(1));
      return packageNameFromArgs(args);
    case "dotnet":
      if (commandName === "add" && args[0]?.toLowerCase() === "package") {
        return packageNameFromArgs(args.slice(1));
      }
      return packageNameFromArgs(args);
    case "swift":
      return commandName === "package"
        ? packageNameFromArgs(args.slice(1))
        : packageNameFromArgs(args);
    case "mix":
      return commandName === "deps"
        ? packageNameFromArgs(args.slice(1))
        : packageNameFromArgs(args);
    default:
      return packageNameFromArgs(args);
  }
}

function packageNameFromArgs(args: string[]): string | undefined {
  const packageArg = args.find((arg) => {
    const lower = arg.toLowerCase();
    return (
      !arg.startsWith("-") &&
      !arg.includes("=") &&
      arg !== "." &&
      arg !== "--" &&
      !packageLifecyclePhase(lower)
    );
  });
  return packageArg ? redactCommandPart(packageArg) : undefined;
}

function cloudCliArgsAreSensitive(provider: string, args: string[]): boolean {
  const joined = args.join(" ").toLowerCase();
  const operation = args[0]?.toLowerCase() ?? "";
  return (
    terraformCliArgsAreSensitive(provider, args, joined) ||
    (provider === "az" && operation === "login") ||
    [
      "secretsmanager get-secret-value",
      "ssm get-parameter",
      "ssm get-parameters",
      "iam create-access-key",
      "iam put-user-policy",
      "iam attach-user-policy",
      "ecr get-login-password",
      "eks update-kubeconfig",
      "codeartifact login",
      "sso login",
      "sts get-session-token",
      "sts assume-role",
      "auth login",
      "auth print-access-token",
      "auth application-default login",
      "auth configure-docker",
      "container clusters get-credentials",
      "secrets versions access",
      "iam service-accounts keys create",
      "keyvault secret show",
      "keyvault secret download",
      "account get-access-token",
      "acr login",
      "aks get-credentials",
      "ad app credential reset",
      "secret set",
      "secret put",
      "secret bulk",
      "secret list",
      "secret delete",
      "versions secret put",
      "versions secret bulk",
      "registry docker-config",
      "registry login",
      "kubernetes cluster kubeconfig save",
      "secrets set",
      "secrets import",
      "secrets unset",
      "secrets list",
      "tokens create",
      "tokens revoke",
      "auth token",
      "variable set",
      "variable update",
      "variable delete",
      "variable get",
      "variable list",
      "variable export",
      "variables",
      "secret get",
      "secret create",
      "secret update",
      "env pull",
      "env add",
      "env rm",
      "env remove",
      "env ls",
      "env:get",
      "env:list",
      "env:set",
      "env:import",
      "env:unset",
      "item get",
      "get item",
      "document get",
      "op://",
      "kv get",
      "read secret/",
      "token create",
      "secrets download",
      "configs tokens create",
      "config:get",
      "config:set",
      "secrets pull",
      "get secret",
      "describe secret",
      "config view --raw",
      "--show-secrets",
      "context store-secret",
      "context remove-secret",
      "runner token create",
      "runner token list",
      "secret add",
      "secret rm",
      "secret remove",
      "auth create-token",
      "encrypt --secret",
      "context create",
      "login --api-key",
      "listen --print-secret",
    ].some((needle) => joined.includes(needle)) ||
    args.some((arg) => {
      const lower = arg.toLowerCase();
      return (
        lower.includes("secret") ||
        lower.includes("token") ||
        lower.includes("credential") ||
        lower.includes("access-key") ||
        lower === "iam" ||
        lower === "sts" ||
        lower === "keyvault"
      );
    })
  );
}

function terraformCliArgsAreSensitive(
  provider: string,
  args: string[],
  joined: string,
): boolean {
  if (!["terraform", "terragrunt", "opentofu"].includes(provider)) return false;
  return (
    [
      "login",
      "output -json",
      "output -raw",
      "state pull",
      "state show",
      "show -json",
      "run-all output",
      "run-all state",
    ].some((needle) => joined.includes(needle)) ||
    args.some((arg) => {
      const lower = arg.toLowerCase();
      return (
        lower.includes("tf_token") ||
        lower.includes("terraform_cloud_token") ||
        lower.includes("terraform_token") ||
        lower.includes("tfe_token")
      );
    })
  );
}

function firstNonOptionArgIndex(args: string[]): number | null {
  let index = 0;
  while (index < args.length) {
    const arg = args[index];
    if (!arg) return null;
    if (arg === "--") return index + 1 < args.length ? index + 1 : null;
    if (shellAssignment(arg)) {
      index += 1;
      continue;
    }
    if (arg.startsWith("--")) {
      index += optionTakesValue(arg) && !arg.includes("=") ? 2 : 1;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      index += shortOptionTakesValue(arg) ? 2 : 1;
      continue;
    }
    return index;
  }
  return null;
}

function optionTakesValue(arg: string): boolean {
  return [
    "--prefix",
    "--cwd",
    "--directory",
    "--project",
    "--profile",
    "--region",
    "--subscription",
    "--account",
    "--configuration",
    "--workspace",
  ].includes(arg);
}

function shortOptionTakesValue(arg: string): boolean {
  return ["-C", "-p", "-r", "-c", "-m"].includes(arg);
}

function shellAssignment(arg: string): boolean {
  const [name, value] = arg.split("=", 2);
  return Boolean(name && value && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
}

function executableName(value: string): string {
  const basename = value.split(/[\\/]/).pop() ?? value;
  return basename.replace(/\.(exe|cmd|bat)$/i, "").toLowerCase();
}

function credentialNameFromPath(path: string, fallback: string): string {
  const trimmed = path.replace(/[/\\]+$/, "");
  const basename = trimmed.split(/[\\/]/).pop();
  return basename && basename !== "." && basename !== "/" ? basename : fallback;
}

function metadataString(metadata: unknown, keys: string[]): string | undefined {
  const record = asRecord(metadata);
  if (!record) return undefined;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string") {
      const trimmed = trimmedString(value);
      if (trimmed) return trimmed;
    }
  }
  return undefined;
}

function metadataStringFromSources(
  sources: unknown[],
  keys: string[],
): string | undefined {
  for (const source of sources) {
    const value = metadataString(source, keys);
    if (value) return value;
  }
  return undefined;
}

function metadataScalarFromSources(
  sources: unknown[],
  keys: string[],
): string | number | boolean | undefined {
  for (const source of sources) {
    const record = asRecord(source);
    if (!record) continue;
    for (const key of keys) {
      const value = record[key];
      if (typeof value === "string") {
        const trimmed = trimmedString(value);
        if (trimmed) return trimmed;
      }
      if (typeof value === "number" && Number.isFinite(value)) return value;
      if (typeof value === "boolean") return value;
    }
  }
  return undefined;
}

function metadataIntegerFromSources(
  sources: unknown[],
  keys: string[],
): number | undefined {
  for (const source of sources) {
    const record = asRecord(source);
    if (!record) continue;
    for (const key of keys) {
      const value = record[key];
      if (typeof value === "number" && Number.isInteger(value) && value >= 0)
        return value;
      if (typeof value === "string") {
        const trimmed = trimmedString(value);
        if (!trimmed || !/^\d+$/.test(trimmed)) continue;
        const parsed = Number(trimmed);
        if (Number.isSafeInteger(parsed)) return parsed;
      }
    }
  }
  return undefined;
}

function developerActivityProcessFromMetadata(
  sources: unknown[],
): Record<string, unknown> | undefined {
  const process: Record<string, unknown> = {};

  const processGuid = metadataStringFromSources(sources, [
    "processGuid",
    "process_guid",
    "endpointProcessGuid",
    "endpoint_process_guid",
    "entityId",
    "entity_id",
  ]);
  if (processGuid) process.processGuid = processGuid;

  const parentProcessGuid = metadataStringFromSources(sources, [
    "parentProcessGuid",
    "parent_process_guid",
    "parentEntityId",
    "parent_entity_id",
  ]);
  if (parentProcessGuid) process.parentProcessGuid = parentProcessGuid;

  const pid = metadataIntegerFromSources(sources, [
    "pid",
    "processPid",
    "process_pid",
  ]);
  if (pid !== undefined) process.pid = pid;

  const ppid = metadataIntegerFromSources(sources, [
    "ppid",
    "parentPid",
    "parent_pid",
    "processPpid",
    "process_ppid",
  ]);
  if (ppid !== undefined) process.ppid = ppid;

  const image = metadataStringFromSources(sources, [
    "processImage",
    "process_image",
    "image",
    "executablePath",
    "executable_path",
  ]);
  if (image) process.image = image;

  const commandLine = metadataStringFromSources(sources, [
    "processCommandLine",
    "process_command_line",
    "commandLine",
    "command_line",
  ]);
  if (commandLine) process.commandLine = redactCommandLine(commandLine);

  const cwd = metadataStringFromSources(sources, [
    "processCwd",
    "process_cwd",
    "cwd",
    "workingDirectory",
    "working_directory",
  ]);
  if (cwd) process.cwd = cwd;

  return Object.keys(process).length > 0
    ? sanitizedBrowserProcess(process)
    : undefined;
}

function developerActivityCorrelationMetadata(
  ...sources: unknown[]
): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  const policyEpoch = metadataScalarFromSources(sources, [
    "policyEpoch",
    "policy_epoch",
    "policyBundleEpoch",
    "policy_bundle_epoch",
  ]);
  if (policyEpoch !== undefined) metadata.policyEpoch = policyEpoch;

  const policyVersion = metadataStringFromSources(sources, [
    "policyVersion",
    "policy_version",
  ]);
  if (policyVersion) metadata.policyVersion = policyVersion;

  const policyHash = metadataStringFromSources(sources, [
    "policyHash",
    "policy_hash",
  ]);
  if (policyHash) metadata.policyHash = policyHash;

  const toolCallId = metadataStringFromSources(sources, [
    "toolCallId",
    "tool_call_id",
  ]);
  if (toolCallId) metadata.toolCallId = toolCallId;

  return metadata;
}

function trimmedString(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
