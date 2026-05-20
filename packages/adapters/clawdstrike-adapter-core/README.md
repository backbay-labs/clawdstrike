# @clawdstrike/adapter-core

Framework-agnostic adapter interfaces for Clawdstrike tool-boundary enforcement.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for the integration contract (and what requires a sandbox/broker).

## Installation

```bash
npm install @clawdstrike/adapter-core
```

## Usage

```ts
import { BaseToolInterceptor, createSecurityContext } from "@clawdstrike/adapter-core";

// Create an engine for policy evaluation (implementation-specific).
// Use @clawdstrike/engine-local (shell out to `hush`) or
// @clawdstrike/engine-remote (HTTP calls to hushd daemon).
const engine = /* ... */;

const interceptor = new BaseToolInterceptor(engine, { blockOnViolation: true });
const ctx = createSecurityContext({ sessionId: "session-123" });

const preflight = await interceptor.beforeExecute("bash", { cmd: "echo hello" }, ctx);
if (!preflight.proceed) throw new Error("Blocked by policy");
```

## Local EDR evidence feed

`BaseToolInterceptor` can optionally publish best-effort `PolicyEvent`
telemetry to a local ClawdStrike agent. This is disabled by default; enable it
explicitly through config or `CLAWDSTRIKE_ADAPTER_CORE_EDR=1` plus a local
agent token.

```ts
const interceptor = new BaseToolInterceptor(engine, {
  blockOnViolation: true,
  edr: {
    enabled: true,
    token: process.env.CLAWDSTRIKE_AGENT_TOKEN,
    agentUrl: "http://127.0.0.1:9878",
  },
});
```

When enabled, pre-execution policy decisions are posted to
`/api/v1/agent/edr/policy-events` with adapter-core collector metadata and
scrubbed payloads. Post-execution result telemetry is emitted as a custom
`adapter_core_tool_result` event with raw inputs and outputs omitted; it records
only structural summaries and redaction counts. Command executions that look
like package-manager lifecycle commands, including npm/pnpm/yarn/Bun, pip,
Cargo, Go, Homebrew, RubyGems, Composer, Maven, Gradle, uv, Poetry, Pipenv,
.NET/NuGet, SwiftPM, and Mix command forms, package-registry credential commands,
or sensitive cloud-CLI operations are also posted to
`/api/v1/agent/edr/developer-activity` as normalized developer-activity facts
with command tokens redacted, including developer platform secret commands such
as Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Bitwarden item reads,
Sentry and Snyk auth-token commands, AWS Secrets Manager/SSM/ECR/EKS/CodeArtifact
credential operations, GCP Secret Manager/service-account key/auth/Docker/cluster
credential operations, Azure Key Vault/access-token/app-credential/ACR/AKS/login
operations, Docker registry login, pip index
credential config reads, Cargo registry auth commands, RubyGems registry auth
commands, Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI secret or token commands, and
Terraform/Terragrunt/OpenTofu state, output, or login commands. Generic tool-call
policy events are posted as `mcp_tool` developer-activity facts with parameters
scrubbed for content-like and secret-like fields. Shell commands and
direct file-read/file-write policy events that touch credential-looking paths
for repo secrets, CI tokens, local API keys, and browser-cookie stores, plus
macOS Keychain password reads through `security`, local password-store reads through `pass`,
SSH-agent key enumeration through `ssh-add`, Git credential-helper reads through `git credential`,
and Docker registry credential reads through `docker-credential-*` and `~/.docker/config.json`,
and Cargo registry credential file reads through `~/.cargo/credentials*`,
and RubyGems registry credential file reads through `~/.gem/credentials`,
and developer CLI token-store reads such as `~/.config/gh/hosts.yml` and
`~/.config/glab-cli/config.yml`,
cloud credential stores such as `~/.kube/config`,
`~/.terraform.d/credentials.tfrc.json`, and `~/.config/pulumi/credentials.json`,
broader package-manager credential stores such as `~/.yarnrc.yml`,
`~/.config/pip/pip.conf`, `~/.config/pypoetry/auth.toml`, `~/.m2/settings.xml`,
`~/.gradle/gradle.properties`, and `~/.nuget/NuGet/NuGet.Config`,
and local signing/decryption key stores such as `~/.config/sops/age/keys.txt`
and `~/.gnupg/private-keys-v1.d/*.key`,
plus translated `secret_access` policy events,
are emitted as credential-access
developer activity. `launchctl`, `crontab`, and `systemctl` persistence
operations, direct LaunchAgent/LaunchDaemon plist writes, and shell-startup file
writes are emitted as `persistence_change` developer activity without uploading
file contents. Direct `network_egress` policy events are emitted as redacted
network developer activity with protocol, host, port, method, and URL path while omitting
request bodies and URL secrets. Ordinary `file_read` and `file_write` policy events are emitted
as raw-content-omitting file developer activity with computed text/binary/base64 or supplied content hashes after credential and persistence
specialization, and `patch_apply` policy events are emitted as raw-patch-omitting
patch developer activity with file path, patch byte count, and computed or supplied patch hash. Shell/file touches of ClawdStrike-specific standard honey
artifact paths, such as the local internal-hosts deception file, carry
deception metadata so the local agent's registered honey artifact registry can
fire `deception.honey_artifact_touched` without uploading file contents. Other command executions are
posted as redacted `shell_command` facts so shell-agent activity reaches the
local flight recorder even when it does not match a higher-specificity
classifier. Shell network utilities such as `curl`, `wget`, `dig`,
`nslookup`, `host`, `ping`, `ssh`, and `scp` that target hostnames are emitted
as `dns_lookup` facts with secret-bearing URLs redacted; standard planted
internal hostnames carry a deception detection hint for the local honey
registry. Developer-activity facts carry available endpoint and runtime
correlation fields from the `SecurityContext`, including host, user, session,
agent, workload, approval, process GUID, parent process GUID, pid/ppid,
process image, redacted process command line, cwd, policy epoch, policy
version, and policy hash metadata. Set
`includeResults: false` to disable result telemetry,
`includeDeveloperActivity: false` to disable normalized command enrichment, or
`includeAllowed: false` to omit allowed pre-execution decisions.

The package also ships `clawdstrike-package-lifecycle`, a best-effort
npm/pnpm/yarn/Bun lifecycle hook for `preinstall`, `install`, `postinstall`,
`prepare`, and similar scripts. It reads package-manager environment variables
such as `npm_lifecycle_event`, `npm_lifecycle_script`, `npm_package_name`,
`npm_config_user_agent`, and `INIT_CWD`, redacts secrets in the lifecycle
script, and posts a `package_script` event to
`/api/v1/agent/edr/package-manager/events`. Capture failures are swallowed so
dependency installation is not broken by local EDR availability.

Set `CLAWDSTRIKE_PACKAGE_LIFECYCLE_ENFORCEMENT=block` when the hook is wired as
an enforcement gate instead of passive telemetry. In blocking mode, the hook
exits non-zero if local EDR is unavailable, returns a non-2xx response, or
records package-script findings in the response payload. This is the mode to use
for guarded CI, controlled developer workstations, or package-manager wrappers
that must fail closed on risky lifecycle scripts.

For language-package ecosystems that do not expose npm-compatible lifecycle
environment, wrappers can call the same hook with
`CLAWDSTRIKE_PACKAGE_MANAGER` (`pip`, `cargo`, `gem`, `go`, `brew`,
`composer`, `maven`, `gradle`, `uv`, `poetry`, `pipenv`, `dotnet`, `nuget`,
`swift`, or `mix`),
`CLAWDSTRIKE_PACKAGE_PHASE`,
`CLAWDSTRIKE_PACKAGE_SCRIPT`, `CLAWDSTRIKE_PACKAGE_NAME`, and
`CLAWDSTRIKE_PACKAGE_WORKING_DIR`. Cargo build-script environments can also be
inferred from `CARGO_MANIFEST_DIR` / `CARGO_PKG_NAME`; explicit values take
precedence when present. RubyGems native-extension/install wrappers can use
the explicit environment path to submit redacted `gem install` lifecycle
evidence; Go module/build wrappers and Homebrew formula/install wrappers can
use the same path for redacted `go` and `brew` lifecycle evidence, and
Composer/JVM/Python/.NET/SwiftPM/Elixir wrappers can submit equivalent
redacted package-manager lifecycle evidence through the same metadata contract.

Repo scanners can publish credential-path findings with
`publishRepoScannerCredentialFindingToLocalEdr()`. The publisher emits
developer-activity facts such as `repo_secret`, `ci_token`, `local_api_key`, or
`browser_cookie` with path, rule, confidence, repository, and identity metadata,
but intentionally drops raw secret values before posting to the local agent.
For local filesystem scans, `scanRepositoryCredentialPathsForLocalEdr()` walks a
repository, skips dependency/build directories, classifies credential-looking
paths, and publishes the same metadata-only findings without reading file
contents.

CI workers can publish token-context evidence with
`publishCiAgentEnvironmentToLocalEdr()`. It recognizes common GitHub Actions,
GitLab CI, Buildkite, CircleCI, Azure Pipelines, Bitbucket Pipelines, Jenkins,
TeamCity, Travis CI, Drone CI, Semaphore CI, AppVeyor, Woodpecker CI, and
Codefresh environment metadata, emits `ci_token`
developer-activity facts for known token variable names, and omits every token
value from the payload. CI jobs can run the same publisher through the
`clawdstrike-ci-env` executable.

Browser automation runtimes can publish local flight-recorder evidence with
`publishBrowserRuntimeActivityToLocalEdr()`. The publisher normalizes browser
automation actions, downloads, and extension installs into
`browser_automation`, `browser_download`, and `browser_extension`
developer-activity facts, carries host/user/session/agent/workload/approval and
tool-call correlation fields, infers common browser identities from profile or
extension paths when collectors omit the browser field, scrubs parameters and
URLs, carries optional download content hashes and byte counts, and omits raw
prompt, page, result, and artifact bodies before posting to the local agent.
The local agent stores those download proof fields on the durable
`browser_download` observation and causal-graph node, not only in transient
publisher metadata.
Translated CUA `PolicyEvent`s flowing through `BaseToolInterceptor` are also
emitted as scrubbed `browser_automation` developer activity, so provider
wrappers that use the shared Claude/OpenAI-style CUA translators get local
flight-recorder evidence without separate runtime glue. CUA file-transfer
actions preserve bounded browser, path, source URL, and transfer-size metadata
so downloads can become `browser_download` facts after local scrubbing.

When `inbound.enabled` is also set, inbound message decisions are emitted as
privacy-preserving custom `PolicyEvent` records with message content omitted,
message and sanitized-replacement hashes recorded, and sender names hashed
instead of uploaded raw.

Environment variables:

- `CLAWDSTRIKE_ADAPTER_CORE_EDR=1`
- `CLAWDSTRIKE_AGENT_TOKEN`
- `CLAWDSTRIKE_POLICY_EVENTS_URL` for an explicit endpoint, or
  `CLAWDSTRIKE_AGENT_URL` for the local agent base URL
- `CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL` for an explicit normalized
  developer-activity endpoint
- `CLAWDSTRIKE_PACKAGE_MANAGER_EVENTS_URL` for an explicit package-manager
  lifecycle endpoint
- `CLAWDSTRIKE_ADAPTER_CORE_EDR_TIMEOUT_MS` for the best-effort POST timeout

## Generic tool runner wrapper

`@clawdstrike/adapter-core` can also wrap any `(toolName, input, runId) => Promise<output>`
dispatcher directly:

```ts
import { GenericToolBoundary, wrapGenericToolDispatcher } from '@clawdstrike/adapter-core';

// Use @clawdstrike/engine-local or @clawdstrike/engine-remote:
const engine = /* createStrikeCell({ policyRef: 'default' }) */;
const boundary = new GenericToolBoundary({ engine });

const dispatchTool = wrapGenericToolDispatcher(
  boundary,
  async (toolName, input, runId) => {
    return { toolName, input, runId };
  },
);

await dispatchTool('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
console.log(boundary.getAuditEvents().length);
```
