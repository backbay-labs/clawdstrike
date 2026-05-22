import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { publishCiAgentEnvironmentToLocalEdr } from "./ci-agent-telemetry.js";

describe("CI agent local EDR telemetry", () => {
  it("publishes GitHub Actions token context without raw token values", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await publishCiAgentEnvironmentToLocalEdr({
      env: {
        GITHUB_ACTIONS: "true",
        GITHUB_TOKEN: "ghp_MY_RAW_SECRET",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-MY_RAW_SECRET",
        GITHUB_RUN_ID: "123456",
        GITHUB_JOB: "build",
        GITHUB_WORKFLOW: "ci",
        GITHUB_REPOSITORY: "acme/repo",
        GITHUB_ACTOR: "alice",
        RUNNER_NAME: "runner-01",
      },
      hostId: "host-ci-1",
      sessionId: "session-ci-1",
      agentId: "agent-ci-1",
      config: {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    });

    expect(result).toMatchObject({
      provider: "github_actions",
      tokenNameCount: 2,
      publishedTokenCount: 2,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const payloads = fetchMock.mock.calls.map(([url, init]) => {
      expect(url).toBe("http://agent.test/api/v1/agent/edr/developer-activity");
      return JSON.parse(String(init?.body)) as { activities: any[] };
    });
    const activities = payloads.map((payload) => payload.activities[0]);
    expect(activities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          hostId: "host-ci-1",
          sessionId: "session-ci-1",
          agentId: "agent-ci-1",
          userId: "alice",
          workloadId: "ci/build",
          kind: "ci_token",
          path: "env:GITHUB_TOKEN",
          name: "GITHUB_TOKEN",
          credentialKind: "api_token",
          commandLine: "ci_env github_actions GITHUB_TOKEN",
          metadata: expect.objectContaining({
            collectorKind: "ci_agent_environment",
            ciProvider: "github_actions",
            ciRunId: "123456",
            ciJob: "build",
            ciWorkflow: "ci",
            ciRepository: "acme/repo",
            ciActor: "alice",
            tokenName: "GITHUB_TOKEN",
            tokenValueOmitted: true,
            payloadScrubbed: true,
          }),
        }),
        expect.objectContaining({
          path: "env:ACTIONS_ID_TOKEN_REQUEST_TOKEN",
          name: "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
          metadata: expect.objectContaining({
            tokenName: "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            tokenValueOmitted: true,
          }),
        }),
      ]),
    );
    expect(JSON.stringify(payloads)).not.toContain("MY_RAW_SECRET");
  });

  it("publishes additional CI provider token contexts without raw token values", async () => {
    const cases = [
      {
        provider: "azure_pipelines",
        tokenName: "SYSTEM_ACCESSTOKEN",
        env: {
          TF_BUILD: "True",
          SYSTEM_ACCESSTOKEN: "ado-MY_RAW_SECRET",
          BUILD_BUILDID: "1001",
          SYSTEM_JOBDISPLAYNAME: "build linux",
          BUILD_DEFINITIONNAME: "ci",
          BUILD_REPOSITORY_NAME: "acme/service",
          BUILD_REQUESTEDFOR: "alice",
          AGENT_NAME: "ado-agent-1",
        },
        expected: {
          sessionId: "1001",
          userId: "alice",
          workloadId: "ci/build linux",
          agentId: "ado-agent-1",
          repository: "acme/service",
        },
      },
      {
        provider: "bitbucket_pipelines",
        tokenName: "BITBUCKET_STEP_OIDC_TOKEN",
        env: {
          BITBUCKET_BUILD_NUMBER: "42",
          BITBUCKET_PIPELINE_UUID: "{pipeline-uuid}",
          BITBUCKET_STEP_UUID: "{step-uuid}",
          BITBUCKET_REPO_FULL_NAME: "acme/service",
          BITBUCKET_STEP_TRIGGERER_UUID: "{user-uuid}",
          BITBUCKET_STEP_OIDC_TOKEN: "bb-MY_RAW_SECRET",
        },
        expected: {
          sessionId: "{pipeline-uuid}",
          userId: "{user-uuid}",
          workloadId: "ci/{step-uuid}",
          repository: "acme/service",
        },
      },
      {
        provider: "jenkins",
        tokenName: "JENKINS_API_TOKEN",
        env: {
          JENKINS_URL: "https://jenkins.example.invalid",
          BUILD_TAG: "jenkins-service-99",
          JOB_NAME: "service/main",
          JOB_BASE_NAME: "main",
          GIT_URL: "https://example.invalid/acme/service.git",
          BUILD_USER_ID: "alice",
          NODE_NAME: "agent-1",
          JENKINS_API_TOKEN: "jenkins-MY_RAW_SECRET",
        },
        expected: {
          sessionId: "jenkins-service-99",
          userId: "alice",
          workloadId: "ci/service/main",
          agentId: "agent-1",
          repository: "https://example.invalid/acme/service.git",
        },
      },
      {
        provider: "teamcity",
        tokenName: "TEAMCITY_TOKEN",
        env: {
          TEAMCITY_VERSION: "2026.05",
          BUILD_ID: "tc-build-1",
          TEAMCITY_BUILDCONF_NAME: "Service Build",
          TEAMCITY_PROJECT_NAME: "Acme",
          BUILD_VCS_NUMBER: "abcdef",
          AGENT_NAME: "tc-agent-1",
          TEAMCITY_TOKEN: "tc-MY_RAW_SECRET",
        },
        expected: {
          sessionId: "tc-build-1",
          workloadId: "ci/Service Build",
          agentId: "tc-agent-1",
          repository: "abcdef",
        },
      },
      {
        provider: "travis_ci",
        tokenName: "TRAVIS_TOKEN",
        env: {
          TRAVIS: "true",
          TRAVIS_BUILD_ID: "travis-build-1",
          TRAVIS_JOB_ID: "travis-job-1",
          TRAVIS_EVENT_TYPE: "push",
          TRAVIS_REPO_SLUG: "acme/service",
          TRAVIS_TRIGGERED_BY: "alice",
          TRAVIS_OS_NAME: "linux",
          TRAVIS_TOKEN: "travis-MY_RAW_SECRET",
        },
        expected: {
          sessionId: "travis-build-1",
          userId: "alice",
          workloadId: "ci/travis-job-1",
          agentId: "linux",
          repository: "acme/service",
        },
      },
      {
        provider: "drone_ci",
        tokenName: "DRONE_TOKEN",
        env: {
          DRONE: "true",
          DRONE_TOKEN: "drone-MY_RAW_SECRET",
          DRONE_BUILD_NUMBER: "314",
          DRONE_STEP_NAME: "publish",
          DRONE_BUILD_EVENT: "push",
          DRONE_REPO: "acme/service",
          DRONE_COMMIT_AUTHOR: "alice",
          DRONE_SYSTEM_HOST: "drone-runner-1",
        },
        expected: {
          sessionId: "314",
          userId: "alice",
          workloadId: "ci/publish",
          agentId: "drone-runner-1",
          repository: "acme/service",
        },
      },
      {
        provider: "semaphore_ci",
        tokenName: "SEMAPHORE_OIDC_TOKEN",
        env: {
          SEMAPHORE: "true",
          SEMAPHORE_OIDC_TOKEN: "semaphore-MY_RAW_SECRET",
          SEMAPHORE_WORKFLOW_ID: "workflow-123",
          SEMAPHORE_JOB_NAME: "deploy",
          SEMAPHORE_WORKFLOW_NAME: "release",
          SEMAPHORE_GIT_REPO_SLUG: "acme/service",
          SEMAPHORE_GIT_COMMIT_AUTHOR: "alice",
          SEMAPHORE_AGENT_MACHINE_TYPE: "e2-standard-2",
        },
        expected: {
          sessionId: "workflow-123",
          userId: "alice",
          workloadId: "ci/deploy",
          agentId: "e2-standard-2",
          repository: "acme/service",
        },
      },
      {
        provider: "appveyor",
        tokenName: "APPVEYOR_API_TOKEN",
        env: {
          APPVEYOR: "True",
          APPVEYOR_API_TOKEN: "appveyor-MY_RAW_SECRET",
          APPVEYOR_BUILD_ID: "build-456",
          APPVEYOR_JOB_ID: "job-456",
          APPVEYOR_PROJECT_NAME: "service",
          APPVEYOR_REPO_NAME: "acme/service",
          APPVEYOR_REPO_COMMIT_AUTHOR: "alice",
          APPVEYOR_BUILD_WORKER_IMAGE: "Visual Studio 2022",
        },
        expected: {
          sessionId: "build-456",
          userId: "alice",
          workloadId: "ci/job-456",
          agentId: "Visual Studio 2022",
          repository: "acme/service",
        },
      },
      {
        provider: "woodpecker_ci",
        tokenName: "WOODPECKER_TOKEN",
        env: {
          WOODPECKER: "true",
          WOODPECKER_TOKEN: "woodpecker-MY_RAW_SECRET",
          CI_PIPELINE_NUMBER: "789",
          CI_STEP_NAME: "test",
          CI_PIPELINE_EVENT: "pull_request",
          CI_REPO: "acme/service",
          CI_COMMIT_AUTHOR: "alice",
          CI_SYSTEM_HOST: "woodpecker-runner-1",
        },
        expected: {
          sessionId: "789",
          userId: "alice",
          workloadId: "ci/test",
          agentId: "woodpecker-runner-1",
          repository: "acme/service",
        },
      },
      {
        provider: "codefresh",
        tokenName: "CODEFRESH_API_KEY",
        env: {
          CODEFRESH_API_KEY: "codefresh-MY_RAW_SECRET",
          CF_BUILD_ID: "cf-build-123",
          CF_STEP_NAME: "deploy",
          CF_PIPELINE_NAME: "release",
          CF_REPO_OWNER: "acme",
          CF_REPO_NAME: "service",
          CF_BUILD_INITIATOR: "alice",
          CF_BUILD_TRIGGER: "git",
        },
        expected: {
          sessionId: "cf-build-123",
          userId: "alice",
          workloadId: "ci/deploy",
          agentId: "git",
          repository: "acme/service",
        },
      },
    ];

    for (const testCase of cases) {
      const fetchMock = vi.fn(async () => ({ ok: true }));
      vi.stubGlobal("fetch", fetchMock);

      const result = await publishCiAgentEnvironmentToLocalEdr({
        env: testCase.env,
        config: {
          enabled: true,
          token: "local-token",
          agentUrl: "http://agent.test",
          timeoutMs: 500,
        },
      });

      expect(result).toMatchObject({
        provider: testCase.provider,
        tokenNameCount: 1,
        publishedTokenCount: 1,
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(url).toBe("http://agent.test/api/v1/agent/edr/developer-activity");
      const payload = JSON.parse(String(init.body)) as { activities: any[] };
      const expected = testCase.expected as {
        sessionId?: string;
        userId?: string;
        workloadId?: string;
        agentId?: string;
        repository?: string;
      };
      expect(payload.activities[0]).toMatchObject({
        kind: "ci_token",
        path: `env:${testCase.tokenName}`,
        name: testCase.tokenName,
        credentialKind: "api_token",
        commandLine: `ci_env ${testCase.provider} ${testCase.tokenName}`,
        ...(expected.sessionId ? { sessionId: expected.sessionId } : {}),
        ...(expected.userId ? { userId: expected.userId } : {}),
        ...(expected.workloadId ? { workloadId: expected.workloadId } : {}),
        ...(expected.agentId ? { agentId: expected.agentId } : {}),
        metadata: expect.objectContaining({
          collectorKind: "ci_agent_environment",
          ciProvider: testCase.provider,
          ciRepository: expected.repository,
          tokenName: testCase.tokenName,
          tokenValueOmitted: true,
          payloadScrubbed: true,
          shellClassifier: "ci_token_environment",
        }),
      });
      expect(JSON.stringify(payload)).not.toContain("MY_RAW_SECRET");
    }
  });

  it("ships a CI environment executable for job wrappers", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { bin?: Record<string, string> };

    expect(packageJson.bin?.["clawdstrike-ci-env"]).toBe("./dist/ci-agent-environment-hook.js");

    const entrypoint = await readFile(
      new URL("./ci-agent-environment-hook.ts", import.meta.url),
      "utf8",
    );
    expect(entrypoint).toContain("publishCiAgentEnvironmentToLocalEdr");
  });
});
