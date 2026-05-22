import type { LocalEdrConfig } from "./local-edr-publisher.js";
import { publishDeveloperActivityToLocalEdr } from "./local-edr-publisher.js";

export interface CiAgentEnvironmentInput {
  env?: Record<string, string | undefined>;
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  config?: LocalEdrConfig;
}

export interface CiAgentEnvironmentPublishResult {
  provider?: string;
  tokenNameCount: number;
  publishedTokenCount: number;
}

type CiProviderContext = {
  provider: string;
  runId?: string;
  job?: string;
  workflow?: string;
  repository?: string;
  actor?: string;
  runnerName?: string;
};

const CI_TOKEN_ENV_NAMES = [
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "APPVEYOR_API_TOKEN",
  "APPVEYOR_TOKEN",
  "AZURE_DEVOPS_EXT_PAT",
  "BITBUCKET_ACCESS_TOKEN",
  "BITBUCKET_STEP_OIDC_TOKEN",
  "BITBUCKET_TOKEN",
  "BUILDKITE_AGENT_ACCESS_TOKEN",
  "CIRCLE_TOKEN",
  "CIRCLECI_API_TOKEN",
  "CODEFRESH_API_KEY",
  "CF_API_KEY",
  "CI_JOB_TOKEN",
  "DRONE_NETRC_PASSWORD",
  "DRONE_TOKEN",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITLAB_TOKEN",
  "JENKINS_API_TOKEN",
  "JENKINS_TOKEN",
  "NPM_TOKEN",
  "SEMAPHORE_API_TOKEN",
  "SEMAPHORE_OIDC_TOKEN",
  "SYSTEM_ACCESSTOKEN",
  "TEAMCITY_TOKEN",
  "TRAVIS_TOKEN",
  "WOODPECKER_TOKEN",
] as const;

export async function publishCiAgentEnvironmentToLocalEdr(
  input: CiAgentEnvironmentInput = {},
): Promise<CiAgentEnvironmentPublishResult> {
  const env = input.env ?? processEnv();
  const context = ciProviderContext(env);
  const tokenNames = CI_TOKEN_ENV_NAMES.filter((name) => Boolean(trimmed(env[name])));
  const result: CiAgentEnvironmentPublishResult = {
    provider: context?.provider,
    tokenNameCount: tokenNames.length,
    publishedTokenCount: 0,
  };
  if (!context) return result;

  for (const tokenName of tokenNames) {
    await publishDeveloperActivityToLocalEdr(
      {
        hostId: trimmed(input.hostId),
        userId: trimmed(input.userId) ?? context.actor,
        sessionId: trimmed(input.sessionId) ?? context.runId,
        agentId: trimmed(input.agentId) ?? context.runnerName,
        workloadId: trimmed(input.workloadId) ?? ciWorkloadId(context),
        approvalId: trimmed(input.approvalId),
        kind: "ci_token",
        path: `env:${tokenName}`,
        name: tokenName,
        credentialKind: "api_token",
        commandLine: `ci_env ${context.provider} ${tokenName}`,
        metadata: {
          collectorKind: "ci_agent_environment",
          ciProvider: context.provider,
          ciRunId: context.runId,
          ciJob: context.job,
          ciWorkflow: context.workflow,
          ciRepository: context.repository,
          ciActor: context.actor,
          ciRunnerName: context.runnerName,
          tokenName,
          tokenValueOmitted: true,
          payloadScrubbed: true,
          shellClassifier: "ci_token_environment",
        },
      },
      input.config,
    );
    result.publishedTokenCount += 1;
  }

  return result;
}

function ciProviderContext(env: Record<string, string | undefined>): CiProviderContext | null {
  if (truthy(env.GITHUB_ACTIONS)) {
    return {
      provider: "github_actions",
      runId: trimmed(env.GITHUB_RUN_ID),
      job: trimmed(env.GITHUB_JOB),
      workflow: trimmed(env.GITHUB_WORKFLOW),
      repository: trimmed(env.GITHUB_REPOSITORY),
      actor: trimmed(env.GITHUB_ACTOR),
      runnerName: trimmed(env.RUNNER_NAME),
    };
  }
  if (truthy(env.GITLAB_CI)) {
    return {
      provider: "gitlab_ci",
      runId: trimmed(env.CI_PIPELINE_ID),
      job: trimmed(env.CI_JOB_NAME),
      workflow: trimmed(env.CI_PIPELINE_SOURCE),
      repository: trimmed(env.CI_PROJECT_PATH),
      actor: trimmed(env.GITLAB_USER_LOGIN),
      runnerName: trimmed(env.CI_RUNNER_DESCRIPTION),
    };
  }
  if (truthy(env.BUILDKITE)) {
    return {
      provider: "buildkite",
      runId: trimmed(env.BUILDKITE_BUILD_ID),
      job: trimmed(env.BUILDKITE_LABEL) ?? trimmed(env.BUILDKITE_COMMAND),
      workflow: trimmed(env.BUILDKITE_PIPELINE_SLUG),
      repository: trimmed(env.BUILDKITE_REPO),
      actor: trimmed(env.BUILDKITE_BUILD_CREATOR),
      runnerName: trimmed(env.BUILDKITE_AGENT_NAME),
    };
  }
  if (truthy(env.CIRCLECI)) {
    return {
      provider: "circleci",
      runId: trimmed(env.CIRCLE_WORKFLOW_ID) ?? trimmed(env.CIRCLE_BUILD_NUM),
      job: trimmed(env.CIRCLE_JOB),
      workflow: trimmed(env.CIRCLE_WORKFLOW_ID),
      repository: [trimmed(env.CIRCLE_PROJECT_USERNAME), trimmed(env.CIRCLE_PROJECT_REPONAME)]
        .filter(Boolean)
        .join("/"),
      actor: trimmed(env.CIRCLE_USERNAME),
    };
  }
  if (truthy(env.TF_BUILD)) {
    return {
      provider: "azure_pipelines",
      runId: trimmed(env.BUILD_BUILDID) ?? trimmed(env.BUILD_BUILDNUMBER),
      job: trimmed(env.SYSTEM_JOBDISPLAYNAME) ?? trimmed(env.AGENT_JOBNAME),
      workflow: trimmed(env.BUILD_DEFINITIONNAME),
      repository: trimmed(env.BUILD_REPOSITORY_NAME),
      actor: trimmed(env.BUILD_REQUESTEDFOR),
      runnerName: trimmed(env.AGENT_NAME),
    };
  }
  if (truthy(env.BITBUCKET_BUILD_NUMBER) || trimmed(env.BITBUCKET_PIPELINE_UUID)) {
    return {
      provider: "bitbucket_pipelines",
      runId: trimmed(env.BITBUCKET_PIPELINE_UUID) ?? trimmed(env.BITBUCKET_BUILD_NUMBER),
      job: trimmed(env.BITBUCKET_STEP_UUID),
      workflow: trimmed(env.BITBUCKET_DEPLOYMENT_ENVIRONMENT),
      repository: trimmed(env.BITBUCKET_REPO_FULL_NAME),
      actor: trimmed(env.BITBUCKET_STEP_TRIGGERER_UUID),
      runnerName: trimmed(env.BITBUCKET_RUNNER_UUID),
    };
  }
  if (truthy(env.JENKINS_URL) || truthy(env.JENKINS_HOME)) {
    return {
      provider: "jenkins",
      runId: trimmed(env.BUILD_TAG) ?? trimmed(env.BUILD_ID) ?? trimmed(env.BUILD_NUMBER),
      job: trimmed(env.JOB_NAME),
      workflow: trimmed(env.JOB_BASE_NAME),
      repository: trimmed(env.GIT_URL),
      actor: trimmed(env.BUILD_USER_ID) ?? trimmed(env.CHANGE_AUTHOR),
      runnerName: trimmed(env.NODE_NAME) ?? trimmed(env.EXECUTOR_NUMBER),
    };
  }
  if (trimmed(env.TEAMCITY_VERSION)) {
    return {
      provider: "teamcity",
      runId: trimmed(env.BUILD_ID) ?? trimmed(env.BUILD_NUMBER),
      job: trimmed(env.TEAMCITY_BUILDCONF_NAME),
      workflow: trimmed(env.TEAMCITY_PROJECT_NAME),
      repository: trimmed(env.BUILD_VCS_NUMBER),
      runnerName: trimmed(env.AGENT_NAME),
    };
  }
  if (truthy(env.TRAVIS)) {
    return {
      provider: "travis_ci",
      runId: trimmed(env.TRAVIS_BUILD_ID) ?? trimmed(env.TRAVIS_BUILD_NUMBER),
      job: trimmed(env.TRAVIS_JOB_ID) ?? trimmed(env.TRAVIS_JOB_NAME),
      workflow: trimmed(env.TRAVIS_EVENT_TYPE),
      repository: trimmed(env.TRAVIS_REPO_SLUG),
      actor: trimmed(env.TRAVIS_TRIGGERED_BY),
      runnerName: trimmed(env.TRAVIS_OS_NAME),
    };
  }
  if (truthy(env.DRONE)) {
    return {
      provider: "drone_ci",
      runId: trimmed(env.DRONE_BUILD_NUMBER) ?? trimmed(env.DRONE_BUILD_LINK),
      job: trimmed(env.DRONE_STEP_NAME) ?? trimmed(env.DRONE_STAGE_NAME),
      workflow: trimmed(env.DRONE_BUILD_EVENT),
      repository: trimmed(env.DRONE_REPO),
      actor: trimmed(env.DRONE_COMMIT_AUTHOR) ?? trimmed(env.DRONE_BUILD_AUTHOR),
      runnerName: trimmed(env.DRONE_SYSTEM_HOST),
    };
  }
  if (truthy(env.SEMAPHORE)) {
    return {
      provider: "semaphore_ci",
      runId:
        trimmed(env.SEMAPHORE_WORKFLOW_ID) ??
        trimmed(env.SEMAPHORE_PIPELINE_ID) ??
        trimmed(env.SEMAPHORE_JOB_ID),
      job: trimmed(env.SEMAPHORE_JOB_NAME),
      workflow: trimmed(env.SEMAPHORE_WORKFLOW_NAME) ?? trimmed(env.SEMAPHORE_PIPELINE_ID),
      repository: trimmed(env.SEMAPHORE_GIT_REPO_SLUG),
      actor: trimmed(env.SEMAPHORE_GIT_COMMIT_AUTHOR),
      runnerName: trimmed(env.SEMAPHORE_AGENT_MACHINE_TYPE),
    };
  }
  if (truthy(env.APPVEYOR)) {
    return {
      provider: "appveyor",
      runId: trimmed(env.APPVEYOR_BUILD_ID) ?? trimmed(env.APPVEYOR_BUILD_NUMBER),
      job: trimmed(env.APPVEYOR_JOB_ID),
      workflow: trimmed(env.APPVEYOR_PROJECT_NAME),
      repository: trimmed(env.APPVEYOR_REPO_NAME),
      actor: trimmed(env.APPVEYOR_REPO_COMMIT_AUTHOR) ?? trimmed(env.APPVEYOR_ACCOUNT_NAME),
      runnerName: trimmed(env.APPVEYOR_BUILD_WORKER_IMAGE),
    };
  }
  if (truthy(env.WOODPECKER) || trimmed(env.CI_SYSTEM_NAME)?.toLowerCase() === "woodpecker") {
    return {
      provider: "woodpecker_ci",
      runId: trimmed(env.CI_PIPELINE_NUMBER) ?? trimmed(env.CI_BUILD_NUMBER),
      job: trimmed(env.CI_STEP_NAME),
      workflow: trimmed(env.CI_PIPELINE_EVENT),
      repository: trimmed(env.CI_REPO),
      actor: trimmed(env.CI_COMMIT_AUTHOR),
      runnerName: trimmed(env.CI_SYSTEM_HOST),
    };
  }
  if (trimmed(env.CF_BUILD_ID) || trimmed(env.CF_PIPELINE_NAME)) {
    return {
      provider: "codefresh",
      runId: trimmed(env.CF_BUILD_ID),
      job: trimmed(env.CF_STEP_NAME),
      workflow: trimmed(env.CF_PIPELINE_NAME),
      repository: [trimmed(env.CF_REPO_OWNER), trimmed(env.CF_REPO_NAME)]
        .filter(Boolean)
        .join("/"),
      actor: trimmed(env.CF_BUILD_INITIATOR),
      runnerName: trimmed(env.CF_BUILD_TRIGGER),
    };
  }
  return null;
}

function ciWorkloadId(context: CiProviderContext): string | undefined {
  if (context.job) return `ci/${context.job}`;
  if (context.workflow) return `ci/${context.workflow}`;
  return context.provider ? `ci/${context.provider}` : undefined;
}

function processEnv(): Record<string, string | undefined> {
  const processLike = (
    globalThis as typeof globalThis & {
      process?: { env?: Record<string, string | undefined> };
    }
  ).process;
  return processLike?.env ?? {};
}

function truthy(value: string | undefined): boolean {
  const normalized = trimmed(value)?.toLowerCase();
  return Boolean(normalized && !["0", "false", "off", "no"].includes(normalized));
}

function trimmed(value: string | undefined): string | undefined {
  const text = value?.trim();
  return text ? text : undefined;
}
