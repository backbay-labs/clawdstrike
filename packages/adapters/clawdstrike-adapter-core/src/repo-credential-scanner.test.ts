import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { scanRepositoryCredentialPathsForLocalEdr } from "./repo-credential-scanner.js";

describe("repo credential scanner local EDR publishing", () => {
  it("publishes metadata-only findings for credential-looking repo files", async () => {
    const rootDir = await mkdtemp(join(tmpdir(), "clawdstrike-repo-scan-"));
    await mkdir(join(rootDir, ".github", "actions"), { recursive: true });
    await mkdir(join(rootDir, "node_modules", "fixture"), { recursive: true });
    await writeFile(join(rootDir, ".env"), "STRIPE_API_KEY=sk-MY_RAW_SECRET\n");
    await writeFile(join(rootDir, ".github", "actions", "ci_token"), "ghp_MY_RAW_SECRET\n");
    await writeFile(join(rootDir, "node_modules", "fixture", ".env"), "IGNORED=MY_RAW_SECRET\n");

    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanRepositoryCredentialPathsForLocalEdr({
      rootDir,
      scannerId: "repo-scan-test-1",
      hostId: "host-repo-scan-2",
      userId: "user-repo-scan-2",
      sessionId: "session-repo-scan-2",
      agentId: "agent-repo-scan-2",
      config: {
        enabled: true,
        token: "local-token",
        agentUrl: "http://agent.test",
        timeoutMs: 500,
      },
    });

    expect(result).toMatchObject({
      scannedPathCount: 2,
      publishedFindingCount: 2,
      skippedDirectoryCount: 1,
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
          kind: "repo_secret",
          path: join(rootDir, ".env"),
          commandLine: `repo_scan ${join(rootDir, ".env")}`,
          metadata: expect.objectContaining({
            collectorKind: "repo_scanner",
            scannerId: "repo-scan-test-1",
            repositoryPath: rootDir,
            repositoryRelativePath: ".env",
            rawValueOmitted: true,
          }),
        }),
        expect.objectContaining({
          kind: "ci_token",
          path: join(rootDir, ".github", "actions", "ci_token"),
          metadata: expect.objectContaining({
            repositoryRelativePath: ".github/actions/ci_token",
            rawValueOmitted: true,
          }),
        }),
      ]),
    );
    expect(JSON.stringify(payloads)).not.toContain("MY_RAW_SECRET");
    expect(JSON.stringify(payloads)).not.toContain("node_modules");
  });
});
