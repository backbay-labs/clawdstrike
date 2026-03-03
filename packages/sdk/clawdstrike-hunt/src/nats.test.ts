import { describe, it, expect } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildNatsConnectOptions } from "./nats.js";
import { WatchError } from "./errors.js";

describe("buildNatsConnectOptions", () => {
  it("returns servers only when no creds are provided", async () => {
    const options = await buildNatsConnectOptions({}, "nats://localhost:4222");
    expect(options).toEqual({ servers: "nats://localhost:4222" });
  });

  it("uses credsAuthenticator with inline creds content", async () => {
    let captured: Uint8Array | undefined;
    const options = await buildNatsConnectOptions(
      {
        credsAuthenticator: (creds) => {
          captured = typeof creds === "function" ? creds() : creds;
          return "auth";
        },
      },
      "nats://localhost:4222",
      "INLINE-CREDS",
    );
    expect(new TextDecoder().decode(captured!)).toBe("INLINE-CREDS");
    expect(options).toEqual({ servers: "nats://localhost:4222", authenticator: "auth" });
  });

  it("reads creds from file path when file exists", async () => {
    const path = join(tmpdir(), `hunt-nats-creds-${Date.now()}.creds`);
    await writeFile(path, "FILE-CREDS", "utf-8");

    let captured: Uint8Array | undefined;
    const options = await buildNatsConnectOptions(
      {
        credsAuthenticator: (creds) => {
          captured = typeof creds === "function" ? creds() : creds;
          return "auth";
        },
      },
      "nats://localhost:4222",
      path,
    );

    expect(new TextDecoder().decode(captured!)).toBe("FILE-CREDS");
    expect(options).toEqual({ servers: "nats://localhost:4222", authenticator: "auth" });
  });

  it("throws WatchError when credsAuthenticator is unavailable", async () => {
    await expect(
      buildNatsConnectOptions({}, "nats://localhost:4222", "whatever"),
    ).rejects.toBeInstanceOf(WatchError);
  });

  it("throws WatchError when natsCreds points to unreadable path kind", async () => {
    const dirPath = join(tmpdir(), `hunt-nats-creds-dir-${Date.now()}`);
    await mkdir(dirPath);

    await expect(
      buildNatsConnectOptions(
        {
          credsAuthenticator: () => "auth",
        },
        "nats://localhost:4222",
        dirPath,
      ),
    ).rejects.toBeInstanceOf(WatchError);
  });
});
