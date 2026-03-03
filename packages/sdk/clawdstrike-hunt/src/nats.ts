import { readFile } from "node:fs/promises";
import { WatchError } from "./errors.js";

export type NatsModuleLike = {
  credsAuthenticator?: (creds: Uint8Array | (() => Uint8Array)) => unknown;
};

export async function buildNatsConnectOptions(
  natsModule: NatsModuleLike,
  natsUrl: string,
  natsCreds?: string,
): Promise<Record<string, unknown>> {
  if (!natsCreds) {
    return { servers: natsUrl };
  }

  if (typeof natsModule.credsAuthenticator !== "function") {
    throw new WatchError(
      "This nats client version does not support credsAuthenticator; cannot use natsCreds.",
    );
  }

  // Prefer reading creds from path; if that fails, treat the value as inline creds content.
  let creds: Uint8Array;
  try {
    creds = await readFile(natsCreds);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    if (code !== "ENOENT") {
      throw new WatchError(
        `Failed to read natsCreds file '${natsCreds}': ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    creds = new TextEncoder().encode(natsCreds);
  }

  return {
    servers: natsUrl,
    authenticator: natsModule.credsAuthenticator(creds),
  };
}
