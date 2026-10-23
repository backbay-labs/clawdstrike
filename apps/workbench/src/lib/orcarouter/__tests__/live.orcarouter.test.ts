/**
 * Live check through the implemented OrcaRouter provider path.
 *
 * Runs only when ORCAROUTER_API_KEY is present (the verification runner injects
 * it); otherwise the suite is skipped so ordinary CI never needs a credential.
 * The key is never printed.
 */

import { describe, expect, it } from "vitest";
import { fetchOrcaRouterCatalog, filterModels, recommendedCyberModels } from "../catalog";
import { createOrcaRouterClient, OrcaRouterRequestError } from "../client";
import { resolveOrcaRouterOrigins } from "../provider";

const apiKey = process.env.ORCAROUTER_API_KEY ?? "";
const live = apiKey ? describe : describe.skip;

const origins = resolveOrcaRouterOrigins();

live("live OrcaRouter provider", () => {
  it(
    "discovers the live model catalogue with the credential",
    async () => {
      const result = await fetchOrcaRouterCatalog({ origins, apiKey });
      expect(result.status).toBe("ready");
      expect(result.catalog.source).toBe("live");
      expect(result.catalog.models.length).toBeGreaterThan(0);

      const chat = filterModels(result.catalog.models, { capability: "chat" });
      expect(chat.length).toBeGreaterThan(0);
      // Model ids are vendor-qualified and preserved verbatim.
      expect(chat.every((model) => model.id.includes("/"))).toBe(true);
      expect(recommendedCyberModels(chat).length).toBeGreaterThanOrEqual(0);
    },
    30_000,
  );

  it(
    "completes a chat completion through the named provider client",
    async () => {
      const { catalog } = await fetchOrcaRouterCatalog({ origins, apiKey });
      const chat = filterModels(catalog.models, { capability: "chat" });
      const candidates = [
        ...recommendedCyberModels(chat).map((model) => model.id),
        "orcarouter/auto",
        "orcarouter/fusion",
        "deepseek/deepseek-v4.1-flash",
      ].filter((id) => chat.some((model) => model.id === id));

      const client = createOrcaRouterClient({ origins, apiKey });
      const failures: { model: string; status: number | null; kind: string }[] = [];
      let reply: Awaited<ReturnType<typeof client.chat>> | null = null;
      for (const model of candidates) {
        try {
          reply = await client.chat(
            model,
            [{ role: "user", content: "Reply with the single word: ready" }],
            32,
          );
          break;
        } catch (err) {
          failures.push({
            model,
            status: err instanceof OrcaRouterRequestError ? err.status : null,
            kind: err instanceof OrcaRouterRequestError ? err.kind : "unknown",
          });
        }
      }

      // A key that cannot use any catalogue model fails loudly with the exact
      // per-model errors instead of pretending the path works.
      expect(reply, JSON.stringify(failures)).not.toBeNull();
      expect(reply?.content.length ?? 0).toBeGreaterThan(0);
      expect(reply?.model).toBeTruthy();
    },
    60_000,
  );
});
