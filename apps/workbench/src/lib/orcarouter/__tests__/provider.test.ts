import { describe, expect, it } from "vitest";
import {
  isOrcaRouterUrl,
  looksLikeOrcaRouterKey,
  normalizeOrcaRouterOrigin,
  orcaRouterAuthorizeUrl,
  orcaRouterChatCompletionsUrl,
  orcaRouterEmbeddingsUrl,
  orcaRouterExchangeUrl,
  orcaRouterModelsUrl,
  redactOrcaRouterKey,
  resolveOrcaRouterOrigins,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_DISPLAY_NAME,
} from "../provider";

describe("OrcaRouter provider definition", () => {
  it("carries the OrcaRouter brand and cyber positioning", () => {
    expect(ORCAROUTER_DISPLAY_NAME).toBe("OrcaRouter Cyber Inference");
    expect(ORCAROUTER_DEFAULT_MODEL).toBe("orcarouter/auto");
  });

  it("defaults auth and inference to separate public origins", () => {
    const origins = resolveOrcaRouterOrigins();
    expect(origins.authBaseUrl).toBe("https://www.orcarouter.ai");
    expect(origins.apiBaseUrl).toBe("https://api.orcarouter.ai/v1");
    // The auth origin must never be derived from the inference origin.
    expect(origins.authBaseUrl).not.toContain("api.orcarouter.ai");
    expect(origins.apiBaseUrl).not.toContain("www.orcarouter.ai");
  });

  it("uses /auth for consent and /api/v1/auth/keys for exchange", () => {
    const origins = resolveOrcaRouterOrigins();
    expect(orcaRouterAuthorizeUrl(origins)).toBe("https://www.orcarouter.ai/auth");
    expect(orcaRouterExchangeUrl(origins)).toBe(
      "https://www.orcarouter.ai/api/v1/auth/keys",
    );
    // The common mistake: /v1/auth/keys on the inference host is a 404.
    expect(orcaRouterExchangeUrl(origins)).not.toContain("api.orcarouter.ai");
  });

  it("builds inference URLs from the API origin", () => {
    const origins = resolveOrcaRouterOrigins();
    expect(orcaRouterModelsUrl(origins)).toBe("https://api.orcarouter.ai/v1/models");
    expect(orcaRouterModelsUrl(origins, "embedding")).toBe(
      "https://api.orcarouter.ai/v1/models?capability=embedding",
    );
    expect(orcaRouterEmbeddingsUrl(origins)).toBe(
      "https://api.orcarouter.ai/v1/embeddings",
    );
    expect(orcaRouterChatCompletionsUrl(origins)).toBe(
      "https://api.orcarouter.ai/v1/chat/completions",
    );
  });

  it("lets explicit overrides win over the shared self-hosted base", () => {
    const origins = resolveOrcaRouterOrigins({
      sharedBaseUrl: "https://orca.internal.example",
      apiBaseUrl: "https://inference.internal.example/v1",
    });
    expect(origins.authBaseUrl).toBe("https://orca.internal.example");
    expect(origins.apiBaseUrl).toBe("https://inference.internal.example/v1");
  });

  it("appends /v1 to a shared base without a version suffix", () => {
    const origins = resolveOrcaRouterOrigins({ sharedBaseUrl: "https://orca.internal.example" });
    expect(origins.apiBaseUrl).toBe("https://orca.internal.example/v1");
    expect(origins.authBaseUrl).toBe("https://orca.internal.example");
  });

  it("rejects plain HTTP for remote origins but allows loopback", () => {
    expect(() => normalizeOrcaRouterOrigin("http://orca.example.com", "base")).toThrow(
      /https/i,
    );
    expect(normalizeOrcaRouterOrigin("http://127.0.0.1:8080", "base")).toBe(
      "http://127.0.0.1:8080",
    );
    expect(normalizeOrcaRouterOrigin("http://localhost:9000/", "base")).toBe(
      "http://localhost:9000",
    );
  });

  it("rejects origins with embedded credentials", () => {
    expect(() =>
      normalizeOrcaRouterOrigin("https://user:pass@www.orcarouter.ai", "auth"),
    ).toThrow(/credentials/i);
  });

  it("recognises OrcaRouter URLs by host only", () => {
    expect(isOrcaRouterUrl("https://api.orcarouter.ai/v1/embeddings")).toBe(true);
    expect(isOrcaRouterUrl("https://www.orcarouter.ai/auth")).toBe(true);
    expect(isOrcaRouterUrl("https://api.openai.com/v1/embeddings")).toBe(false);
    expect(isOrcaRouterUrl("not a url")).toBe(false);
    expect(isOrcaRouterUrl(undefined)).toBe(false);
  });

  it("treats the sk-orca prefix as a format hint only", () => {
    expect(looksLikeOrcaRouterKey("sk-orca-abcdefgh1234")).toBe(true);
    expect(looksLikeOrcaRouterKey("sk-proj-abcdefgh1234")).toBe(false);
  });

  it("redacts keys for display", () => {
    const masked = redactOrcaRouterKey("sk-orca-abcdefgh12345678");
    expect(masked).not.toContain("abcdefgh123");
    expect(masked.startsWith("sk-o")).toBe(true);
    expect(redactOrcaRouterKey("short")).toBe("••••");
  });
});
