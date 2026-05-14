/**
 * Embedding provider connection testing for Spider Sense configuration.
 *
 * In desktop mode (Tauri): performs a real HTTP call to the embedding API.
 * In web mode: simulates a connection test (browsers may have CORS issues).
 */

import { isDesktop } from "@/lib/tauri-bridge";


export interface ConnectionTestResult {
  success: boolean;
  latencyMs?: number;
  dimensions?: number;
  modelName?: string;
  error?: string;
}


async function testDesktop(
  url: string,
  key: string,
  model: string,
): Promise<ConnectionTestResult> {
  const { invoke } = await import("@tauri-apps/api/core");

  const start = performance.now();

  try {
    const response = await invoke<{
      status: number;
      body: string;
    }>("http_post", {
      url,
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        input: "ClawdStrike connection test",
        model,
      }),
    });

    const latencyMs = Math.round(performance.now() - start);

    if (response.status >= 200 && response.status < 300) {
      try {
        const parsed = JSON.parse(response.body);
        const embedding = parsed?.data?.[0]?.embedding;
        const dimensions = Array.isArray(embedding) ? embedding.length : undefined;
        const modelName = parsed?.model ?? model;

        return {
          success: true,
          latencyMs,
          dimensions,
          modelName,
        };
      } catch {
        return {
          success: true,
          latencyMs,
          modelName: model,
        };
      }
    }

    // HTTP error
    let errorMsg = `HTTP ${response.status}`;
    if (response.status === 401) {
      errorMsg = "401 Unauthorized — check your API key";
    } else if (response.status === 403) {
      errorMsg = "403 Forbidden — API key lacks required permissions";
    } else if (response.status === 404) {
      errorMsg = "404 Not Found — check the API URL and model name";
    } else if (response.status === 429) {
      errorMsg = "429 Rate Limited — too many requests, try again shortly";
    }

    return { success: false, error: errorMsg };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "Connection failed",
    };
  }
}


/** Model-to-dimensions lookup for known models. */
const KNOWN_DIMENSIONS: Record<string, number> = {
  "text-embedding-3-small": 1536,
  "text-embedding-3-large": 3072,
  "text-embedding-ada-002": 1536,
  "embed-english-v3.0": 1024,
  "embed-multilingual-v3.0": 1024,
  "embed-english-light-v3.0": 384,
  "voyage-3": 1024,
  "voyage-3-lite": 512,
  "voyage-code-3": 1024,
};

async function testSimulated(
  _url: string,
  key: string,
  model: string,
): Promise<ConnectionTestResult> {
  // Simulate network latency
  const delay = 120 + Math.floor(Math.random() * 180);
  await new Promise((r) => setTimeout(r, delay));

  // Basic validation: key must be present
  if (!key || key.trim().length === 0) {
    return { success: false, error: "API key is required" };
  }

  // Reject obviously invalid keys
  if (key.length < 8) {
    return { success: false, error: "401 Unauthorized — check your API key" };
  }

  const dimensions = KNOWN_DIMENSIONS[model];

  return {
    success: true,
    latencyMs: delay,
    dimensions: dimensions ?? 768,
    modelName: model,
  };
}


/**
 * Test the embedding API connection.
 *
 * - Desktop (Tauri): makes a real HTTP POST to the embedding endpoint.
 * - Web: runs a simulated test with synthetic latency (CORS prevents real calls).
 */
export async function testEmbeddingConnection(
  url: string,
  key: string,
  model: string,
): Promise<ConnectionTestResult> {
  if (!url || !key || !model) {
    return {
      success: false,
      error: "URL, API key, and model are all required",
    };
  }

  if (isDesktop()) {
    return testDesktop(url, key, model);
  }

  return testSimulated(url, key, model);
}
