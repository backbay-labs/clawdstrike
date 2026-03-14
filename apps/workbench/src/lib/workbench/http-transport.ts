export interface HttpTransportOptions {
  dev?: boolean;
  hasTauriInternals?: boolean;
  fallbackFetch?: typeof globalThis.fetch;
  loadTauriFetch?: () => Promise<typeof globalThis.fetch>;
}

function detectTauriInternals(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function getDefaultFetch(): typeof globalThis.fetch {
  return globalThis.fetch.bind(globalThis);
}

async function loadDefaultTauriFetch(): Promise<typeof globalThis.fetch> {
  const mod = await import("@tauri-apps/plugin-http");
  return mod.fetch as typeof globalThis.fetch;
}

export function createHttpTransport(options: HttpTransportOptions = {}): typeof globalThis.fetch {
  const dev = options.dev ?? import.meta.env.DEV;
  const hasTauriInternals = options.hasTauriInternals ?? detectTauriInternals();
  const getFallbackFetch = (): typeof globalThis.fetch => options.fallbackFetch ?? getDefaultFetch();
  const loadTauriFetch = options.loadTauriFetch ?? loadDefaultTauriFetch;
  const useTauriTransport = !dev && hasTauriInternals;
  let tauriFetchPromise: Promise<typeof globalThis.fetch> | null = null;

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    if (!useTauriTransport) {
      return getFallbackFetch()(input, init);
    }

    tauriFetchPromise ??= loadTauriFetch().catch(() => getFallbackFetch());
    const fetchFn = await tauriFetchPromise;
    return fetchFn(input, init);
  };
}

export const httpFetch = createHttpTransport();
