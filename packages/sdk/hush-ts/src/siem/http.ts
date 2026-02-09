export interface BasicAuth {
  username: string;
  password: string;
}

export interface HttpClientOptions {
  baseUrl: string;
  headers?: Record<string, string>;
  auth?: BasicAuth;
  fetchFn?: typeof fetch;
}

export class HttpClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly auth?: BasicAuth;
  private readonly fetchFn: typeof fetch;

  constructor(options: HttpClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.headers = options.headers ?? {};
    this.auth = options.auth;
    this.fetchFn = options.fetchFn ?? fetch;
  }

  async get(path: string, options: { headers?: Record<string, string> } = {}): Promise<Response> {
    return this.request("GET", path, undefined, options.headers);
  }

  async post(
    path: string,
    body: unknown,
    options: { headers?: Record<string, string> } = {}
  ): Promise<Response> {
    return this.request("POST", path, body, options.headers);
  }

  async put(
    path: string,
    body: unknown,
    options: { headers?: Record<string, string> } = {}
  ): Promise<Response> {
    return this.request("PUT", path, body, options.headers);
  }

  private async request(
    method: string,
    path: string,
    body: unknown,
    headers?: Record<string, string>
  ): Promise<Response> {
    const url = new URL(path, this.baseUrl);
    const h: Record<string, string> = { ...this.headers, ...(headers ?? {}) };
    if (this.auth && !("Authorization" in h)) {
      const token = Buffer.from(`${this.auth.username}:${this.auth.password}`).toString("base64");
      h.Authorization = `Basic ${token}`;
    }

    const init: RequestInit = {
      method,
      headers: h,
    };

    if (body !== undefined) {
      init.body = typeof body === "string" || body instanceof Uint8Array ? (body as any) : JSON.stringify(body);
      if (!("Content-Type" in h) && typeof init.body === "string") {
        h["Content-Type"] = "application/json";
      }
    }

    return this.fetchFn(url, init);
  }
}

export async function readResponseBody(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "";
  }
}

