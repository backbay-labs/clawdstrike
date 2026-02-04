import { HttpClient } from "../http";
import type { StixObject, TaxiiServerConfig } from "./types";

export interface TaxiiObjectsResponse {
  objects: StixObject[];
  next?: string;
}

export class TaxiiClient {
  private readonly config: TaxiiServerConfig;
  private readonly client: HttpClient;

  constructor(config: TaxiiServerConfig) {
    this.config = config;
    this.client = this.createClient();
  }

  private createClient(): HttpClient {
    const version = this.config.version ?? "2.1";
    const headers: Record<string, string> = {
      Accept: `application/taxii+json;version=${version}`,
      "Content-Type": `application/taxii+json;version=${version}`,
      ...(this.config.headers ?? {}),
    };

    if (this.config.auth?.type === "api_key" && this.config.auth.apiKey) {
      headers.Authorization = `Bearer ${this.config.auth.apiKey}`;
    }

    const auth =
      this.config.auth?.type === "basic" && this.config.auth.username
        ? { username: this.config.auth.username, password: this.config.auth.password ?? "" }
        : undefined;

    return new HttpClient({
      baseUrl: this.config.url.replace(/\/+$/, ""),
      headers,
      auth,
    });
  }

  async getObjects(options: {
    addedAfter?: string;
    limit?: number;
    type?: string[];
    next?: string;
  } = {}): Promise<TaxiiObjectsResponse> {
    const params = new URLSearchParams();
    if (options.addedAfter) {
      params.set("added_after", options.addedAfter);
    }
    if (options.limit) {
      params.set("limit", String(options.limit));
    }
    if (options.type?.length) {
      params.set("match[type]", options.type.join(","));
    }
    if (options.next) {
      params.set("next", options.next);
    }

    const path = `/${this.config.apiRoot}/collections/${this.config.collectionId}/objects/?${params.toString()}`;
    const response = await this.client.get(path);
    if (!response.ok) {
      throw new Error(`TAXII HTTP ${response.status}`);
    }

    const body = (await response.json()) as { objects?: StixObject[] };
    const next = response.headers.get("X-TAXII-Next") ?? undefined;
    return { objects: body.objects ?? [], next };
  }

  async *getAllObjects(options: {
    addedAfter?: string;
    type?: string[];
    pageSize?: number;
  } = {}): AsyncGenerator<StixObject[]> {
    let next: string | undefined;
    do {
      const resp = await this.getObjects({
        addedAfter: options.addedAfter,
        limit: options.pageSize ?? 100,
        type: options.type,
        next,
      });
      if (resp.objects.length) {
        yield resp.objects;
      }
      next = resp.next;
    } while (next);
  }
}
