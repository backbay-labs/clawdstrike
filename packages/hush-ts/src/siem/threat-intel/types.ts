export interface TaxiiServerConfig {
  url: string;
  apiRoot: string;
  collectionId: string;
  auth?: {
    type: "basic" | "api_key";
    username?: string;
    password?: string;
    apiKey?: string;
  };
  version?: "2.0" | "2.1";
  headers?: Record<string, string>;
}

export interface FeedConfig {
  intervalMinutes?: number;
  pageSize?: number;
  includeTypes?: string[];
  minConfidence?: number;
  addedAfter?: string;
  cacheTtlHours?: number;
}

export interface ThreatIntelConfig {
  enabled: boolean;
  servers: TaxiiServerConfig[];
  feed?: FeedConfig;
  cache?: {
    persistent?: boolean;
    path?: string;
    maxSize?: number;
  };
  actions?: {
    blockEgress?: boolean;
    blockPaths?: boolean;
    enrichEvents?: boolean;
  };
}

export type IndicatorType =
  | "domain"
  | "ipv4"
  | "ipv6"
  | "url"
  | "file_hash"
  | "file_name";

export interface ParsedIndicator {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
  validFrom: Date;
  validUntil?: Date;
  source: string;
  context: {
    name?: string;
    description?: string;
    labels?: string[];
    externalRefs?: Array<{ source_name: string; url?: string; external_id?: string }>;
  };
}

export interface StixIndicator {
  type: "indicator";
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  name?: string;
  description?: string;
  pattern: string;
  pattern_type: string;
  valid_from: string;
  valid_until?: string;
  confidence?: number;
  labels?: string[];
  external_references?: Array<{ source_name: string; url?: string; external_id?: string }>;
}

export type StixObject = Record<string, unknown> & { type?: string };

