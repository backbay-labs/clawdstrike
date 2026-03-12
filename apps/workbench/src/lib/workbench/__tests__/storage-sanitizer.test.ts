import YAML from "yaml";
import { describe, expect, it } from "vitest";

import {
  sanitizeObjectForStorageWithMetadata,
  sanitizeYamlForStorage,
  sanitizeYamlForStorageWithMetadata,
} from "../storage-sanitizer";

describe("storage-sanitizer", () => {
  it("removes inline embedding_api_key fields", () => {
    const yaml = `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
    embedding_api_key: "super-secret"
    threshold: 0.8
`;

    const sanitized = sanitizeYamlForStorageWithMetadata(yaml);

    expect(sanitized.sensitiveFieldsStripped).toBe(true);
    expect(sanitized.yaml).not.toContain("embedding_api_key");
    expect(sanitized.yaml).not.toContain("super-secret");
    expect(YAML.parse(sanitized.yaml)).toEqual({
      version: "1.4.0",
      name: "Sensitive Policy",
      guards: {
        spider_sense: {
          enabled: true,
          threshold: 0.8,
        },
      },
    });
  });

  it("removes full multiline embedding_api_key blocks without corrupting YAML", () => {
    const yaml = `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
    embedding_api_key: |
      line-one
      line-two

    threshold: 0.8
`;

    const sanitized = sanitizeYamlForStorageWithMetadata(yaml);

    expect(sanitized.sensitiveFieldsStripped).toBe(true);
    expect(sanitized.yaml).not.toContain("embedding_api_key");
    expect(sanitized.yaml).not.toContain("line-one");
    expect(sanitizeYamlForStorage(yaml)).toBe(sanitized.yaml);
    expect(YAML.parse(sanitized.yaml)).toEqual({
      version: "1.4.0",
      name: "Sensitive Policy",
      guards: {
        spider_sense: {
          enabled: true,
          threshold: 0.8,
        },
      },
    });
  });

  it("removes embedding_api_key from nested policy objects", () => {
    const sanitized = sanitizeObjectForStorageWithMetadata({
      guards: {
        spider_sense: {
          enabled: true,
          embedding_api_key: "super-secret",
          threshold: 0.8,
        },
      },
      nested: [
        {
          name: "provider",
          embedding_api_key: "another-secret",
        },
      ],
    });

    expect(sanitized.sensitiveFieldsStripped).toBe(true);
    expect(JSON.stringify(sanitized.value)).not.toContain("embedding_api_key");
    expect(JSON.stringify(sanitized.value)).not.toContain("super-secret");
    expect(JSON.stringify(sanitized.value)).not.toContain("another-secret");
    expect(sanitized.value).toEqual({
      guards: {
        spider_sense: {
          enabled: true,
          threshold: 0.8,
        },
      },
      nested: [
        {
          name: "provider",
        },
      ],
    });
  });
});
