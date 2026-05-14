import { describe, it, expect, vi, beforeEach } from "vitest";
import { createSecretsApi } from "../secrets-api";

// Mock secureStore
vi.mock("@/lib/workbench/secure-store", () => ({
  secureStore: {
    get: vi.fn(),
    set: vi.fn(),
    delete: vi.fn(),
    has: vi.fn(),
  },
}));

import { secureStore } from "@/lib/workbench/secure-store";

const mockedStore = vi.mocked(secureStore);

describe("SecretsApi", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("createSecretsApi returns object with get/set/delete/has methods", () => {
    const api = createSecretsApi("my-plugin");
    expect(typeof api.get).toBe("function");
    expect(typeof api.set).toBe("function");
    expect(typeof api.delete).toBe("function");
    expect(typeof api.has).toBe("function");
  });

  it('set("api_key", "abc") delegates to secureStore.set("plugin:my-plugin:api_key", "abc")', async () => {
    mockedStore.set.mockResolvedValue(undefined);

    const api = createSecretsApi("my-plugin");
    await api.set("api_key", "abc");

    expect(mockedStore.set).toHaveBeenCalledWith("plugin:my-plugin:api_key", "abc");
  });

  it('get("api_key") delegates to secureStore.get("plugin:my-plugin:api_key")', async () => {
    mockedStore.get.mockResolvedValue("abc");

    const api = createSecretsApi("my-plugin");
    const result = await api.get("api_key");

    expect(mockedStore.get).toHaveBeenCalledWith("plugin:my-plugin:api_key");
    expect(result).toBe("abc");
  });

  it('delete("api_key") delegates to secureStore.delete("plugin:my-plugin:api_key")', async () => {
    mockedStore.delete.mockResolvedValue(undefined);

    const api = createSecretsApi("my-plugin");
    await api.delete("api_key");

    expect(mockedStore.delete).toHaveBeenCalledWith("plugin:my-plugin:api_key");
  });

  it('has("api_key") delegates to secureStore.has("plugin:my-plugin:api_key")', async () => {
    mockedStore.has.mockResolvedValue(true);

    const api = createSecretsApi("my-plugin");
    const result = await api.has("api_key");

    expect(mockedStore.has).toHaveBeenCalledWith("plugin:my-plugin:api_key");
    expect(result).toBe(true);
  });
});
