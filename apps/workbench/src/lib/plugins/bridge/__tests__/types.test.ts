/**
 * Bridge Protocol Types Tests
 *
 * Tests for the BridgeMessage type guard, BRIDGE_METHODS mapping,
 * BRIDGE_TIMEOUT_MS constant, and BridgeErrorCode coverage.
 */

import { describe, it, expect } from "vitest";
import {
  isBridgeMessage,
  BRIDGE_METHODS,
  BRIDGE_TIMEOUT_MS,
  type BridgeRequest,
  type BridgeResponse,
  type BridgeEvent,
  type BridgeErrorResponse,
  type BridgeErrorCode,
  type BridgeError,
  type BridgeMethodName,
} from "../types";

// ---- BRIDGE_TIMEOUT_MS ----

describe("BRIDGE_TIMEOUT_MS", () => {
  it("is 30000 milliseconds", () => {
    expect(BRIDGE_TIMEOUT_MS).toBe(30_000);
  });
});

// ---- BRIDGE_METHODS ----

describe("BRIDGE_METHODS", () => {
  it("maps commands.register", () => {
    expect(BRIDGE_METHODS.commands.register).toBe("commands.register");
  });

  it("maps guards.register", () => {
    expect(BRIDGE_METHODS.guards.register).toBe("guards.register");
  });

  it("maps fileTypes.register", () => {
    expect(BRIDGE_METHODS.fileTypes.register).toBe("fileTypes.register");
  });

  it("maps statusBar.register", () => {
    expect(BRIDGE_METHODS.statusBar.register).toBe("statusBar.register");
  });

  it("maps sidebar.register", () => {
    expect(BRIDGE_METHODS.sidebar.register).toBe("sidebar.register");
  });

  it("maps storage.get", () => {
    expect(BRIDGE_METHODS.storage.get).toBe("storage.get");
  });

  it("maps storage.set", () => {
    expect(BRIDGE_METHODS.storage.set).toBe("storage.set");
  });

  it("has exactly 7 methods across all namespaces", () => {
    const methods: string[] = [];
    for (const ns of Object.values(BRIDGE_METHODS)) {
      for (const m of Object.values(ns as Record<string, string>)) {
        methods.push(m);
      }
    }
    expect(methods).toHaveLength(7);
  });
});

// ---- isBridgeMessage ----

describe("isBridgeMessage", () => {
  it("returns true for a valid BridgeRequest", () => {
    const msg: BridgeRequest = {
      id: "1",
      type: "request",
      method: "guards.register",
      params: { id: "test" },
    };
    expect(isBridgeMessage(msg)).toBe(true);
  });

  it("returns true for a valid BridgeResponse", () => {
    const msg: BridgeResponse = { id: "1", type: "response", result: 42 };
    expect(isBridgeMessage(msg)).toBe(true);
  });

  it("returns true for a valid BridgeEvent", () => {
    const msg: BridgeEvent = {
      type: "event",
      method: "policy.changed",
      params: {},
    };
    expect(isBridgeMessage(msg)).toBe(true);
  });

  it("returns true for a valid BridgeErrorResponse", () => {
    const msg: BridgeErrorResponse = {
      id: "1",
      type: "error",
      error: { code: "INTERNAL_ERROR", message: "oops" },
    };
    expect(isBridgeMessage(msg)).toBe(true);
  });

  it("returns false for null", () => {
    expect(isBridgeMessage(null)).toBe(false);
  });

  it("returns false for undefined", () => {
    expect(isBridgeMessage(undefined)).toBe(false);
  });

  it("returns false for a string", () => {
    expect(isBridgeMessage("hello")).toBe(false);
  });

  it("returns false for an object with no type field", () => {
    expect(isBridgeMessage({ id: "1", method: "test" })).toBe(false);
  });

  it("returns false for an object with an invalid type field", () => {
    expect(isBridgeMessage({ id: "1", type: "unknown" })).toBe(false);
  });

  it("returns false for a request without an id", () => {
    expect(isBridgeMessage({ type: "request", method: "test" })).toBe(false);
  });

  it("returns false for a response without an id", () => {
    expect(isBridgeMessage({ type: "response", result: 42 })).toBe(false);
  });

  it("returns false for an error without an id", () => {
    expect(
      isBridgeMessage({
        type: "error",
        error: { code: "INTERNAL_ERROR", message: "oops" },
      }),
    ).toBe(false);
  });

  it("returns true for an event without an id (events have no id)", () => {
    expect(
      isBridgeMessage({ type: "event", method: "policy.changed" }),
    ).toBe(true);
  });
});

// ---- Type shape compile-time checks ----

describe("type shapes", () => {
  it("BridgeErrorCode includes all required codes", () => {
    // This is a compile-time check -- if any of these fail to type-check,
    // the test file won't compile. The runtime assertion just confirms the
    // string values are distinct.
    const codes: BridgeErrorCode[] = [
      "METHOD_NOT_FOUND",
      "INVALID_PARAMS",
      "INTERNAL_ERROR",
      "TIMEOUT",
      "PERMISSION_DENIED",
      "PLUGIN_REVOKED",
    ];
    expect(new Set(codes).size).toBe(6);
  });

  it("BridgeError has code and message", () => {
    const err: BridgeError = { code: "TIMEOUT", message: "timed out" };
    expect(err.code).toBe("TIMEOUT");
    expect(err.message).toBe("timed out");
  });

  it("BridgeRequest has required fields", () => {
    const req: BridgeRequest = {
      id: "0",
      type: "request",
      method: "storage.get",
    };
    expect(req.type).toBe("request");
    expect(req.id).toBe("0");
    expect(req.method).toBe("storage.get");
  });

  it("BridgeResponse result is optional", () => {
    const res: BridgeResponse = { id: "0", type: "response" };
    expect(res.result).toBeUndefined();
  });

  it("BridgeMethodName matches BRIDGE_METHODS values", () => {
    const method: BridgeMethodName = "guards.register";
    expect(method).toBe("guards.register");
  });
});
