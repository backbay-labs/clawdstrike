import { describe, it, expect } from "vitest";
import { operatorReducer, type OperatorState, type OperatorAction } from "../operator-store";
import type { OperatorIdentity, IdpClaims } from "../operator-types";


function makeOperator(overrides?: Partial<OperatorIdentity>): OperatorIdentity {
  return {
    publicKey: "a".repeat(64),
    fingerprint: "b".repeat(16),
    sigil: "\u2666",
    nickname: "test-operator",
    displayName: "Test Operator",
    idpClaims: null,
    createdAt: 1000,
    originDeviceId: "dev001",
    devices: [{ deviceId: "dev001", deviceName: "primary", addedAt: 1000, lastSeenAt: 1000 }],
    ...overrides,
  };
}

function initialState(overrides?: Partial<OperatorState>): OperatorState {
  return {
    currentOperator: null,
    initialized: false,
    loading: true,
    ...overrides,
  };
}


describe("operatorReducer", () => {
  it("handles INIT with an operator", () => {
    const operator = makeOperator();
    const next = operatorReducer(initialState(), { type: "INIT", operator });
    expect(next.currentOperator).toEqual(operator);
    expect(next.initialized).toBe(true);
    expect(next.loading).toBe(false);
  });

  it("handles INIT with null (no saved identity)", () => {
    const next = operatorReducer(initialState(), { type: "INIT", operator: null });
    expect(next.currentOperator).toBeNull();
    expect(next.initialized).toBe(true);
    expect(next.loading).toBe(false);
  });

  it("handles CREATE", () => {
    const operator = makeOperator();
    const next = operatorReducer(initialState(), { type: "CREATE", operator });
    expect(next.currentOperator).toEqual(operator);
    expect(next.loading).toBe(false);
  });

  it("handles UPDATE_DISPLAY_NAME", () => {
    const state = initialState({ currentOperator: makeOperator() });
    const next = operatorReducer(state, { type: "UPDATE_DISPLAY_NAME", displayName: "New Name" });
    expect(next.currentOperator?.displayName).toBe("New Name");
  });

  it("UPDATE_DISPLAY_NAME is no-op without operator", () => {
    const state = initialState();
    const next = operatorReducer(state, { type: "UPDATE_DISPLAY_NAME", displayName: "New Name" });
    expect(next).toBe(state);
  });

  it("handles LINK_IDP", () => {
    const claims: IdpClaims = {
      provider: "oidc",
      issuer: "https://issuer.example.com",
      subject: "user-123",
      email: "test@example.com",
      emailVerified: true,
      organizationId: "org-1",
      teams: ["security"],
      roles: ["admin"],
      boundAt: 2000,
      lastRefreshed: 2000,
      expiresAt: 3000,
    };
    const state = initialState({ currentOperator: makeOperator() });
    const next = operatorReducer(state, { type: "LINK_IDP", claims });
    expect(next.currentOperator?.idpClaims).toEqual(claims);
  });

  it("LINK_IDP is no-op without operator", () => {
    const claims: IdpClaims = {
      provider: "oidc",
      issuer: "https://issuer.example.com",
      subject: "user-123",
      email: null,
      emailVerified: false,
      organizationId: null,
      teams: [],
      roles: [],
      boundAt: 2000,
      lastRefreshed: 2000,
      expiresAt: 3000,
    };
    const state = initialState();
    const next = operatorReducer(state, { type: "LINK_IDP", claims });
    expect(next).toBe(state);
  });

  it("handles UNLINK_IDP", () => {
    const claims: IdpClaims = {
      provider: "okta",
      issuer: "https://okta.example.com",
      subject: "user-456",
      email: "test@okta.example.com",
      emailVerified: true,
      organizationId: null,
      teams: [],
      roles: [],
      boundAt: 2000,
      lastRefreshed: 2000,
      expiresAt: 3000,
    };
    const state = initialState({ currentOperator: makeOperator({ idpClaims: claims }) });
    const next = operatorReducer(state, { type: "UNLINK_IDP" });
    expect(next.currentOperator?.idpClaims).toBeNull();
  });

  it("UNLINK_IDP is no-op without operator", () => {
    const state = initialState();
    const next = operatorReducer(state, { type: "UNLINK_IDP" });
    expect(next).toBe(state);
  });

  it("handles ADD_DEVICE", () => {
    const state = initialState({ currentOperator: makeOperator() });
    const next = operatorReducer(state, {
      type: "ADD_DEVICE",
      device: { deviceId: "dev002", deviceName: "laptop" },
    });
    expect(next.currentOperator?.devices).toHaveLength(2);
    expect(next.currentOperator?.devices[1].deviceId).toBe("dev002");
    expect(next.currentOperator?.devices[1].deviceName).toBe("laptop");
  });

  it("ADD_DEVICE is no-op without operator", () => {
    const state = initialState();
    const next = operatorReducer(state, {
      type: "ADD_DEVICE",
      device: { deviceId: "dev002", deviceName: "laptop" },
    });
    expect(next).toBe(state);
  });

  it("handles SIGN_OUT", () => {
    const state = initialState({ currentOperator: makeOperator() });
    const next = operatorReducer(state, { type: "SIGN_OUT" });
    expect(next.currentOperator).toBeNull();
  });

  it("returns same state for unknown action", () => {
    const state = initialState({ currentOperator: makeOperator() });
    const next = operatorReducer(state, { type: "UNKNOWN" } as unknown as OperatorAction);
    expect(next).toBe(state);
  });
});
