import { describe, it, expect } from "vitest";
import { guarded } from "./decorator.js";
import { HuntAlertError } from "./errors.js";
import { parseRule } from "./correlate/index.js";
import type { CorrelationRule } from "./types.js";

function singleConditionRule(): CorrelationRule {
  return parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Guard Call Alert"
severity: high
description: "Fires on any guarded function call"
window: 5m
conditions:
  - source: receipt
    action_type: function_call
    bind: fn_call
output:
  title: "Guarded function invoked"
  evidence:
    - fn_call
`);
}

function nonMatchingRule(): CorrelationRule {
  return parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Non-matching rule"
severity: low
description: "Does not match guarded calls"
window: 5m
conditions:
  - source: tetragon
    action_type: process
    verdict: deny
    bind: proc
output:
  title: "Process denied"
  evidence:
    - proc
`);
}

describe("guarded", () => {
  it("sync function runs normally when no alert", async () => {
    function add(a: number, b: number) { return a + b; }
    const wrapped = guarded(add, { rules: [nonMatchingRule()] });
    const result = await wrapped(2, 3);
    expect(result).toBe(5);
  });

  it("async function runs normally when no alert", async () => {
    async function asyncAdd(a: number, b: number) { return a + b; }
    const wrapped = guarded(asyncAdd, { rules: [nonMatchingRule()] });
    const result = await wrapped(2, 3);
    expect(result).toBe(5);
  });

  it("raises HuntAlertError in deny mode", () => {
    function doSomething() { return 42; }
    const wrapped = guarded(doSomething, {
      rules: [singleConditionRule()],
      onAlert: 'deny',
    });
    expect(() => wrapped()).toThrow(HuntAlertError);
    expect(() => wrapped()).toThrow("Alert triggered");
  });

  it("collects alerts in log mode", async () => {
    function doSomething() { return 42; }
    const wrapped = guarded(doSomething, {
      rules: [singleConditionRule()],
      onAlert: 'log',
    });
    const result = await wrapped();
    expect(result).toBe(42);
    expect(wrapped.alerts.length).toBeGreaterThan(0);
    expect(wrapped.alerts[0].title).toBe("Guarded function invoked");
  });

  it(".alerts property returns collected alerts", async () => {
    function doSomething() { return 1; }
    const wrapped = guarded(doSomething, {
      rules: [singleConditionRule()],
      onAlert: 'log',
    });
    expect(wrapped.alerts).toHaveLength(0);
    await wrapped();
    expect(wrapped.alerts.length).toBeGreaterThan(0);
  });

  it("function name preserved", () => {
    function myFunction() { return 1; }
    const wrapped = guarded(myFunction, { rules: [] });
    expect(wrapped.name).toBe("myFunction");
  });

  it("function arguments passed through", async () => {
    function concat(a: string, b: string) { return a + b; }
    const wrapped = guarded(concat, { rules: [nonMatchingRule()] });
    const result = await wrapped("hello", " world");
    expect(result).toBe("hello world");
  });

  it("return value preserved (sync)", async () => {
    function getObj() { return { key: "value" }; }
    const wrapped = guarded(getObj, { rules: [nonMatchingRule()] });
    const result = await wrapped();
    expect(result).toEqual({ key: "value" });
  });

  it("return value preserved (async)", async () => {
    async function getObjAsync() { return { key: "value" }; }
    const wrapped = guarded(getObjAsync, { rules: [nonMatchingRule()] });
    const result = await wrapped();
    expect(result).toEqual({ key: "value" });
  });

  it("defaults to deny mode", () => {
    function doSomething() { return 42; }
    const wrapped = guarded(doSomething, { rules: [singleConditionRule()] });
    expect(() => wrapped()).toThrow(HuntAlertError);
  });
});
