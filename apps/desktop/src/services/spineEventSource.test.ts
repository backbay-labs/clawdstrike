import { describe, expect, it } from "vitest";
import { normalizeSpinePayload } from "./spineEventSource";

describe("normalizeSpinePayload", () => {
  it("classifies Hubble DNS payloads before generic flow payloads", () => {
    const payload = {
      time: "2026-02-10T20:00:00Z",
      source: { ip: "10.0.0.10", pod_name: "web-0", namespace: "default" },
      destination: { ip: "8.8.8.8", port: 53 },
      verdict: "forwarded",
      dns_names: ["example.com"],
    };

    const event = normalizeSpinePayload(payload);
    expect(event).not.toBeNull();
    expect(event?.source).toBe("hubble");
    expect(event?.category).toBe("dns_query");
    expect(event?.network?.dnsName).toBe("example.com");
  });

  it("classifies Hubble DNS L7 payloads as dns_query", () => {
    const payload = {
      time: "2026-02-10T20:00:00Z",
      source: { ip: "10.0.0.11", pod_name: "api-0", namespace: "default" },
      destination: { ip: "1.1.1.1", port: 53 },
      verdict: "forwarded",
      l7: { type: "DNS", dns_name: "internal.service.local" },
    };

    const event = normalizeSpinePayload(payload);
    expect(event).not.toBeNull();
    expect(event?.category).toBe("dns_query");
    expect(event?.network?.dnsName).toBe("internal.service.local");
  });

  it("keeps non-DNS Hubble payloads as network_flow", () => {
    const payload = {
      time: "2026-02-10T20:00:00Z",
      source: { ip: "10.0.0.20", port: 443, pod_name: "client-0", namespace: "default" },
      destination: { ip: "10.0.0.30", port: 8443 },
      verdict: "forwarded",
      protocol: "tcp",
    };

    const event = normalizeSpinePayload(payload);
    expect(event).not.toBeNull();
    expect(event?.category).toBe("network_flow");
  });
});
