import { describe, it, expect } from "vitest";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { detectIocType, containsWordBounded, IocDatabase } from "./ioc.js";
import type { TimelineEvent } from "../types.js";

function makeEvent(
  summary: string,
  process?: string,
  raw?: unknown
): TimelineEvent {
  return {
    timestamp: new Date("2025-06-15T12:00:00Z"),
    source: "tetragon",
    kind: "process_exec",
    verdict: "none",
    summary,
    process,
    raw,
  };
}

// ---------------------------------------------------------------------------
// detectIocType
// ---------------------------------------------------------------------------

describe("detectIocType", () => {
  it("detects SHA-256 (64 hex chars)", () => {
    expect(detectIocType("a".repeat(64))).toBe("sha256");
  });

  it("detects SHA-1 (40 hex chars)", () => {
    expect(detectIocType("b".repeat(40))).toBe("sha1");
  });

  it("detects MD5 (32 hex chars)", () => {
    expect(detectIocType("c".repeat(32))).toBe("md5");
  });

  it("detects domain", () => {
    expect(detectIocType("evil.com")).toBe("domain");
    expect(detectIocType("sub.evil.com")).toBe("domain");
  });

  it("detects IPv4", () => {
    expect(detectIocType("192.168.1.1")).toBe("ipv4");
    expect(detectIocType("10.0.0.1")).toBe("ipv4");
  });

  it("rejects invalid IPv4 octets", () => {
    expect(detectIocType("256.0.0.1")).not.toBe("ipv4");
  });

  it("detects IPv6", () => {
    expect(detectIocType("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe("ipv6");
  });

  it("detects URL", () => {
    expect(detectIocType("http://evil.com/payload")).toBe("url");
    expect(detectIocType("https://malware.example.org/dl")).toBe("url");
  });

  it("returns undefined for empty string", () => {
    expect(detectIocType("")).toBeUndefined();
    expect(detectIocType("   ")).toBeUndefined();
  });

  it("returns undefined for unrecognized", () => {
    expect(detectIocType("hello world")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// containsWordBounded
// ---------------------------------------------------------------------------

describe("containsWordBounded", () => {
  it("matches at string boundaries", () => {
    expect(containsWordBounded("evil.com", "evil.com")).toBe(true);
  });

  it("matches surrounded by non-word chars", () => {
    expect(containsWordBounded("connect to evil.com:8080", "evil.com")).toBe(true);
  });

  it("does not match as substring of larger domain", () => {
    expect(containsWordBounded("notevil.com", "evil.com")).toBe(false);
  });

  it("does not match within larger hostname", () => {
    expect(containsWordBounded("cdn-evil.com.example.org", "evil.com")).toBe(false);
  });

  it("does not match IP as substring of larger IP", () => {
    expect(containsWordBounded("210.0.0.10", "10.0.0.1")).toBe(false);
  });

  it("matches IP at word boundary", () => {
    expect(containsWordBounded("connect to 10.0.0.1 port 80", "10.0.0.1")).toBe(true);
  });

  it("returns false for empty needle", () => {
    expect(containsWordBounded("something", "")).toBe(false);
  });

  it("matches at start of string", () => {
    expect(containsWordBounded("evil.com is bad", "evil.com")).toBe(true);
  });

  it("matches at end of string", () => {
    expect(containsWordBounded("connected to evil.com", "evil.com")).toBe(true);
  });

  it("non-word separator allows match", () => {
    expect(containsWordBounded("dns:evil.com/query", "evil.com")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// IocDatabase
// ---------------------------------------------------------------------------

describe("IocDatabase", () => {
  it("starts empty", () => {
    const db = new IocDatabase();
    expect(db.size).toBe(0);
    expect(db.isEmpty).toBe(true);
  });

  it("adds entries and updates size", () => {
    const db = new IocDatabase();
    db.addEntry({
      indicator: "evil.com",
      iocType: "domain",
      description: "C2 domain",
    });
    expect(db.size).toBe(1);
    expect(db.isEmpty).toBe(false);
  });

  it("ignores empty indicators", () => {
    const db = new IocDatabase();
    db.addEntry({ indicator: "", iocType: "domain" });
    db.addEntry({ indicator: "   ", iocType: "domain" });
    expect(db.size).toBe(0);
  });

  it("merges databases", () => {
    const db1 = new IocDatabase();
    db1.addEntry({ indicator: "evil.com", iocType: "domain" });

    const db2 = new IocDatabase();
    db2.addEntry({ indicator: "10.0.0.1", iocType: "ipv4" });

    db1.merge(db2);
    expect(db1.size).toBe(2);
  });

  describe("matchEvent", () => {
    it("matches hash IOC in summary via substring", () => {
      const db = new IocDatabase();
      const hash = "a".repeat(64);
      db.addEntry({ indicator: hash, iocType: "sha256" });

      const event = makeEvent(`file hash: ${hash}`);
      const match = db.matchEvent(event);
      expect(match).toBeDefined();
      expect(match!.matchedIocs[0].indicator).toBe(hash);
      expect(match!.matchField).toBe("summary");
    });

    it("matches domain IOC with word boundary", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "evil.com", iocType: "domain" });

      const event = makeEvent("connected to evil.com:443");
      const match = db.matchEvent(event);
      expect(match).toBeDefined();
      expect(match!.matchField).toBe("summary");
    });

    it("does not match domain as substring of larger domain", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "evil.com", iocType: "domain" });

      const event = makeEvent("connected to notevil.com:443");
      const match = db.matchEvent(event);
      expect(match).toBeUndefined();
    });

    it("matches IOC in process field", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "evil.com", iocType: "domain" });

      const event = makeEvent("some event", "curl evil.com");
      const match = db.matchEvent(event);
      expect(match).toBeDefined();
      expect(match!.matchField).toBe("process");
    });

    it("matches IOC in raw field", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "evil.com", iocType: "domain" });

      const event = makeEvent("some event", undefined, {
        url: "http://evil.com/payload",
      });
      const match = db.matchEvent(event);
      expect(match).toBeDefined();
      expect(match!.matchField).toBe("raw");
    });

    it("returns undefined when no match", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "evil.com", iocType: "domain" });

      const event = makeEvent("connected to good.com");
      const match = db.matchEvent(event);
      expect(match).toBeUndefined();
    });

    it("matching is case-insensitive", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "Evil.Com", iocType: "domain" });

      const event = makeEvent("connected to evil.com:443");
      const match = db.matchEvent(event);
      expect(match).toBeDefined();
    });
  });

  describe("matchEvents", () => {
    it("batch matches multiple events", () => {
      const db = new IocDatabase();
      db.addEntry({ indicator: "evil.com", iocType: "domain" });

      const events = [
        makeEvent("connected to evil.com"),
        makeEvent("connected to good.com"),
        makeEvent("dns query evil.com"),
      ];

      const matches = db.matchEvents(events);
      expect(matches).toHaveLength(2);
    });
  });
});

// ---------------------------------------------------------------------------
// File loaders
// ---------------------------------------------------------------------------

describe("IocDatabase file loaders", () => {
  it("loads text file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioc-test-"));
    const filePath = path.join(dir, "iocs.txt");
    await fs.writeFile(
      filePath,
      [
        "# comment line",
        "a".repeat(64),
        "",
        "evil.com",
        "192.168.1.1",
      ].join("\n")
    );

    const db = await IocDatabase.loadTextFile(filePath);
    expect(db.size).toBe(3);

    await fs.rm(dir, { recursive: true });
  });

  it("loads CSV file with header", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioc-test-"));
    const filePath = path.join(dir, "iocs.csv");
    await fs.writeFile(
      filePath,
      [
        "indicator,type,description,source",
        `${"a".repeat(64)},sha256,Bad file,ThreatFeed`,
        "evil.com,domain,C2 domain,Intel",
      ].join("\n")
    );

    const db = await IocDatabase.loadCsvFile(filePath);
    expect(db.size).toBe(2);

    await fs.rm(dir, { recursive: true });
  });

  it("loads CSV file without header", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioc-test-"));
    const filePath = path.join(dir, "iocs.csv");
    await fs.writeFile(
      filePath,
      [`${"a".repeat(64)},sha256,Bad file,ThreatFeed`].join("\n")
    );

    const db = await IocDatabase.loadCsvFile(filePath);
    expect(db.size).toBe(1);

    await fs.rm(dir, { recursive: true });
  });

  it("loads CSV with quoted fields", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioc-test-"));
    const filePath = path.join(dir, "iocs.csv");
    await fs.writeFile(
      filePath,
      [
        "indicator,type,description,source",
        `evil.com,domain,"C2 domain, dangerous","Intel Feed"`,
      ].join("\n")
    );

    const db = await IocDatabase.loadCsvFile(filePath);
    expect(db.size).toBe(1);

    await fs.rm(dir, { recursive: true });
  });

  it("loads STIX 2.1 bundle", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioc-test-"));
    const filePath = path.join(dir, "bundle.json");

    const bundle = {
      type: "bundle",
      id: "bundle--test",
      objects: [
        {
          type: "indicator",
          id: "indicator--1",
          pattern: "[file:hashes.SHA-256 = 'aaaa']",
          description: "Malicious file",
          name: "TestFeed",
        },
        {
          type: "indicator",
          id: "indicator--2",
          pattern: "[domain-name:value = 'evil.com']",
          description: "C2 domain",
        },
        {
          type: "indicator",
          id: "indicator--3",
          pattern: "[ipv4-addr:value = '10.0.0.1']",
        },
        {
          type: "indicator",
          id: "indicator--4",
          pattern: "[url:value = 'http://evil.com/payload']",
        },
        {
          type: "malware",
          id: "malware--1",
          name: "TestMalware",
        },
      ],
    };

    await fs.writeFile(filePath, JSON.stringify(bundle));

    const db = await IocDatabase.loadStixBundle(filePath);
    expect(db.size).toBe(4);

    await fs.rm(dir, { recursive: true });
  });

  it("STIX loader rejects missing objects array", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioc-test-"));
    const filePath = path.join(dir, "bad.json");
    await fs.writeFile(filePath, JSON.stringify({ type: "bundle" }));

    await expect(IocDatabase.loadStixBundle(filePath)).rejects.toThrow(
      "missing 'objects' array"
    );

    await fs.rm(dir, { recursive: true });
  });
});
