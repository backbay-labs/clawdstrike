import { describe, expect, it, afterEach } from "vitest";

import {
  detectFileType,
  getFileTypeByExtension,
  registerFileType,
  unregisterFileType,
  getAllFileTypes,
  getDescriptor,
  FILE_TYPE_REGISTRY,
} from "../file-type-registry";
import type { ExplainabilityTrace } from "../detection-workflow/shared-types";

describe("file-type-registry", () => {
  it("treats json extensions as ambiguous until content is inspected", () => {
    expect(getFileTypeByExtension("event.json")).toBeNull();
    expect(getFileTypeByExtension("policy.json")).toBeNull();
  });

  it("detects JSON policy exports as clawdstrike_policy", () => {
    const content = JSON.stringify({
      schema_version: "1.5.0",
      guards: {
        forbidden_path: {
          enabled: true,
        },
      },
    });

    expect(detectFileType("policy.json", content)).toBe("clawdstrike_policy");
  });

  it("detects structurally valid OCSF JSON as ocsf_event", () => {
    const content = JSON.stringify({
      class_uid: 2004,
      category_uid: 2,
      metadata: {
        version: "1.4.0",
      },
      finding_info: {
        title: "Suspicious event",
      },
    });

    expect(detectFileType("event.json", content)).toBe("ocsf_event");
  });

  it("does not classify arbitrary json files as ocsf_event", () => {
    const content = JSON.stringify({
      name: "fixture",
      version: "1.0.0",
    });

    expect(detectFileType("package.json", content)).toBe("clawdstrike_policy");
  });

  // Receipt / evidence file type tests
  describe("receipt file type", () => {
    it("detectFileType('agent.receipt', '...') returns 'receipt'", () => {
      expect(detectFileType("agent.receipt", "...")).toBe("receipt");
    });

    it("detectFileType('evidence.hush', '...') returns 'receipt'", () => {
      expect(detectFileType("evidence.hush", "...")).toBe("receipt");
    });

    it("getFileTypeByExtension('foo.receipt') returns 'receipt'", () => {
      expect(getFileTypeByExtension("foo.receipt")).toBe("receipt");
    });

    it("getFileTypeByExtension('foo.hush') returns 'receipt'", () => {
      expect(getFileTypeByExtension("foo.hush")).toBe("receipt");
    });

    it("FILE_TYPE_REGISTRY['receipt'] has iconColor '#7ee6f2', testable=false, extensions ['.receipt', '.hush']", () => {
      const descriptor = FILE_TYPE_REGISTRY["receipt"];
      expect(descriptor.iconColor).toBe("#7ee6f2");
      expect(descriptor.testable).toBe(false);
      expect(descriptor.extensions).toEqual([".receipt", ".hush"]);
    });
  });
});

// ---- Dynamic file type registration tests ----

describe("dynamic file type registration", () => {
  const snortDescriptor = {
    id: "snort_rule",
    label: "Snort Rule",
    shortLabel: "Snort",
    extensions: [".rules", ".snort"],
    iconColor: "#ff6b6b",
    defaultContent: "alert tcp any any -> any any (msg:\"test\"; sid:1;)",
    testable: false,
    convertibleTo: [] as string[],
  };

  // Cleanup any registered custom types after each test
  afterEach(() => {
    unregisterFileType("snort_rule");
    unregisterFileType("kql_query");
  });

  it("registerFileType() adds a custom file type visible in getAllFileTypes() and getDescriptor()", () => {
    const dispose = registerFileType(snortDescriptor);
    try {
      const all = getAllFileTypes();
      const snort = all.find((d) => d.id === "snort_rule");
      expect(snort).toBeDefined();
      expect(snort!.label).toBe("Snort Rule");
      expect(getDescriptor("snort_rule")).toEqual(snortDescriptor);
    } finally {
      dispose();
    }
  });

  it("registerFileType() returns a dispose function that removes the file type", () => {
    const dispose = registerFileType(snortDescriptor);
    expect(getAllFileTypes().some((d) => d.id === "snort_rule")).toBe(true);

    dispose();

    expect(getAllFileTypes().some((d) => d.id === "snort_rule")).toBe(false);
    expect(() => getDescriptor("snort_rule")).toThrow("Unknown file type: snort_rule");
  });

  it("registerFileType() throws if file type ID already exists", () => {
    const dispose = registerFileType(snortDescriptor);
    try {
      expect(() => registerFileType(snortDescriptor)).toThrow(
        'File type "snort_rule" is already registered',
      );
    } finally {
      dispose();
    }
  });

  it("unregisterFileType() removes a file type, no-op for unknown ID", () => {
    registerFileType(snortDescriptor);
    expect(getAllFileTypes().some((d) => d.id === "snort_rule")).toBe(true);

    unregisterFileType("snort_rule");
    expect(getAllFileTypes().some((d) => d.id === "snort_rule")).toBe(false);

    // No-op for unknown ID -- should not throw
    expect(() => unregisterFileType("nonexistent_type")).not.toThrow();
  });

  it("custom file type with detect function is used by detectFileType()", () => {
    const dispose = registerFileType({
      ...snortDescriptor,
      detect: (filename, content) =>
        filename.endsWith(".rules") || content.includes("alert tcp"),
    });

    try {
      // Custom detector matches content
      expect(detectFileType("unknown.txt", "alert tcp any any -> any any")).toBe("snort_rule");
    } finally {
      dispose();
    }
  });

  it("after unregistering, detectFileType() no longer matches custom detector", () => {
    const dispose = registerFileType({
      ...snortDescriptor,
      detect: (_filename, content) => content.includes("alert tcp"),
    });

    // Matches while registered
    expect(detectFileType("unknown.txt", "alert tcp any any")).toBe("snort_rule");

    dispose();

    // Falls back to default after unregistering
    expect(detectFileType("unknown.txt", "alert tcp any any")).toBe("clawdstrike_policy");
  });

  it("getFileTypeByExtension() resolves plugin-registered extensions", () => {
    const dispose = registerFileType(snortDescriptor);
    try {
      expect(getFileTypeByExtension("test.rules")).toBe("snort_rule");
      expect(getFileTypeByExtension("test.snort")).toBe("snort_rule");
    } finally {
      dispose();
    }
  });
});

// ---- FILE_TYPE_REGISTRY backward compatibility tests ----

describe("FILE_TYPE_REGISTRY backward compatibility", () => {
  it("FILE_TYPE_REGISTRY[id] returns the correct descriptor for built-in types", () => {
    const policy = FILE_TYPE_REGISTRY["clawdstrike_policy"];
    expect(policy).toBeDefined();
    expect(policy.id).toBe("clawdstrike_policy");
    expect(policy.label).toBe("ClawdStrike Policy");
  });

  it("Object.keys(FILE_TYPE_REGISTRY) returns all 4 built-in IDs", () => {
    const keys = Object.keys(FILE_TYPE_REGISTRY);
    expect(keys).toContain("clawdstrike_policy");
    expect(keys).toContain("sigma_rule");
    expect(keys).toContain("yara_rule");
    expect(keys).toContain("ocsf_event");
    expect(keys.length).toBeGreaterThanOrEqual(4);
  });

  it("after registering a custom file type, FILE_TYPE_REGISTRY[id] returns it", () => {
    const dispose = registerFileType({
      id: "kql_query",
      label: "KQL Query",
      shortLabel: "KQL",
      extensions: [".kql"],
      iconColor: "#9b59b6",
      defaultContent: "",
      testable: false,
      convertibleTo: [],
    });

    try {
      const kql = FILE_TYPE_REGISTRY["kql_query"];
      expect(kql).toBeDefined();
      expect(kql.id).toBe("kql_query");
      expect(kql.label).toBe("KQL Query");

      // Also visible in Object.keys
      expect(Object.keys(FILE_TYPE_REGISTRY)).toContain("kql_query");
    } finally {
      dispose();
    }
  });

  it("Object.values and Object.entries work through the proxy", () => {
    const values = Object.values(FILE_TYPE_REGISTRY);
    expect(values.length).toBeGreaterThanOrEqual(4);
    expect(values.every((v) => typeof v.id === "string" && typeof v.label === "string")).toBe(true);

    const entries = Object.entries(FILE_TYPE_REGISTRY);
    expect(entries.length).toBeGreaterThanOrEqual(4);
    for (const [key, val] of entries) {
      expect(key).toBe(val.id);
    }
  });
});

// ---- plugin_trace ExplainabilityTrace variant tests ----

describe("plugin_trace ExplainabilityTrace variant", () => {
  it("a plugin_trace object satisfies the ExplainabilityTrace type", () => {
    const trace: ExplainabilityTrace = {
      id: "trace-001",
      kind: "plugin_trace",
      caseId: "case-001",
      traceType: "snort_match",
      data: {
        matchedSignature: "ET MALWARE",
        severity: 3,
        protocol: "tcp",
      },
      sourceLineHints: [1, 5, 12],
    };

    // Runtime shape validation
    expect(trace.kind).toBe("plugin_trace");
    expect(trace.id).toBe("trace-001");
    expect(trace.caseId).toBe("case-001");

    // Narrow to plugin_trace variant and check fields
    if (trace.kind === "plugin_trace") {
      expect(trace.traceType).toBe("snort_match");
      expect(trace.data).toEqual({
        matchedSignature: "ET MALWARE",
        severity: 3,
        protocol: "tcp",
      });
      expect(trace.sourceLineHints).toEqual([1, 5, 12]);
    }
  });

  it("plugin_trace without optional sourceLineHints is valid", () => {
    const trace: ExplainabilityTrace = {
      id: "trace-002",
      kind: "plugin_trace",
      caseId: "case-002",
      traceType: "kql_result",
      data: { queryId: "q-123", rowCount: 42 },
    };

    expect(trace.kind).toBe("plugin_trace");
    if (trace.kind === "plugin_trace") {
      expect(trace.sourceLineHints).toBeUndefined();
    }
  });
});
