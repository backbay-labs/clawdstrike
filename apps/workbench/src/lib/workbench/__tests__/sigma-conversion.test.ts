import { describe, it, expect, beforeAll } from "vitest";
import { convertSigmaToPolicy } from "../detection-workflow/sigma-conversion";
import { yamlToPolicy } from "../yaml-utils";
import { sigmaAdapter } from "../detection-workflow/sigma-adapter";

// Ensure adapter is registered (side-effect import)
beforeAll(() => {
  void sigmaAdapter;
});

// ---- Sigma YAML fixtures ----

const PROCESS_CREATION_RULE = `
title: Suspicious Process Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: test
description: Detects suspicious process execution via command line
author: Test Author
date: 2026/03/15
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - "powershell -enc"
      - "cmd /c whoami"
    Image|endswith:
      - "\\\\mimikatz.exe"
  condition: selection
falsepositives:
  - Unknown
level: high
`;

const FILE_EVENT_RULE = `
title: Sensitive File Access
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: test
description: Detects access to sensitive system files
author: Test Author
date: 2026/03/15
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|contains:
      - "\\\\etc\\\\shadow"
      - "\\\\etc\\\\passwd"
    SourceFilename|startswith:
      - "C:\\\\Users\\\\Public"
  condition: selection
falsepositives:
  - System administration
level: medium
`;

const NETWORK_CONNECTION_RULE = `
title: Suspicious Network Connection
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: test
description: Detects connections to known malicious domains
author: Test Author
date: 2026/03/15
logsource:
  category: network_connection
detection:
  selection:
    DestinationHostname|contains:
      - "evil.com"
      - "malware.cn"
    DestinationIp:
      - "192.168.1.100"
  condition: selection
falsepositives:
  - None known
level: critical
`;

const DNS_QUERY_RULE = `
title: DNS Query to Suspicious Domain
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: test
description: Detects DNS queries to suspicious domains
author: Test Author
date: 2026/03/15
logsource:
  category: dns
detection:
  selection:
    QueryName|endswith:
      - ".evil.com"
      - ".c2.net"
  condition: selection
falsepositives:
  - CDN lookups
level: medium
`;

const MULTI_SELECTION_RULE = `
title: Multi-Selection Detection
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: test
description: Rule with multiple selection conditions
author: Test Author
date: 2026/03/15
logsource:
  category: process_creation
  product: windows
detection:
  selection_cmd:
    CommandLine|contains:
      - "net user"
  selection_image:
    Image|endswith:
      - "\\\\cmd.exe"
  condition: selection_cmd or selection_image
falsepositives:
  - Admin scripts
level: low
`;

const REGISTRY_RULE = `
title: Suspicious Registry Modification
id: f6a7b8c9-d0e1-2345-fabc-456789012345
status: test
description: Detects suspicious registry changes
author: Test Author
date: 2026/03/15
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetFilename|contains:
      - "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
  condition: selection
falsepositives:
  - Installers
level: high
`;

const REGEX_MODIFIER_RULE = `
title: Regex Pattern Detection
id: a7b8c9d0-e1f2-3456-abcd-567890123456
status: test
description: Uses regex modifier for detection
author: Test Author
date: 2026/03/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re:
      - "powershell.*-[eE]nc.*[A-Za-z0-9+/]+"
  condition: selection
falsepositives:
  - Unknown
level: high
`;

const UNKNOWN_CATEGORY_RULE = `
title: Custom Category Detection
id: b8c9d0e1-f2a3-4567-bcde-678901234567
status: test
description: Rule with an unknown logsource category
author: Test Author
date: 2026/03/15
logsource:
  category: custom_telemetry
  product: linux
detection:
  selection:
    CommandLine|contains:
      - "suspicious_binary"
  condition: selection
falsepositives:
  - Unknown
level: medium
`;

const INFORMATIONAL_LEVEL_RULE = `
title: Informational Event
id: c9d0e1f2-a3b4-5678-cdef-789012345678
status: test
description: Low severity informational detection
author: Test Author
date: 2026/03/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - "ipconfig"
  condition: selection
falsepositives:
  - Normal usage
level: informational
`;

const NO_DETECTION_RULE = `
title: Broken Rule
id: d0e1f2a3-b4c5-6789-defa-890123456789
status: test
description: Missing detection
author: Test Author
date: 2026/03/15
logsource:
  category: process_creation
level: medium
`;

const STARTSWITH_RULE = `
title: StartsWith Detection
id: e1f2a3b4-c5d6-7890-efab-901234567890
status: test
description: Uses startswith modifier
author: Test Author
date: 2026/03/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|startswith:
      - "powershell"
      - "cmd.exe"
  condition: selection
falsepositives:
  - Unknown
level: medium
`;

// ---- Tests ----

describe("convertSigmaToPolicy", () => {
  it("converts process_creation rule to policy with shell_command guard", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    expect(result.policy).not.toBeNull();
    expect(result.policyYaml).not.toBeNull();

    const policy = result.policy!;
    expect(policy.guards.shell_command).toBeDefined();
    expect(policy.guards.shell_command!.enabled).toBe(true);
    expect(policy.guards.shell_command!.forbidden_patterns).toBeDefined();
    expect(policy.guards.shell_command!.forbidden_patterns!.length).toBeGreaterThan(0);

    // CommandLine|contains patterns should have wildcards
    expect(policy.guards.shell_command!.forbidden_patterns).toContain("*powershell -enc*");
    expect(policy.guards.shell_command!.forbidden_patterns).toContain("*cmd /c whoami*");

    // Image|endswith patterns should be basenames with prefix wildcard
    expect(policy.guards.shell_command!.forbidden_patterns).toContain("*mimikatz.exe");
  });

  it("converts file_event rule to policy with forbidden_path guard", () => {
    const result = convertSigmaToPolicy(FILE_EVENT_RULE);

    expect(result.success).toBe(true);
    expect(result.policy).not.toBeNull();

    const policy = result.policy!;
    expect(policy.guards.forbidden_path).toBeDefined();
    expect(policy.guards.forbidden_path!.enabled).toBe(true);
    expect(policy.guards.forbidden_path!.patterns).toBeDefined();
    expect(policy.guards.forbidden_path!.patterns!.length).toBeGreaterThan(0);
  });

  it("converts network_connection rule to policy with egress_allowlist guard", () => {
    const result = convertSigmaToPolicy(NETWORK_CONNECTION_RULE);

    expect(result.success).toBe(true);
    expect(result.policy).not.toBeNull();

    const policy = result.policy!;
    expect(policy.guards.egress_allowlist).toBeDefined();
    expect(policy.guards.egress_allowlist!.enabled).toBe(true);
    expect(policy.guards.egress_allowlist!.block).toBeDefined();
    expect(policy.guards.egress_allowlist!.block).toContain("*evil.com*");
    expect(policy.guards.egress_allowlist!.block).toContain("*malware.cn*");
    expect(policy.guards.egress_allowlist!.block).toContain("192.168.1.100");
    expect(policy.guards.egress_allowlist!.default_action).toBe("block");
  });

  it("handles |contains modifier (adds wildcards)", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    const patterns = result.policy!.guards.shell_command!.forbidden_patterns!;
    // Contains modifier wraps in wildcards
    expect(patterns.some((p) => p.startsWith("*") && p.endsWith("*"))).toBe(true);
  });

  it("handles |endswith modifier", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    const patterns = result.policy!.guards.shell_command!.forbidden_patterns!;
    // endswith adds prefix wildcard to basename
    expect(patterns.some((p) => p.startsWith("*") && p.endsWith(".exe"))).toBe(true);
  });

  it("handles |startswith modifier", () => {
    const result = convertSigmaToPolicy(STARTSWITH_RULE);

    expect(result.success).toBe(true);
    const patterns = result.policy!.guards.shell_command!.forbidden_patterns!;
    // startswith adds suffix wildcard
    expect(patterns).toContain("powershell*");
    expect(patterns).toContain("cmd.exe*");
  });

  it("handles |re modifier (preserves raw regex)", () => {
    const result = convertSigmaToPolicy(REGEX_MODIFIER_RULE);

    expect(result.success).toBe(true);
    const patterns = result.policy!.guards.shell_command!.forbidden_patterns!;
    // re modifier: no wildcard wrapping, pattern preserved as-is
    expect(patterns.some((p) => p.includes("powershell.*-[eE]nc"))).toBe(true);
    expect(patterns.some((p) => p.startsWith("*") || p.endsWith("*"))).toBe(false);
  });

  it("maps Sigma level critical/high to strict mode", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.extends).toBe("strict");
    expect(policy.settings.fail_fast).toBe(true);
    expect(policy.settings.verbose_logging).toBe(true);
  });

  it("maps Sigma level medium to default mode", () => {
    const result = convertSigmaToPolicy(FILE_EVENT_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.extends).toBeUndefined();
    expect(policy.settings.fail_fast).toBe(false);
  });

  it("maps Sigma level informational to permissive mode", () => {
    const result = convertSigmaToPolicy(INFORMATIONAL_LEVEL_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.extends).toBe("permissive");
    expect(policy.settings.fail_fast).toBe(false);
  });

  it("maps Sigma level low to permissive mode", () => {
    const result = convertSigmaToPolicy(MULTI_SELECTION_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.extends).toBe("permissive");
  });

  it("extracts title and description", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.name).toBe("Suspicious Process Execution");
    expect(policy.description).toContain("Detects suspicious process execution");
    expect(policy.description).toContain("Converted from Sigma rule");
    expect(policy.description).toContain("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
  });

  it("returns diagnostics for unconvertible rules (missing detection)", () => {
    const result = convertSigmaToPolicy(NO_DETECTION_RULE);

    // Should fail due to missing detection
    expect(result.success).toBe(false);
    expect(result.diagnostics.some((d) => d.severity === "error")).toBe(true);
  });

  it("produces valid YAML that can be parsed by yamlToPolicy", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    expect(result.policyYaml).not.toBeNull();

    const [parsed, errors] = yamlToPolicy(result.policyYaml!);
    expect(parsed).not.toBeNull();
    expect(errors).toHaveLength(0);
    expect(parsed!.version).toBe("1.2.0");
    expect(parsed!.name).toBe("Suspicious Process Execution");
  });

  it("field mappings track which Sigma fields mapped to which guard configs", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    expect(result.fieldMappings.length).toBeGreaterThan(0);

    // CommandLine should map to shell_command.forbidden_patterns
    const cmdMappings = result.fieldMappings.filter(
      (m) => m.sigmaField.startsWith("CommandLine"),
    );
    expect(cmdMappings.length).toBeGreaterThan(0);
    expect(cmdMappings[0].guardId).toBe("shell_command");
    expect(cmdMappings[0].guardField).toBe("forbidden_patterns");

    // Image should map to shell_command.forbidden_patterns
    const imgMappings = result.fieldMappings.filter(
      (m) => m.sigmaField.startsWith("Image"),
    );
    expect(imgMappings.length).toBeGreaterThan(0);
    expect(imgMappings[0].guardId).toBe("shell_command");
  });

  it("multiple selection conditions produce multiple guard entries", () => {
    const result = convertSigmaToPolicy(MULTI_SELECTION_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;

    // Both selection_cmd and selection_image should contribute to shell_command
    expect(policy.guards.shell_command).toBeDefined();
    expect(policy.guards.shell_command!.forbidden_patterns!.length).toBeGreaterThanOrEqual(2);
  });

  it("handles missing detection section gracefully", () => {
    const result = convertSigmaToPolicy(NO_DETECTION_RULE);

    expect(result.success).toBe(false);
    expect(result.policy).toBeNull();
    expect(result.policyYaml).toBeNull();
    expect(result.diagnostics.some((d) => d.severity === "error")).toBe(true);
  });

  it("handles unknown logsource categories (returns warning, produces best-effort output)", () => {
    const result = convertSigmaToPolicy(UNKNOWN_CATEGORY_RULE);

    expect(result.success).toBe(true);
    expect(result.policy).not.toBeNull();

    // Should have a warning about unknown category
    const warnings = result.diagnostics.filter((d) => d.severity === "warning");
    expect(warnings.some((w) => w.message.includes("Unknown logsource category"))).toBe(true);

    // Should still produce guard config via fallback to shell_command
    expect(result.policy!.guards.shell_command).toBeDefined();
  });

  it("maps DNS QueryName to egress_allowlist guard", () => {
    const result = convertSigmaToPolicy(DNS_QUERY_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.guards.egress_allowlist).toBeDefined();
    expect(policy.guards.egress_allowlist!.block).toBeDefined();
    expect(policy.guards.egress_allowlist!.block!.some((d) => d.includes(".evil.com"))).toBe(true);
    expect(policy.guards.egress_allowlist!.block!.some((d) => d.includes(".c2.net"))).toBe(true);
  });

  it("maps registry rules to forbidden_path guard", () => {
    const result = convertSigmaToPolicy(REGISTRY_RULE);

    expect(result.success).toBe(true);
    const policy = result.policy!;
    expect(policy.guards.forbidden_path).toBeDefined();
    expect(policy.guards.forbidden_path!.patterns!.length).toBeGreaterThan(0);
  });

  it("sets policy version to 1.2.0", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);

    expect(result.success).toBe(true);
    expect(result.policy!.version).toBe("1.2.0");
  });

  it("sets converter version", () => {
    const result = convertSigmaToPolicy(PROCESS_CREATION_RULE);
    expect(result.converterVersion).toBe("1.0.0");
  });

  it("returns error for invalid YAML", () => {
    const result = convertSigmaToPolicy(":::invalid yaml:::");
    expect(result.success).toBe(false);
    expect(result.diagnostics.some((d) => d.severity === "error")).toBe(true);
  });

  it("deduplicates patterns", () => {
    const rule = `
title: Duplicate Patterns
id: 11111111-2222-3333-4444-555555555555
status: test
description: Has duplicate patterns across selections
author: Test
date: 2026/03/15
logsource:
  category: process_creation
detection:
  selection_a:
    CommandLine|contains:
      - "whoami"
  selection_b:
    CommandLine|contains:
      - "whoami"
  condition: selection_a or selection_b
falsepositives:
  - Unknown
level: medium
`;
    const result = convertSigmaToPolicy(rule);
    expect(result.success).toBe(true);
    // After dedup, should have only one *whoami* pattern
    const patterns = result.policy!.guards.shell_command!.forbidden_patterns!;
    const whoamiPatterns = patterns.filter((p) => p.includes("whoami"));
    expect(whoamiPatterns).toHaveLength(1);
  });

  it("handles SourceFilename mapping to forbidden_path", () => {
    const result = convertSigmaToPolicy(FILE_EVENT_RULE);
    expect(result.success).toBe(true);

    // SourceFilename|startswith patterns should be in forbidden_path
    const mappings = result.fieldMappings.filter(
      (m) => m.sigmaField.startsWith("SourceFilename"),
    );
    expect(mappings.length).toBeGreaterThan(0);
    expect(mappings[0].guardId).toBe("forbidden_path");
  });
});

describe("sigma-adapter buildPublication with native_policy target", () => {
  it("uses sigma-to-policy converter for native_policy target", async () => {
    const result = await sigmaAdapter.buildPublication({
      document: {
        documentId: "doc-1",
        fileType: "sigma_rule",
        filePath: null,
        name: "Test Sigma",
        sourceHash: "abc",
      },
      source: PROCESS_CREATION_RULE,
      targetFormat: "native_policy",
    });

    // Manifest should record sigma-to-policy converter
    expect(result.manifest.converter.id).toBe("sigma-to-policy");
    expect(result.manifest.converter.version).toBe("1.0.0");
    expect(result.manifest.sourceFileType).toBe("sigma_rule");
    expect(result.manifest.target).toBe("native_policy");

    // Output should be policy YAML, not Sigma source
    expect(result.outputContent).toContain("version:");
    expect(result.outputContent).toContain("guards:");
    expect(result.outputContent).not.toContain("logsource:");
    expect(result.outputContent).not.toContain("detection:");
  });

  it("output hash covers the converted policy, not the Sigma source", async () => {
    const result = await sigmaAdapter.buildPublication({
      document: {
        documentId: "doc-1",
        fileType: "sigma_rule",
        filePath: null,
        name: "Test",
        sourceHash: "abc",
      },
      source: PROCESS_CREATION_RULE,
      targetFormat: "native_policy",
    });

    // sourceHash and outputHash should differ (different content)
    expect(result.manifest.sourceHash).not.toBe(result.manifest.outputHash);
    // outputHash should match what's reported
    expect(result.outputHash).toBe(result.manifest.outputHash);
  });

  it("uses sigma-to-policy converter for fleet_deploy target", async () => {
    const result = await sigmaAdapter.buildPublication({
      document: {
        documentId: "doc-1",
        fileType: "sigma_rule",
        filePath: null,
        name: "Test",
        sourceHash: "abc",
      },
      source: PROCESS_CREATION_RULE,
      targetFormat: "fleet_deploy",
    });

    expect(result.manifest.converter.id).toBe("sigma-to-policy");
    expect(result.manifest.target).toBe("fleet_deploy");
  });

  it("produces structured JSON export for json_export target", async () => {
    const result = await sigmaAdapter.buildPublication({
      document: {
        documentId: "doc-1",
        fileType: "sigma_rule",
        filePath: null,
        name: "Test",
        sourceHash: "abc",
      },
      source: PROCESS_CREATION_RULE,
      targetFormat: "json_export",
    });

    expect(result.manifest.converter.id).toBe("sigma-to-json");
    const parsed = JSON.parse(result.outputContent);
    expect(parsed._meta).toBeDefined();
    expect(parsed._meta.converter).toBe("sigma-to-json");
    expect(parsed.rule).toBeDefined();
    expect(parsed.rule.title).toBeDefined();
    expect(parsed.rule.detection).toBeDefined();
  });

  it("includes run snapshot when labRunId and evidencePackId are provided", async () => {
    const result = await sigmaAdapter.buildPublication({
      document: {
        documentId: "doc-1",
        fileType: "sigma_rule",
        filePath: null,
        name: "Test",
        sourceHash: "abc",
      },
      source: PROCESS_CREATION_RULE,
      targetFormat: "native_policy",
      evidencePackId: "pack-1",
      labRunId: "run-1",
    });

    expect(result.manifest.runSnapshot).not.toBeNull();
    expect(result.manifest.runSnapshot!.evidencePackId).toBe("pack-1");
    expect(result.manifest.runSnapshot!.labRunId).toBe("run-1");
    expect(result.manifest.runSnapshot!.passed).toBe(true);
  });

  it("throws on unconvertible Sigma for native_policy target", async () => {
    await expect(
      sigmaAdapter.buildPublication({
        document: {
          documentId: "doc-1",
          fileType: "sigma_rule",
          filePath: null,
          name: "Test",
          sourceHash: "abc",
        },
        source: ":::invalid:::",
        targetFormat: "native_policy",
      }),
    ).rejects.toThrow("Sigma to policy conversion failed");
  });
});
