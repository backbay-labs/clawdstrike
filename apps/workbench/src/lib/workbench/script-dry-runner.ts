import type { WorkbenchPolicy, Verdict, TestActionType, TestScenario } from "./types";
import { simulatePolicy } from "./simulation-engine";


export interface DryRunResult {
  scenarioName: string;
  action: string;
  target: string;
  verdict: Verdict;
  guard: string | null;
  passed: boolean | null;
  expected: string | null;
}

export interface DryRunOutput {
  results: DryRunResult[];
  terminalOutput: string;
  total: number;
  passed: number;
  failed: number;
  durationMs: number;
}


const ACTION_STRING_MAP: Record<string, TestActionType> = {
  file_access: "file_access",
  file_read: "file_access",
  read: "file_access",
  file_write: "file_write",
  write: "file_write",
  network_egress: "network_egress",
  network: "network_egress",
  egress: "network_egress",
  shell_command: "shell_command",
  command: "shell_command",
  shell: "shell_command",
  mcp_tool_call: "mcp_tool_call",
  mcp_tool: "mcp_tool_call",
  mcp: "mcp_tool_call",
  patch_apply: "patch_apply",
  patch: "patch_apply",
  user_input: "user_input",
  input: "user_input",
  prompt: "user_input",
};

function mapAction(raw: string): TestActionType {
  const key = raw.trim().toLowerCase();
  return ACTION_STRING_MAP[key] || "shell_command";
}


function buildPayload(
  actionType: TestActionType,
  target: string,
): Record<string, unknown> {
  switch (actionType) {
    case "file_access":
    case "file_write":
    case "patch_apply":
      return { path: target };
    case "network_egress":
      return { host: target };
    case "shell_command":
      return { command: target };
    case "mcp_tool_call":
      return { tool: target };
    case "user_input":
      return { text: target };
    default:
      return { target };
  }
}


interface ExtractedScenario {
  name: string;
  action: string;
  target: string;
  expected: string | null;
}


function parsePythonScenarios(script: string): ExtractedScenario[] {
  const scenarios: ExtractedScenario[] = [];

  // Pattern 1: runner.check("name", "action", "target", expect="verdict")
  // Handles both single and double quotes, with or without expect
  const checkPattern =
    /runner\.check\(\s*(['"])(.*?)\1\s*,\s*(['"])(.*?)\3\s*,\s*(['"])(.*?)\5(?:\s*,\s*expect\s*=\s*(['"])(.*?)\7)?\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = checkPattern.exec(script)) !== null) {
    scenarios.push({
      name: match[2],
      action: match[4],
      target: match[6],
      expected: match[8] || null,
    });
  }

  // Pattern 2: Tuple list — ("name", "action", "target", "expect") in a list
  const tuplePattern =
    /\(\s*(['"])(.*?)\1\s*,\s*(['"])(.*?)\3\s*,\s*(['"])(.*?)\5\s*,\s*(['"])(.*?)\7\s*\)/g;
  while ((match = tuplePattern.exec(script)) !== null) {
    // Skip if this is already inside a runner.check call (avoid duplicates)
    const before = script.slice(Math.max(0, match.index - 30), match.index);
    if (before.includes("runner.check")) continue;

    scenarios.push({
      name: match[2],
      action: match[4],
      target: match[6],
      expected: match[8] || null,
    });
  }

  // Pattern 3: cs.check_file("target") style
  const checkFilePattern = /cs\.check_file\(\s*(['"])(.*?)\1/g;
  while ((match = checkFilePattern.exec(script)) !== null) {
    scenarios.push({
      name: `check_file(${match[2]})`,
      action: "file_access",
      target: match[2],
      expected: null,
    });
  }

  // Pattern 4: cs.check_command("target") style
  const checkCommandPattern = /cs\.check_command\(\s*(['"])(.*?)\1/g;
  while ((match = checkCommandPattern.exec(script)) !== null) {
    scenarios.push({
      name: `check_command(${match[2]})`,
      action: "shell_command",
      target: match[2],
      expected: null,
    });
  }

  // Pattern 5: cs.check_network("target") style
  const checkNetworkPattern = /cs\.check_network\(\s*(['"])(.*?)\1/g;
  while ((match = checkNetworkPattern.exec(script)) !== null) {
    scenarios.push({
      name: `check_network(${match[2]})`,
      action: "network_egress",
      target: match[2],
      expected: null,
    });
  }

  // Pattern 6: YAML-embedded scenarios in ScenarioSuite.from_yaml("""...""")
  const yamlBlockPattern = /ScenarioSuite\.from_yaml\(\s*"{3}([\s\S]*?)"{3}\s*\)/g;
  while ((match = yamlBlockPattern.exec(script)) !== null) {
    const yamlContent = match[1];
    // Simple line-based extraction — not a full YAML parser
    const scenarioBlocks = yamlContent.split(/^\s*-\s+name:/m);
    for (let i = 1; i < scenarioBlocks.length; i++) {
      const block = "name:" + scenarioBlocks[i];
      const nameMatch = block.match(/name:\s*['"]?(.*?)['"]?\s*$/m);
      const actionMatch = block.match(/action:\s*['"]?(.*?)['"]?\s*$/m);
      const targetMatch = block.match(/target:\s*['"]?(.*?)['"]?\s*$/m);
      const expectMatch = block.match(/expect:\s*['"]?(.*?)['"]?\s*$/m);
      if (nameMatch && actionMatch && targetMatch) {
        scenarios.push({
          name: nameMatch[1].trim(),
          action: actionMatch[1].trim(),
          target: targetMatch[1].trim(),
          expected: expectMatch ? expectMatch[1].trim() : null,
        });
      }
    }
  }

  return scenarios;
}


function parseTypeScriptScenarios(script: string): ExtractedScenario[] {
  const scenarios: ExtractedScenario[] = [];
  let match: RegExpExecArray | null;

  // Pattern 1: cs.checkFile("target")
  const checkFilePattern = /cs\.checkFile\(\s*(['"`])(.*?)\1/g;
  while ((match = checkFilePattern.exec(script)) !== null) {
    scenarios.push({
      name: `checkFile(${match[2]})`,
      action: "file_access",
      target: match[2],
      expected: null,
    });
  }

  // Pattern 2: cs.checkCommand("target")
  const checkCommandPattern = /cs\.checkCommand\(\s*(['"`])(.*?)\1/g;
  while ((match = checkCommandPattern.exec(script)) !== null) {
    scenarios.push({
      name: `checkCommand(${match[2]})`,
      action: "shell_command",
      target: match[2],
      expected: null,
    });
  }

  // Pattern 3: cs.checkNetwork("target")
  const checkNetworkPattern = /cs\.checkNetwork\(\s*(['"`])(.*?)\1/g;
  while ((match = checkNetworkPattern.exec(script)) !== null) {
    scenarios.push({
      name: `checkNetwork(${match[2]})`,
      action: "network_egress",
      target: match[2],
      expected: null,
    });
  }

  // Pattern 4: cs.check({ type: "action", target: "target" }) or cs.check({ action: "...", target: "..." })
  const checkObjPattern =
    /cs\.check\(\s*\{\s*(?:type|action)\s*:\s*(['"`])(.*?)\1\s*,\s*target\s*:\s*(['"`])(.*?)\3/g;
  while ((match = checkObjPattern.exec(script)) !== null) {
    scenarios.push({
      name: `check(${match[2]}, ${match[4]})`,
      action: match[2],
      target: match[4],
      expected: null,
    });
  }

  // Pattern 5: engine.check({ action: "action", target: "target" })
  const engineCheckPattern =
    /engine\.check\(\s*\{\s*(?:type|action)\s*:\s*(['"`])(.*?)\1\s*,\s*target\s*:\s*(['"`])(.*?)\3/g;
  while ((match = engineCheckPattern.exec(script)) !== null) {
    scenarios.push({
      name: `engine.check(${match[2]}, ${match[4]})`,
      action: match[2],
      target: match[4],
      expected: null,
    });
  }

  // Pattern 6: Named checks array — { name: "...", fn: () => cs.checkFile("...") }
  const namedCheckFilePattern =
    /name:\s*(['"`])(.*?)\1\s*,\s*fn:\s*\(\)\s*=>\s*cs\.checkFile\(\s*(['"`])(.*?)\3\)/g;
  while ((match = namedCheckFilePattern.exec(script)) !== null) {
    // Avoid duplicate if we already captured from cs.checkFile above
    const existingIdx = scenarios.findIndex(
      (s) => s.target === match![4] && s.action === "file_access",
    );
    if (existingIdx >= 0) {
      scenarios[existingIdx].name = match[2];
    } else {
      scenarios.push({
        name: match[2],
        action: "file_access",
        target: match[4],
        expected: null,
      });
    }
  }

  const namedCheckCommandPattern =
    /name:\s*(['"`])(.*?)\1\s*,\s*fn:\s*\(\)\s*=>\s*cs\.checkCommand\(\s*(['"`])(.*?)\3\)/g;
  while ((match = namedCheckCommandPattern.exec(script)) !== null) {
    const existingIdx = scenarios.findIndex(
      (s) => s.target === match![4] && s.action === "shell_command",
    );
    if (existingIdx >= 0) {
      scenarios[existingIdx].name = match[2];
    } else {
      scenarios.push({
        name: match[2],
        action: "shell_command",
        target: match[4],
        expected: null,
      });
    }
  }

  const namedCheckNetworkPattern =
    /name:\s*(['"`])(.*?)\1\s*,\s*fn:\s*\(\)\s*=>\s*cs\.checkNetwork\(\s*(['"`])(.*?)\3\)/g;
  while ((match = namedCheckNetworkPattern.exec(script)) !== null) {
    const existingIdx = scenarios.findIndex(
      (s) => s.target === match![4] && s.action === "network_egress",
    );
    if (existingIdx >= 0) {
      scenarios[existingIdx].name = match[2];
    } else {
      scenarios.push({
        name: match[2],
        action: "network_egress",
        target: match[4],
        expected: null,
      });
    }
  }

  return scenarios;
}


function formatTerminalOutput(
  results: DryRunResult[],
  policyName: string,
  durationMs: number,
): string {
  const lines: string[] = [];
  const timestamp = new Date().toISOString();
  const passed = results.filter((r) => r.passed === true).length;
  const failed = results.filter((r) => r.passed === false).length;
  const noExpect = results.filter((r) => r.passed === null).length;

  lines.push("ClawdStrike Dry Run (simulated)");
  lines.push("================================");
  lines.push(`Policy: ${policyName}`);
  lines.push("Engine: workbench-simulator");
  lines.push(`Date:   ${timestamp}`);
  lines.push("");
  lines.push(`Running ${results.length} scenarios...`);
  lines.push("");

  for (const r of results) {
    const guardTag = r.guard ? `[${r.guard}]` : "";
    const simMs = Math.floor(Math.random() * 3) + 1;

    let icon: string;
    let suffix = "";
    if (r.passed === true) {
      icon = "\u2713";
    } else if (r.passed === false) {
      icon = "\u2717";
      suffix = ` (expected: ${r.expected})`;
    } else {
      icon = "?";
    }

    const verdictStr = r.verdict.toUpperCase().padEnd(5);
    const nameStr = r.scenarioName.padEnd(26);
    lines.push(
      `  ${icon} ${nameStr} ${verdictStr} ${guardTag.padEnd(22)} ${simMs}ms${suffix}`,
    );
  }

  lines.push("");
  lines.push("================================");

  const parts: string[] = [];
  parts.push(`${passed}/${results.length} passed`);
  if (failed > 0) parts.push(`${failed} failed`);
  if (noExpect > 0) parts.push(`${noExpect} unchecked`);

  lines.push(`Results: ${parts.join(", ")}`);
  lines.push(`Duration: ${durationMs}ms`);

  return lines.join("\n");
}


export function dryRunScript(
  scriptContent: string,
  policy: WorkbenchPolicy,
  language: "python" | "typescript",
): DryRunOutput {
  const start = performance.now();

  // Parse scenarios from the script
  const extracted =
    language === "python"
      ? parsePythonScenarios(scriptContent)
      : parseTypeScriptScenarios(scriptContent);

  const results: DryRunResult[] = [];

  for (let i = 0; i < extracted.length; i++) {
    const ext = extracted[i];
    const actionType = mapAction(ext.action);
    const payload = buildPayload(actionType, ext.target);

    const scenario: TestScenario = {
      id: `dry-run-${i}`,
      name: ext.name,
      description: `Dry run: ${ext.name}`,
      category: "benign",
      actionType,
      payload,
    };

    const simResult = simulatePolicy(policy, scenario);

    // Determine which guard drove the decision
    const denyGuard = simResult.guardResults.find((g) => g.verdict === "deny");
    const warnGuard = simResult.guardResults.find((g) => g.verdict === "warn");
    const drivingGuard = denyGuard || warnGuard || simResult.guardResults[0] || null;

    // Compare verdict to expectation
    let passed: boolean | null = null;
    if (ext.expected) {
      const normalizedExpected = ext.expected.toLowerCase().trim();
      passed = simResult.overallVerdict === normalizedExpected;
    }

    results.push({
      scenarioName: ext.name,
      action: ext.action,
      target: ext.target,
      verdict: simResult.overallVerdict,
      guard: drivingGuard?.guardId || null,
      passed,
      expected: ext.expected,
    });
  }

  const durationMs = Math.round(performance.now() - start);

  const passedCount = results.filter((r) => r.passed === true).length;
  const failedCount = results.filter((r) => r.passed === false).length;

  const terminalOutput = formatTerminalOutput(results, policy.name, durationMs);

  return {
    results,
    terminalOutput,
    total: results.length,
    passed: passedCount,
    failed: failedCount,
    durationMs,
  };
}
