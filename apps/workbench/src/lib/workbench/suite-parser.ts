import YAML from "yaml";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SuiteScenario {
  id: string;
  name: string;
  action: string;
  target: string;
  expect?: string;
  expect_guard?: string;
  content?: string;
  payload?: Record<string, unknown>;
  tags?: string[];
  description?: string;
}

export interface ParsedSuite {
  scenarios: SuiteScenario[];
  name?: string;
  policy?: string;
  errors: string[];
}

// ---------------------------------------------------------------------------
// Deterministic ID generation
// ---------------------------------------------------------------------------

function deterministicId(name: string, index: number): string {
  // Simple deterministic ID from scenario name + index
  let hash = 0;
  const str = `${name}::${index}`;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return `sc-${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/**
 * Parse a scenario suite YAML string into typed objects.
 * Returns `{ scenarios: [], errors: [...] }` on invalid input so callers
 * never need to handle exceptions.
 */
export function parseSuiteYaml(yamlStr: string): ParsedSuite {
  const empty: ParsedSuite = { scenarios: [], errors: [] };

  if (!yamlStr || yamlStr.trim() === "") {
    return { ...empty, errors: ["Empty YAML input"] };
  }

  let doc: unknown;
  try {
    doc = YAML.parse(yamlStr, { maxAliasCount: 0, uniqueKeys: true });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Invalid YAML";
    return { ...empty, errors: [msg] };
  }

  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { ...empty, errors: ["YAML must be a mapping/object with a 'scenarios' key"] };
  }

  const root = doc as Record<string, unknown>;
  const errors: string[] = [];

  const name = typeof root.name === "string" ? root.name : undefined;
  const policy = typeof root.policy === "string" ? root.policy : undefined;

  if (!root.scenarios) {
    return { scenarios: [], name, policy, errors: ["Missing 'scenarios' key"] };
  }

  if (!Array.isArray(root.scenarios)) {
    return { scenarios: [], name, policy, errors: ["'scenarios' must be an array"] };
  }

  const scenarios: SuiteScenario[] = [];

  for (let i = 0; i < root.scenarios.length; i++) {
    const raw = root.scenarios[i];
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      errors.push(`scenarios[${i}]: must be an object`);
      continue;
    }

    const entry = raw as Record<string, unknown>;

    // name is required
    if (typeof entry.name !== "string" || entry.name.trim() === "") {
      errors.push(`scenarios[${i}]: missing or empty 'name'`);
      continue;
    }

    // action is required
    if (typeof entry.action !== "string" || entry.action.trim() === "") {
      errors.push(`scenarios[${i}] (${entry.name}): missing or empty 'action'`);
      continue;
    }

    // target is required
    if (entry.target === undefined || entry.target === null) {
      errors.push(`scenarios[${i}] (${entry.name}): missing 'target'`);
      continue;
    }

    const scenario: SuiteScenario = {
      id: deterministicId(String(entry.name).trim(), i),
      name: String(entry.name).trim(),
      action: String(entry.action).trim(),
      target: String(entry.target).trim(),
    };

    if (typeof entry.expect === "string") {
      scenario.expect = entry.expect.trim();
    }
    if (typeof entry.expect_guard === "string") {
      scenario.expect_guard = entry.expect_guard.trim();
    }
    if (typeof entry.content === "string") {
      scenario.content = entry.content;
    }
    if (entry.payload && typeof entry.payload === "object" && !Array.isArray(entry.payload)) {
      scenario.payload = entry.payload as Record<string, unknown>;
    }
    if (Array.isArray(entry.tags)) {
      scenario.tags = entry.tags.filter((t): t is string => typeof t === "string");
    }
    if (typeof entry.description === "string") {
      scenario.description = entry.description;
    }

    scenarios.push(scenario);
  }

  return { scenarios, name, policy, errors };
}

// ---------------------------------------------------------------------------
// Serialize
// ---------------------------------------------------------------------------

/**
 * Serialize an array of SuiteScenario objects back to YAML.
 * Produces a clean document suitable for editing in the suite textarea.
 */
export function suiteScenariosToYaml(scenarios: SuiteScenario[], name?: string): string {
  const doc: Record<string, unknown> = {};

  if (name) {
    doc.name = name;
  }

  doc.scenarios = scenarios.map((s) => {
    const entry: Record<string, unknown> = {
      name: s.name,
      action: s.action,
      target: s.target,
    };
    if (s.expect) entry.expect = s.expect;
    if (s.expect_guard) entry.expect_guard = s.expect_guard;
    if (s.content) entry.content = s.content;
    if (s.payload && Object.keys(s.payload).length > 0) entry.payload = s.payload;
    if (s.tags && s.tags.length > 0) entry.tags = s.tags;
    if (s.description) entry.description = s.description;
    return entry;
  });

  return YAML.stringify(doc, {
    indent: 2,
    lineWidth: 120,
    defaultStringType: "QUOTE_DOUBLE",
    defaultKeyType: "PLAIN",
  });
}
