---
description: "Run ClawdStrike self-test to verify all components are working"
---

# ClawdStrike Selftest

Run a comprehensive self-test to verify that all ClawdStrike components are operational. Reports PASS/FAIL for each check with an overall score.

## Steps

Run each of the following 6 checks in order. For each check, report PASS or FAIL with details.

### Check 1: CLI Binary

**What it tests**: The `clawdstrike` CLI binary is installed and executable.

**How to check**: Run `clawdstrike --version` using the Bash tool.

**PASS**: Command exits 0 and prints a version string.
**FAIL**: Command not found, permission denied, or non-zero exit.

**Remediation on failure**:
- Install the CLI: `cargo install --path crates/services/hush-cli`
- Verify it is on PATH: `which clawdstrike`
- If using a standalone binary, check file permissions: `chmod +x /path/to/clawdstrike`

### Check 2: hushd Connectivity

**What it tests**: The hushd daemon is reachable and responding.

**How to check**: Call the `clawdstrike_policy_show` MCP tool with no arguments. A successful response means hushd is connected.

**PASS**: Tool returns policy data (even if it is a default/empty policy).
**FAIL**: Connection refused, timeout, or error response.

**Remediation on failure**:
- Check if hushd is running: `ps aux | grep hushd`
- Start hushd if needed: `cargo run -p hushd`
- Verify the MCP server configuration points to the correct hushd endpoint
- Check `HUSHD_URL` environment variable

### Check 3: Policy Load

**What it tests**: A valid security policy is loaded and active.

**How to check**: Inspect the response from Check 2. Verify that it contains a `schema_version` field and at least one configured guard.

**PASS**: Policy contains a valid schema version and one or more guards.
**FAIL**: No policy loaded, schema version missing, or zero guards configured.

**Remediation on failure**:
- Load a policy: `clawdstrike check --ruleset default`
- Verify policy file exists and is valid YAML
- Check for syntax errors: use `clawdstrike_policy_lint` (Check 4)

### Check 4: Policy Lint

**What it tests**: The active policy passes schema validation with no errors.

**How to check**: Call the `clawdstrike_policy_lint` MCP tool on the active policy.

**PASS**: Lint returns zero errors (warnings are acceptable).
**FAIL**: Lint returns one or more errors.

**Remediation on failure**:
- Review the lint errors -- they indicate specific schema violations
- Check `schema_version` matches the expected format (e.g., "1.2.0")
- Validate guard names are spelled correctly
- Ensure required fields are present for each guard configuration

### Check 5: MCP Tool Ping

**What it tests**: The ClawdStrike MCP tools are registered and responsive.

**How to check**: Call `clawdstrike_policy_eval` with a simple test action: `action_type=file`, `target=/tmp/selftest-probe`. This tests that the MCP tool pipeline is working end-to-end.

**PASS**: Tool returns a verdict (allow or deny) with guard evaluation results.
**FAIL**: Tool not found, connection error, or malformed response.

**Remediation on failure**:
- Verify the MCP server is configured in your Claude settings
- Check that the clawdstrike MCP server process is running
- Restart the MCP server and retry
- Check MCP server logs for errors

### Check 6: Receipt Directory Writable

**What it tests**: The receipt storage directory exists and is writable (receipts are signed attestations of security decisions).

**How to check**: Run the following using the Bash tool:
```
test -d "${CLAWDSTRIKE_RECEIPT_DIR:-$HOME/.clawdstrike/receipts}" && \
  test -w "${CLAWDSTRIKE_RECEIPT_DIR:-$HOME/.clawdstrike/receipts}" && \
  echo "writable" || echo "not writable"
```

**PASS**: Directory exists and is writable.
**FAIL**: Directory does not exist or is not writable.

**Remediation on failure**:
- Create the directory: `mkdir -p "${CLAWDSTRIKE_RECEIPT_DIR:-$HOME/.clawdstrike/receipts}"`
- Fix permissions: `chmod 700 "$HOME/.clawdstrike/receipts"`
- If using a custom path, verify `CLAWDSTRIKE_RECEIPT_DIR` is set correctly

## Output Format

After running all checks, present results in this format:

```
ClawdStrike Self-Test Results
=============================

[PASS] CLI Binary          - clawdstrike v0.1.x
[PASS] hushd Connectivity  - Connected
[PASS] Policy Load         - schema v1.2.0, 6 guards active
[FAIL] Policy Lint         - 2 errors found
[PASS] MCP Tool Ping       - policy_eval responded in Xms
[PASS] Receipt Directory   - ~/.clawdstrike/receipts writable

Overall: 5/6 checks passed

Recommended actions:
1. [From failed check] Specific remediation step
```

If all 6 checks pass, end with:
```
Overall: 6/6 checks passed -- ClawdStrike is fully operational.
```
