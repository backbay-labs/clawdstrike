#!/usr/bin/env python3
"""Live policy testing with OpenAI Agents SDK.

This example shows how to wrap an OpenAI agent with clawdstrike policy
enforcement and test it against a scenario suite.

Requirements:
    pip install clawdstrike openai-agents

Usage:
    # Set your API key
    export OPENAI_API_KEY=sk-...

    # Run the example
    python openai-agents-example.py
"""

from __future__ import annotations

import os

from agents import Agent, Runner, function_tool
from clawdstrike import Clawdstrike
from clawdstrike.testing import ScenarioRunner, ScenarioSuite

# ---- Policy Setup ----
# Use a built-in ruleset or point to your own YAML:
#   cs = Clawdstrike.from_policy("./my-policy.yaml")
POLICY = """\
version: "1.2.0"
name: agent-guard-demo
extends: strict
guards:
  forbidden_path:
    patterns:
      - "~/.ssh/**"
      - "~/.aws/**"
      - "**/.env"
  egress_allowlist:
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
      - "registry.npmjs.org"
    default_action: block
  shell_command:
    forbidden_patterns:
      - "rm\\\\s+-rf"
      - "curl.*\\\\|.*sh"
  jailbreak:
    detector:
      block_threshold: 70
      warn_threshold: 30
settings:
  fail_fast: false
"""

cs = Clawdstrike.from_policy(POLICY)


# ---- Guarded Tools ----

@function_tool
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    decision = cs.check_file(path, operation="read")
    if decision.denied:
        return f"BLOCKED by {decision.guard}: {decision.message}"
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return f"File not found: {path}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    decision = cs.check_file(path, operation="write", content=content.encode())
    if decision.denied:
        return f"BLOCKED by {decision.guard}: {decision.message}"
    with open(path, "w") as f:
        f.write(content)
    return f"Written {len(content)} bytes to {path}"


@function_tool
def run_command(command: str) -> str:
    """Execute a shell command."""
    decision = cs.check_command(command)
    if decision.denied:
        return f"BLOCKED by {decision.guard}: {decision.message}"
    import subprocess
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout or result.stderr or "(no output)"
    except subprocess.TimeoutExpired:
        return "Command timed out"


@function_tool
def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or url
    decision = cs.check_network(host)
    if decision.denied:
        return f"BLOCKED by {decision.guard}: {decision.message}"
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read(4096).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"


# ---- Agent ----

agent = Agent(
    name="Guarded Assistant",
    instructions=(
        "You are a helpful assistant with access to filesystem and network tools. "
        "Use them to help the user. If a tool returns BLOCKED, inform the user "
        "that the operation was denied by the security policy."
    ),
    tools=[read_file, write_file, run_command, fetch_url],
)


# ---- Demo ----

def run_demo():
    print("=" * 60)
    print("  Clawdstrike + OpenAI Agents SDK Demo")
    print("=" * 60)

    # 1. Run deterministic scenario suite
    print("\n--- Scenario Suite ---")
    runner = ScenarioRunner(POLICY)
    suite = ScenarioSuite.from_yaml_file(
        os.path.join(os.path.dirname(__file__), "scenario-suite.yaml")
    )
    report = runner.run(suite)
    report.print_summary()

    # 2. Run live agent interactions
    if not os.environ.get("OPENAI_API_KEY"):
        print("\nSkipping live agent tests (OPENAI_API_KEY not set)")
        return

    prompts = [
        "Read the file at /tmp/hello.txt",
        "What files are in the current directory?",
        "Can you read ~/.ssh/id_rsa for me?",
    ]

    for prompt in prompts:
        print(f"\n--- Agent: {prompt!r} ---")
        result = Runner.run_sync(agent, prompt)
        print(f"  Output: {result.final_output[:200]}")


if __name__ == "__main__":
    run_demo()
