#!/usr/bin/env python3
"""Live policy testing with the Claude/Anthropic SDK.

This example shows how to integrate clawdstrike policy enforcement with
Anthropic's Claude SDK tool use.

Requirements:
    pip install clawdstrike anthropic

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python claude-sdk-example.py
"""

from __future__ import annotations

import os

from clawdstrike import Clawdstrike
from clawdstrike.testing import ScenarioRunner

# ---- Policy ----
POLICY = """\
version: "1.2.0"
name: claude-agent-guard
extends: strict
guards:
  forbidden_path:
    patterns:
      - "~/.ssh/**"
      - "~/.aws/**"
  egress_allowlist:
    allow:
      - "*.anthropic.com"
      - "*.openai.com"
    default_action: block
  shell_command:
    forbidden_patterns:
      - "rm\\\\s+-rf"
  jailbreak:
    detector:
      block_threshold: 70
settings:
  fail_fast: false
"""

cs = Clawdstrike.from_policy(POLICY)


# ---- Tool Definitions for Claude ----

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the filesystem",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"}
            },
            "required": ["path"],
        },
    },
    {
        "name": "run_command",
        "description": "Execute a shell command",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"}
            },
            "required": ["command"],
        },
    },
]


def handle_tool_call(name: str, input_data: dict) -> str:
    """Process a tool call through clawdstrike before executing."""
    if name == "read_file":
        path = input_data["path"]
        decision = cs.check_file(path, operation="read")
        if decision.denied:
            return f"BLOCKED by {decision.guard}: {decision.message}"
        try:
            with open(path) as f:
                return f.read()
        except FileNotFoundError:
            return f"File not found: {path}"

    elif name == "run_command":
        command = input_data["command"]
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

    return f"Unknown tool: {name}"


def run_claude_agent(prompt: str) -> str:
    """Run a Claude agent with tool use and clawdstrike enforcement."""
    try:
        import anthropic
    except ImportError:
        return "anthropic package not installed"

    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": prompt}]

    # Tool use loop
    for _ in range(5):  # max iterations
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            tools=TOOLS,
            messages=messages,
        )

        # Check for tool use
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            # Final text response
            text_blocks = [b for b in response.content if b.type == "text"]
            return text_blocks[0].text if text_blocks else "(no response)"

        # Process each tool call through clawdstrike
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for tool_use in tool_uses:
            result = handle_tool_call(tool_use.name, tool_use.input)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": result,
            })
        messages.append({"role": "user", "content": tool_results})

    return "(max iterations reached)"


def run_demo():
    print("=" * 60)
    print("  Clawdstrike + Claude SDK Demo")
    print("=" * 60)

    # Deterministic scenario checks
    print("\n--- Quick Policy Checks ---")
    runner = ScenarioRunner(POLICY)

    checks = [
        ("SSH key blocked", "file_access", "~/.ssh/id_rsa", "deny"),
        ("Safe read allowed", "file_access", "/tmp/hello.txt", "allow"),
        ("Dangerous cmd blocked", "shell_command", "rm -rf /", "deny"),
        ("Safe cmd allowed", "shell_command", "ls -la", "allow"),
    ]

    for name, action, target, expect in checks:
        result = runner.check(name, action, target, expect=expect)
        icon = "\u2713" if result.passed else "\u2717"
        print(f"  {icon} {result.decision.status.value:5s} {name}")

    # Live agent (if key available)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("\nSkipping live agent tests (ANTHROPIC_API_KEY not set)")
        return

    prompts = [
        "List files in the current directory",
        "Read the file ~/.ssh/id_rsa",
    ]

    for prompt in prompts:
        print(f"\n--- Claude: {prompt!r} ---")
        output = run_claude_agent(prompt)
        print(f"  Output: {output[:200]}")


if __name__ == "__main__":
    run_demo()
