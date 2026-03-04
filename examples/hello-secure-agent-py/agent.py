"""Secure AI agent demo using Clawdstrike + OpenAI Agents SDK.

Run in dry-run mode (no API key required):
    python agent.py --dry-run

Run with a live OpenAI agent (requires OPENAI_API_KEY):
    python agent.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.parse

from clawdstrike import Clawdstrike


def main() -> None:
    dry_run = "--dry-run" in sys.argv

    # Load policy from the YAML file next to this script.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    policy_path = os.path.join(script_dir, "policy.yaml")

    cs = Clawdstrike.from_policy(policy_path)
    session = cs.session(agent_id="hello-secure-agent")

    # -- Tool definitions with inline security checks -------------------------

    def read_file(path: str) -> str:
        """Read a file from disk after checking the security policy."""
        decision = session.check_file(path)
        if decision.denied:
            return f"BLOCKED by {decision.guard}: {decision.message}"
        try:
            with open(path) as f:
                return f.read()
        except OSError as exc:
            return f"OS error: {exc}"

    def run_command(cmd: str) -> str:
        """Run a shell command after checking the security policy."""
        decision = session.check_command(cmd)
        if decision.denied:
            return f"BLOCKED by {decision.guard}: {decision.message}"
        try:
            return subprocess.check_output(cmd, shell=True, text=True, timeout=10)
        except subprocess.CalledProcessError as exc:
            return f"Command failed (exit {exc.returncode}): {exc.output}"
        except subprocess.TimeoutExpired:
            return "Command timed out"

    def fetch_url(url: str) -> str:
        """Fetch a URL after checking the security policy."""
        host = urllib.parse.urlparse(url).hostname or ""
        decision = session.check_network(host)
        if decision.denied:
            return f"BLOCKED by {decision.guard}: {decision.message}"
        import requests  # noqa: E402  (lazy import -- only needed when allowed)

        try:
            resp = requests.get(url, timeout=10)
            return resp.text[:500]
        except requests.RequestException as exc:
            return f"Request error: {exc}"

    # -- Run ------------------------------------------------------------------

    if dry_run:
        _run_dry(read_file, run_command, fetch_url)
    else:
        _run_agent(read_file, run_command, fetch_url)

    # Print session summary regardless of mode.
    summary = session.get_summary()
    print("\n=== Session Summary ===")
    print(f"Total checks: {summary.check_count}")
    print(f"Allowed:      {summary.allow_count}")
    print(f"Denied:       {summary.deny_count}")
    if summary.blocked_actions:
        print(f"Blocked:      {summary.blocked_actions}")


def _run_dry(
    read_file,
    run_command,
    fetch_url,
) -> None:
    """Run six demo scenarios without an API key."""
    print("=== Clawdstrike Security Demo (dry-run) ===\n")

    # Set up a workspace file for the allowed-read scenario.
    os.makedirs("/tmp/workspace", exist_ok=True)
    with open("/tmp/workspace/notes.txt", "w") as f:
        f.write("Hello from the secure agent!")

    scenarios: list[tuple[str, object]] = [
        ("Read allowed file (/tmp/workspace/notes.txt)", lambda: read_file("/tmp/workspace/notes.txt")),
        ("Read blocked file (/etc/shadow)",              lambda: read_file("/etc/shadow")),
        ("Run allowed command (ls -la /tmp)",             lambda: run_command("ls -la /tmp")),
        ("Run blocked command (rm -rf /)",               lambda: run_command("rm -rf /")),
        ("Fetch allowed host (api.openai.com)",          lambda: fetch_url("https://api.openai.com")),
        ("Fetch blocked host (evil.com)",                lambda: fetch_url("https://evil.com")),
    ]

    for name, fn in scenarios:
        print(f"Scenario: {name}")
        result = fn()
        first_line = result.splitlines()[0] if result else "(empty)"
        print(f"  Result: {first_line}\n")


def _run_agent(
    read_file,
    run_command,
    fetch_url,
) -> None:
    """Run a live agent with the OpenAI Agents SDK."""
    try:
        from agents import Agent, Runner, function_tool  # type: ignore[import-untyped]
    except ImportError:
        print(
            "ERROR: openai-agents is not installed.\n"
            "Install it with:  pip install openai-agents\n"
            "Or run in dry-run mode:  python agent.py --dry-run",
            file=sys.stderr,
        )
        sys.exit(1)

    read_file_tool = function_tool(read_file)
    run_command_tool = function_tool(run_command)
    fetch_url_tool = function_tool(fetch_url)

    agent = Agent(
        name="secure-assistant",
        instructions=(
            "You are a helpful assistant with secure tool access. "
            "Try to help the user while respecting security policies."
        ),
        tools=[read_file_tool, run_command_tool, fetch_url_tool],
    )

    result = Runner.run_sync(agent, "List files in /tmp and read /tmp/workspace/notes.txt")
    print(result.final_output)


if __name__ == "__main__":
    main()
