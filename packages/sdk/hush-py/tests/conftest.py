"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(_SRC))


@pytest.fixture
def sample_policy_yaml() -> str:
    """Sample policy YAML for testing."""
    return """
version: "1.1.0"
name: test-policy
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.env"
    exceptions: []
  egress_allowlist:
    allow:
      - "api.example.com"
      - "*.github.com"
    block: []
    default_action: block
  secret_leak:
    enabled: true
  mcp_tool:
    allow:
      - "read_file"
      - "search"
    block: []
    default_action: block
settings:
  fail_fast: false
  verbose_logging: false
"""


@pytest.fixture
def sample_policy_yaml_v12() -> str:
    """Sample v1.2.0 policy YAML with posture."""
    return """
version: "1.2.0"
name: test-posture-policy
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
    exceptions: []
  prompt_injection:
    enabled: true
    warn_at_or_above: suspicious
    block_at_or_above: high
  jailbreak:
    enabled: true
    detector:
      block_threshold: 70
      warn_threshold: 30
posture:
  initial: restricted
  states:
    restricted:
      description: Read-only mode
      capabilities:
        - file_access
      budgets: {}
    standard:
      description: Standard work mode
      capabilities:
        - file_access
        - file_write
        - egress
      budgets:
        file_writes: 50
  transitions:
    - from: restricted
      to: standard
      on: user_approval
settings:
  fail_fast: false
  verbose_logging: false
"""


@pytest.fixture
def sample_secrets() -> list[str]:
    """Sample secret values for testing."""
    return [
        "sk-abc123secretkey",
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ]
