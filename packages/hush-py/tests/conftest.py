"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_policy_yaml() -> str:
    """Sample policy YAML for testing."""
    return """
version: "1.0.0"
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
def sample_secrets() -> list[str]:
    """Sample secret values for testing."""
    return [
        "sk-abc123secretkey",
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ]
