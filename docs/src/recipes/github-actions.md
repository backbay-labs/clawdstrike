# GitHub Actions

Integrate hushclaw into CI/CD pipelines.

## Overview

Run AI agents securely in GitHub Actions with policy enforcement.

## Quick Setup

### 1. Add Policy to Repo

Create `.hush/ci-policy.yaml`:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:cicd

egress:
  allowed_domains:
    - "api.github.com"
    - "api.anthropic.com"
    - "pypi.org"
    - "registry.npmjs.org"

filesystem:
  allowed_write_roots:
    - "${GITHUB_WORKSPACE}"
    - "/tmp"

limits:
  max_execution_seconds: 1800  # 30 min

on_violation: cancel
```

### 2. Create Workflow

Create `.github/workflows/ai-agent.yml`:

```yaml
name: AI Agent

on:
  push:
    branches: [main]
  pull_request:

jobs:
  run-agent:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install hush-cli
        run: |
          curl -L https://github.com/hushclaw/hushclaw/releases/latest/download/hush-cli-linux-x64 -o hush
          chmod +x hush
          sudo mv hush /usr/local/bin/

      - name: Run agent with security
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          hush run --policy .hush/ci-policy.yaml -- ./run-agent.sh

      - name: Upload security receipt
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-receipt
          path: .hush/receipts/
```

## Reusable Action

Create a reusable action for your org:

```yaml
# .github/actions/secure-agent/action.yml
name: 'Secure AI Agent'
description: 'Run AI agent with hushclaw security'

inputs:
  policy:
    description: 'Policy file path'
    default: '.hush/ci-policy.yaml'
  command:
    description: 'Command to run'
    required: true
  mode:
    description: 'Enforcement mode'
    default: 'deterministic'

runs:
  using: 'composite'
  steps:
    - name: Install hush-cli
      shell: bash
      run: |
        if ! command -v hush &> /dev/null; then
          curl -L https://github.com/hushclaw/hushclaw/releases/latest/download/hush-cli-linux-x64 -o /tmp/hush
          chmod +x /tmp/hush
          sudo mv /tmp/hush /usr/local/bin/hush
        fi

    - name: Run with security
      shell: bash
      run: |
        hush run \
          --policy ${{ inputs.policy }} \
          --mode ${{ inputs.mode }} \
          --receipt .hush/receipts/run-${{ github.run_id }}.json \
          -- ${{ inputs.command }}
```

Use it:

```yaml
- uses: ./.github/actions/secure-agent
  with:
    command: python agent.py
```

## CI Policy

Recommended CI-specific policy:

```yaml
# .hush/ci-policy.yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    # AI APIs
    - "api.anthropic.com"
    - "api.openai.com"

    # GitHub
    - "api.github.com"
    - "github.com"
    - "*.githubusercontent.com"

    # Package registries
    - "pypi.org"
    - "files.pythonhosted.org"
    - "registry.npmjs.org"
    - "crates.io"

filesystem:
  allowed_write_roots:
    - "${GITHUB_WORKSPACE}"
    - "/tmp"
    - "/home/runner/work"

  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".git/config"

execution:
  denied_patterns:
    - "rm -rf /"
    - "curl.*|.*bash"
    - "git push --force"

limits:
  max_execution_seconds: 1800

on_violation: cancel
```

## Security Scanning

Validate policies in PRs:

```yaml
name: Policy Validation

on:
  pull_request:
    paths:
      - '.hush/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install hush-cli
        run: |
          curl -L https://github.com/hushclaw/hushclaw/releases/latest/download/hush-cli-linux-x64 -o hush
          chmod +x hush

      - name: Validate policy
        run: |
          ./hush policy lint .hush/ci-policy.yaml

      - name: Check for weakened security
        run: |
          # Compare with base branch
          git fetch origin ${{ github.base_ref }}
          ./hush policy diff origin/${{ github.base_ref }}:.hush/ci-policy.yaml .hush/ci-policy.yaml
```

## Matrix Testing

Test with different policies:

```yaml
jobs:
  test:
    strategy:
      matrix:
        policy: [strict, default, permissive]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run with ${{ matrix.policy }} policy
        run: |
          hush run --policy .hush/${{ matrix.policy }}-policy.yaml -- ./test.sh
```

## Receipt Verification

Verify receipts in downstream jobs:

```yaml
jobs:
  run-agent:
    runs-on: ubuntu-latest
    outputs:
      receipt: ${{ steps.run.outputs.receipt }}
    steps:
      - uses: actions/checkout@v4
      - id: run
        run: |
          RECEIPT=".hush/receipts/run-${{ github.run_id }}.json"
          hush run --policy .hush/policy.yaml --receipt $RECEIPT -- ./agent.sh
          echo "receipt=$RECEIPT" >> $GITHUB_OUTPUT
      - uses: actions/upload-artifact@v4
        with:
          name: receipt
          path: ${{ steps.run.outputs.receipt }}

  verify:
    needs: run-agent
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: receipt
      - run: hush verify *.json
```

## Environment Variables

Common CI variables:

```yaml
env:
  HUSHCLAW_POLICY: .hush/ci-policy.yaml
  HUSH_LOG_LEVEL: info
  HUSH_LOG_FORMAT: json
```

## Troubleshooting

### Network access blocked

Add domains to allowlist:

```yaml
egress:
  allowed_domains:
    - "your-api.example.com"
```

### Write permission denied

Check workspace path:

```yaml
filesystem:
  allowed_write_roots:
    - "${GITHUB_WORKSPACE}"
    - "/home/runner/work"
```

### Timeout issues

Increase limit:

```yaml
limits:
  max_execution_seconds: 3600  # 1 hour
```
