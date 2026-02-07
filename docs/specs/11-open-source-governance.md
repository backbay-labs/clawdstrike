# Spec 11: Open Source Governance

> **Status:** Draft | **Date:** 2026-02-07
> **Author:** Phase C Spec Agent
> **Effort estimate:** 3-4 engineer-days
> **Dependencies:** Spec 04 (Apache 2.0 license migration) for license references in CONTRIBUTING.md

---

## Summary / Objective

Upgrade the project's open source governance infrastructure for a public launch: overhaul `CONTRIBUTING.md` to reflect the full SDR stack (Spine, bridges, marketplace, desktop), create a standalone `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1), expand `SECURITY.md` with private vulnerability reporting and an expanded scope covering Spine/bridges/marketplace, add GitHub issue templates (bug, feature, security policy, guard proposal), add a PR template, and create a `GOVERNANCE.md` documenting the BDFL + Maintainer Council model with a path to CNCF governance.

---

## Current State

### What exists today

**`CONTRIBUTING.md`** (220 lines):
- Covers Rust-only development (prerequisites list Rust 1.93+, optional Node/Python/wasm-pack). Node.js version should be listed as 24+ to match CI.
- Architecture diagram is outdated: missing Spine, bridges, multi-agent, certification, desktop
- References "MIT License" (line 213), which will change under Spec 04
- No DCO (Developer Certificate of Origin) sign-off requirement
- No mention of security-sensitive review requirements
- No contribution guide for rulesets, guards, or adapters (the easiest on-ramps)
- Pull request review says "a maintainer will review" with no defined SLAs or areas of ownership

**`SECURITY.md`** (109 lines):
- Basic vulnerability reporting process (email connor@backbay.io)
- Response timeline: 48h ack, 7d assessment, 30d fix
- Good security model description for guards and attestation
- Missing: Spine protocol scope, marketplace supply chain scope, bridge/kernel scope
- Missing: GitHub private vulnerability reporting integration
- Missing: CVE/advisory publication process
- Missing: Security audit history and planned audits

**`LICENSE`** (22 lines):
- MIT License, Copyright 2026 Backbay Industries
- Will change to Apache 2.0 under Spec 04

**No `CODE_OF_CONDUCT.md`**:
- CONTRIBUTING.md references the Rust Code of Conduct by link only
- A standalone file is expected by GitHub and CNCF

**No `GOVERNANCE.md`**:
- No defined governance model, decision process, or maintainer roles

**No GitHub issue templates**:
- No `.github/ISSUE_TEMPLATE/` directory
- No issue forms (YAML-based)
- No PR template

**Existing `.github/` assets**:
- `dependabot.yml` -- dependency update automation
- `release.yml` -- GitHub Releases config
- Workflow files: `ci.yml`, `docker.yml`, `docs.yml`, `fuzz.yml`, `release.yml`
- Brand assets in `.github/assets/`

### Referenced research

From `docs/research/open-source-strategy.md` (section 4.3, Community Governance Model):

> **Phase 1 (0-12 months): BDFL with Maintainer Council**
> - Founding team retains final decision authority
> - Maintainer Council of 3-5 core contributors with commit access
> - All design decisions documented in RFCs (markdown in `docs/rfcs/`)
> - Weekly community call (recorded, notes published)
> - Decision process: RFC -> community comment period (2 weeks) -> BDFL approval

> **Phase 2 (12-24 months): Steering Committee**
> - Transition to 5-member elected Steering Committee
> - BDFL retains veto on security-critical decisions only

> **Phase 3 (24+ months): CNCF Sandbox Application**
> - Apache 2.0 license, CLA or DCO
> - Dual-company maintainership

From section 4.4 (Contribution Guidelines):

> - All contributions via GitHub Pull Request
> - DCO sign-off required (`Signed-off-by:` trailer)
> - CI must pass: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`
> - Security-sensitive changes require review from 2 maintainers
> - Guard and ruleset contributions require test coverage

From section 4.4 (Extension points):
1. Rulesets (YAML) -- lowest barrier
2. Guard plugins (Rust)
3. Transport adapters (Rust/Python)
4. Framework adapters (TS/Python)
5. Compliance templates
6. Bridge plugins (Rust + eBPF)

From section 9 (Phase 0 timeline):
> Create CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md (3 days)

---

## Target State

After this work is complete:

1. **`CONTRIBUTING.md`** is comprehensive, covering all contribution types (rulesets, guards, adapters, bridges, Spine transports, docs, compliance templates), with DCO requirement and multi-language dev setup
2. **`CODE_OF_CONDUCT.md`** is the Contributor Covenant v2.1, standalone file
3. **`SECURITY.md`** covers the full SDR stack scope, integrates GitHub private vulnerability reporting, defines CVE publication process, and lists planned security audits
4. **`GOVERNANCE.md`** defines the BDFL + Maintainer Council model with component ownership areas, RFC process, and evolution path
5. **`.github/ISSUE_TEMPLATE/`** contains issue forms for: bug report, feature request, guard proposal, security policy/ruleset proposal
6. **`.github/PULL_REQUEST_TEMPLATE.md`** guides PR authors through checklist
7. All files cross-reference each other and are discoverable from the repository root

---

## Implementation Plan

### Step 1: Create `CODE_OF_CONDUCT.md`

Adopt the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) verbatim, with enforcement contact filled in.

```markdown
# Contributor Covenant Code of Conduct

## Our Pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone...

[Full text of Contributor Covenant v2.1]

## Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported to the project team at **conduct@clawdstrike.io**.

All complaints will be reviewed and investigated promptly and fairly.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage],
version 2.1, available at
https://www.contributor-covenant.org/version/2/1/code_of_conduct.html
```

**Rationale:** Contributor Covenant v2.1 is the CNCF standard. Using it positions the project for future CNCF Sandbox application.

### Step 2: Create `GOVERNANCE.md`

Define the governance model in phases, matching the open-source-strategy.md roadmap:

```markdown
# ClawdStrike Governance

## Current Model: BDFL + Maintainer Council

ClawdStrike uses a Benevolent Dictator For Life (BDFL) governance model with
a Maintainer Council for the initial phase of the project.

### BDFL

The BDFL has final authority on all project decisions.

- **Current BDFL:** Connor (GitHub: @connor)

### Maintainer Council

Maintainers have commit access and review authority within their component areas.

| Maintainer | Component Area | GitHub |
|------------|---------------|--------|
| (TBD)      | Guards / Policy Engine | |
| (TBD)      | Spine Protocol | |
| (TBD)      | Desktop / SDK | |
| (TBD)      | Bridges / Infrastructure | |
| (TBD)      | Documentation / Community | |

### Decision Process

1. **Minor changes** (bug fixes, docs, typos): Single maintainer approval
2. **Feature additions** (new guards, adapters): Maintainer approval + CI pass
3. **Architecture changes** (new crates, protocol changes): RFC required
4. **Security-sensitive changes** (crypto, guard logic, Spine protocol): Two maintainer reviews
5. **Governance changes**: BDFL approval

### RFC Process

Significant design decisions are documented as RFCs in `docs/rfcs/`:

1. Author opens a PR adding `docs/rfcs/NNNN-title.md`
2. Community comment period: 14 days minimum
3. Maintainer Council discusses in weekly call
4. BDFL approves, requests changes, or rejects
5. Approved RFCs are merged and implementation can begin

### Component Ownership

| Component | Directory | Owner(s) |
|-----------|-----------|----------|
| Crypto primitives | `crates/hush-core/` | Guards maintainer |
| Guard engine | `crates/clawdstrike/` | Guards maintainer |
| Spine protocol | `crates/spine/` | Spine maintainer |
| Tetragon bridge | `crates/tetragon-bridge/` | Bridges maintainer |
| Hubble bridge | `crates/hubble-bridge/` | Bridges maintainer |
| hushd daemon | `crates/hushd/` | Guards maintainer |
| CLI | `crates/hush-cli/` | Guards maintainer |
| Desktop app | `apps/desktop/` | Desktop maintainer |
| TypeScript SDK | `packages/hush-ts/` | Desktop maintainer |
| Python SDK | `packages/hush-py/` | Community maintainer |
| Rulesets | `rulesets/` | Any maintainer |
| Documentation | `docs/` | Any maintainer |
| Helm chart | `deploy/helm/` | Bridges maintainer |

### Becoming a Maintainer

Maintainer candidates are nominated by existing maintainers based on:
- Sustained, high-quality contributions (6+ merged PRs)
- Demonstrated understanding of the codebase and design philosophy
- Constructive participation in reviews and discussions
- Alignment with the project's fail-closed security philosophy

The BDFL approves all maintainer additions.

## Future Evolution

### Phase 2: Steering Committee (12-24 months)

When the contributor base grows beyond the founding team:
- Transition to a 5-member elected Steering Committee
- BDFL retains veto on security-critical decisions only
- Sub-teams form around components with designated leads
- Annual elections for Steering Committee seats

### Phase 3: CNCF Sandbox (24+ months)

Requirements for CNCF Sandbox application:
- 2+ maintainers from different organizations
- Apache 2.0 license (prerequisite: Spec 04 must be completed first)
- Adopt CNCF governance template
- Security audit completed
- 3+ production adopters

## Community Channels

| Channel | Purpose |
|---------|---------|
| [GitHub Discussions](https://github.com/backbay-labs/clawdstrike/discussions) | Q&A, feature ideas, architecture |
| [Discord](https://discord.gg/clawdstrike) | Real-time chat, contributor coordination |
| Weekly community call | Demos, roadmap, contributor spotlights |
| Monthly security office hours | Guard design, threat modeling |
```

### Step 3: Overhaul `CONTRIBUTING.md`

Major changes from the current version:

1. **Add DCO sign-off requirement** with instructions:
   ```
   git commit -s -m "feat(guards): add rate limiting"
   ```
   Every commit must include `Signed-off-by: Name <email>` (DCO 1.1).

2. **Update architecture diagram** to include Spine, bridges, marketplace, desktop, multi-agent, certification crates

3. **Add contribution on-ramps by difficulty** (from open-source-strategy.md section 4.4):
   - Level 1: Rulesets (YAML) -- with step-by-step example
   - Level 2: Documentation improvements
   - Level 3: Framework adapters (TypeScript/Python)
   - Level 4: Compliance templates
   - Level 5: Custom guards (Rust) -- with Guard trait example
   - Level 6: Transport adapters
   - Level 7: Bridge plugins

4. **Add multi-language development sections** (with prerequisite versions):
   - Rust 1.93+ (existing, update to include Spine and bridges)
   - Node.js 24+ / TypeScript (`npm install --workspace=packages/hush-ts && npm test`)
   - Python 3.10+ (`pip install -e packages/hush-py[dev] && pytest`)
   - Desktop (`cd apps/desktop && npm run tauri dev`)

5. **Add security review requirements**: "Changes to cryptographic code (`crates/hush-core/`), guard implementations, or the Spine protocol require review from two maintainers."

6. **Update license reference**: Change "MIT License" to "Apache License 2.0". **This change is conditional on Spec 04 (Apache 2.0 license migration) completing first.** If Spec 04 has not yet landed, use a placeholder: `"See [LICENSE](./LICENSE) for the project's license terms."` to avoid referencing an incorrect license.

7. **Add ruleset contribution guide** with example:
   ```yaml
   # rulesets/community/my-policy.yaml
   schema_version: "1.1.0"
   name: "my-org-baseline"
   extends: "default"
   guards:
     forbidden_paths:
       deny:
         - "/etc/shadow"
   ```

8. **Reference GOVERNANCE.md** for decision-making process

9. **Reference CODE_OF_CONDUCT.md** directly (not the Rust CoC)

### Step 4: Expand `SECURITY.md`

Major additions:

1. **Enable GitHub private vulnerability reporting**:
   Add to `SECURITY.md`:
   ```
   ## Reporting a Vulnerability

   We use GitHub's private vulnerability reporting. To report:

   1. Go to https://github.com/backbay-labs/clawdstrike/security/advisories/new
   2. Fill out the vulnerability report form
   3. We will respond within 48 hours

   Alternatively, email security@clawdstrike.io with PGP-encrypted details.
   ```

   Enable in repo settings: Settings > Security > Private vulnerability reporting.

2. **Expand security scope** to cover the full SDR stack:

   | Component | Security Scope | Critical Assets |
   |-----------|---------------|-----------------|
   | hush-core | Ed25519 signing, SHA-256/Keccak, Merkle trees, canonical JSON | Key material, signature verification |
   | Guards | Policy evaluation, guard bypass resistance | Fail-closed invariant |
   | Spine | Envelope signing, checkpoint integrity, proof verification | Append-only log, witness signatures |
   | Bridges | Tetragon/Hubble event integrity, NATS transport | Signing key management, dedup |
   | Marketplace | Feed signing, bundle verification, IPFS content integrity | Curator keys, provenance chain |
   | hushd | API auth, audit log integrity, SSE broadcast | API keys, audit database |
   | Desktop | Tauri IPC, localStorage trust config, P2P discovery | Trust settings, local key storage |

3. **Add CVE publication process**:
   ```
   ## CVE Publication

   For confirmed vulnerabilities:
   1. We request a CVE ID via GitHub Security Advisory
   2. We develop and test a fix on a private branch
   3. We publish the fix, CVE, and advisory simultaneously
   4. Security patches are released within 48 hours for critical issues
   ```

4. **Add planned security audits section**:
   ```
   ## Security Audits

   | Scope | Status | Firm | Date |
   |-------|--------|------|------|
   | hush-core cryptography | Planned | TBD | Pre-1.0 |
   | Spine protocol | Planned | TBD | Pre-1.0 |
   | Guard bypass resistance | Planned | TBD | Pre-1.0 |
   ```

5. **Add security design principles**:
   - Fail-closed: Invalid policies reject at load time; errors during evaluation deny access
   - No `unwrap()`/`expect()` in production code (Clippy enforced)
   - `deny_unknown_fields` on all deserialized types
   - Canonical JSON (RFC 8785) for cross-language determinism

### Step 5: Create GitHub issue templates

**`.github/ISSUE_TEMPLATE/config.yml`:**
```yaml
blank_issues_enabled: false
contact_links:
  - name: Security Vulnerability
    url: https://github.com/backbay-labs/clawdstrike/security/advisories/new
    about: Report security vulnerabilities via private disclosure
  - name: Question / Discussion
    url: https://github.com/backbay-labs/clawdstrike/discussions/new
    about: Ask questions or start a discussion
```

**`.github/ISSUE_TEMPLATE/bug_report.yml`:**
```yaml
name: Bug Report
description: Report a bug in ClawdStrike
labels: ["bug", "triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for reporting a bug! Please fill out the form below.
        **Security vulnerabilities**: Please use [private reporting](https://github.com/backbay-labs/clawdstrike/security/advisories/new) instead.
  - type: dropdown
    id: component
    attributes:
      label: Component
      description: Which component is affected?
      options:
        - "Guards / Policy Engine (crates/clawdstrike)"
        - "Crypto (crates/hush-core)"
        - "CLI (crates/hush-cli)"
        - "Daemon (crates/hushd)"
        - "Spine Protocol (crates/spine)"
        - "Tetragon Bridge (crates/tetragon-bridge)"
        - "Hubble Bridge (crates/hubble-bridge)"
        - "Desktop App (apps/desktop)"
        - "TypeScript SDK (packages/hush-ts)"
        - "Python SDK (packages/hush-py)"
        - "Rulesets"
        - "Documentation"
        - "Helm Chart / Deployment"
        - "Other"
    validations:
      required: true
  - type: textarea
    id: description
    attributes:
      label: Description
      description: Clear description of the bug
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: Minimal steps to reproduce the behavior
      value: |
        1.
        2.
        3.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What you expected to happen
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: What actually happened
    validations:
      required: true
  - type: textarea
    id: environment
    attributes:
      label: Environment
      description: |
        - OS:
        - Rust version:
        - ClawdStrike version:
      render: text
    validations:
      required: false
```

**`.github/ISSUE_TEMPLATE/feature_request.yml`:**
```yaml
name: Feature Request
description: Suggest a new feature or enhancement
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: What problem does this solve?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: How would you like this to work?
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered
      description: Other approaches you considered
    validations:
      required: false
  - type: dropdown
    id: component
    attributes:
      label: Component
      options:
        - "Guards / Policy Engine"
        - "Spine Protocol"
        - "Desktop App"
        - "CLI"
        - "SDK (Rust/TypeScript/Python)"
        - "Marketplace"
        - "Bridges"
        - "Deployment / Helm"
        - "Documentation"
        - "Other"
    validations:
      required: true
```

**`.github/ISSUE_TEMPLATE/guard_proposal.yml`:**
```yaml
name: Guard Proposal
description: Propose a new built-in or community guard
labels: ["guard-proposal", "enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Propose a new guard for ClawdStrike. Guards implement the `Guard` or `AsyncGuard` trait
        and provide security checks at the agent tool boundary.
  - type: input
    id: guard_name
    attributes:
      label: Guard Name
      description: "e.g., RateLimitGuard, SqlInjectionGuard"
      placeholder: "MyNewGuard"
    validations:
      required: true
  - type: textarea
    id: threat_model
    attributes:
      label: Threat Model
      description: What attack or risk does this guard protect against?
    validations:
      required: true
  - type: textarea
    id: detection_logic
    attributes:
      label: Detection / Enforcement Logic
      description: How does the guard detect or prevent the threat?
    validations:
      required: true
  - type: textarea
    id: policy_config
    attributes:
      label: Policy Configuration
      description: Example YAML policy config for this guard
      render: yaml
    validations:
      required: false
  - type: dropdown
    id: guard_type
    attributes:
      label: Guard Type
      options:
        - "Sync (Guard trait)"
        - "Async (AsyncGuard trait)"
        - "Not sure"
    validations:
      required: true
  - type: textarea
    id: prior_art
    attributes:
      label: Prior Art
      description: Similar features in other tools (e.g., Falco rules, OPA policies)
    validations:
      required: false
```

**`.github/ISSUE_TEMPLATE/ruleset_proposal.yml`:**
```yaml
name: Ruleset / Policy Proposal
description: Propose a community security ruleset
labels: ["ruleset", "community"]
body:
  - type: input
    id: ruleset_name
    attributes:
      label: Ruleset Name
      placeholder: "e.g., hipaa-phi-protection, aws-agent-baseline"
    validations:
      required: true
  - type: textarea
    id: description
    attributes:
      label: Description
      description: What does this ruleset protect against?
    validations:
      required: true
  - type: textarea
    id: policy_yaml
    attributes:
      label: Policy YAML
      description: Draft policy YAML (schema v1.1.0)
      render: yaml
    validations:
      required: true
  - type: dropdown
    id: extends
    attributes:
      label: Base Ruleset
      description: Which built-in ruleset does this extend?
      options:
        - "permissive"
        - "default"
        - "strict"
        - "ai-agent"
        - "cicd"
        - "None (standalone)"
    validations:
      required: true
```

### Step 6: Create PR template

**`.github/PULL_REQUEST_TEMPLATE.md`:**

```markdown
## Summary

<!-- Brief description of what this PR does and why -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] New ruleset or policy template
- [ ] New guard implementation

## Component(s) Affected

<!-- Which crates/packages does this touch? -->

## Checklist

- [ ] I have signed off all commits (`git commit -s`) per the [DCO](https://developercertificate.org/)
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] I have added tests for new functionality
- [ ] I have updated documentation for public API changes
- [ ] Security-sensitive changes have been flagged for two-maintainer review

## Security Impact

<!-- Does this change affect cryptography, guard logic, Spine protocol, or authentication? If yes, describe the security implications. -->

## Related Issues

<!-- Closes #123, Fixes #456 -->
```

### Step 7: Cross-reference all governance files

Ensure each file links to the others:
- `CONTRIBUTING.md` links to `CODE_OF_CONDUCT.md`, `SECURITY.md`, `GOVERNANCE.md`
- `CODE_OF_CONDUCT.md` links to enforcement email
- `SECURITY.md` links to `CONTRIBUTING.md` for non-security contributions
- `GOVERNANCE.md` links to `CONTRIBUTING.md` for how to contribute
- `README.md` links to all four files in a "Community" section

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `CODE_OF_CONDUCT.md` | Create | Contributor Covenant v2.1 |
| `GOVERNANCE.md` | Create | BDFL + Maintainer Council model, RFC process, evolution path |
| `CONTRIBUTING.md` | Overhaul | DCO, updated architecture, contribution on-ramps, multi-language setup, security review requirements |
| `SECURITY.md` | Expand | Full SDR scope, GitHub private reporting, CVE process, audit plans |
| `.github/ISSUE_TEMPLATE/config.yml` | Create | Disable blank issues, add security/discussion links |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Create | Bug report form with component dropdown |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Create | Feature request form |
| `.github/ISSUE_TEMPLATE/guard_proposal.yml` | Create | Guard proposal form with threat model |
| `.github/ISSUE_TEMPLATE/ruleset_proposal.yml` | Create | Ruleset/policy proposal form |
| `.github/PULL_REQUEST_TEMPLATE.md` | Create | PR checklist with DCO, CI, security impact |
| `README.md` | Modify | Add "Community" section linking to governance files |

---

## Testing Strategy

### Validation (no automated tests -- these are documentation files)

1. **Render check**: All markdown files render correctly on GitHub (no broken links, tables, or formatting)
2. **Link validation**: Run a markdown link checker (`mlc` or `markdown-link-check`) against all governance files
3. **Issue template test**: Create a test issue using each template in a draft/fork to verify form rendering
4. **PR template test**: Open a test PR to verify the template appears
5. **DCO enforcement**: Set up a GitHub App or CI check (e.g., `dco-check` GitHub Action) that verifies `Signed-off-by:` on all commits in PRs
6. **Cross-reference audit**: Verify every governance file links to the others correctly

### CI addition (optional but recommended)

Add a DCO check to `.github/workflows/ci.yml`:

```yaml
dco:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
      with:
        fetch-depth: 0
    - uses: cla-assistant/github-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      with:
        check-dco: true
```

Alternatively, use the simpler `probot/dco` GitHub App.

---

## Rollback Plan

1. **Revert commits**: All changes are documentation files. A simple `git revert` restores the previous versions.
2. **Issue templates**: Delete `.github/ISSUE_TEMPLATE/` directory to restore default GitHub issue creation.
3. **PR template**: Delete `.github/PULL_REQUEST_TEMPLATE.md` to remove the PR checklist.
4. **DCO check**: Disable the CI job or GitHub App.
5. **No data loss**: These are all additive documentation files with no impact on runtime behavior.

---

## Dependencies

| Dependency | Type | Notes |
|------------|------|-------|
| Spec 04 (Apache 2.0 license migration) | Soft | CONTRIBUTING.md should reference the correct license. Can use "see LICENSE" as a placeholder until Spec 04 lands. |
| GitHub repo settings | Admin | Enable "Private vulnerability reporting" in repo settings |
| Email setup | Admin | `conduct@clawdstrike.io` and `security@clawdstrike.io` email addresses |
| Discord server | Admin | Create Discord server and update invite link in GOVERNANCE.md |

---

## Acceptance Criteria

- [ ] `CODE_OF_CONDUCT.md` exists at repo root with Contributor Covenant v2.1 text and enforcement contact
- [ ] `GOVERNANCE.md` exists at repo root documenting BDFL model, Maintainer Council, RFC process, component ownership, and evolution phases
- [ ] `CONTRIBUTING.md` is updated with: DCO sign-off requirement, full architecture diagram (including Spine/bridges/marketplace/desktop), contribution on-ramps by difficulty level, multi-language dev setup (Rust/TS/Python), security review requirement for crypto/guard/Spine changes
- [ ] `SECURITY.md` is expanded with: full SDR stack scope table, GitHub private vulnerability reporting instructions, CVE publication process, planned security audit section, security design principles
- [ ] `.github/ISSUE_TEMPLATE/config.yml` disables blank issues and links to security reporting and discussions
- [ ] `.github/ISSUE_TEMPLATE/bug_report.yml` renders correctly with component dropdown covering all crates
- [ ] `.github/ISSUE_TEMPLATE/feature_request.yml` renders correctly
- [ ] `.github/ISSUE_TEMPLATE/guard_proposal.yml` renders correctly with threat model and guard type fields
- [ ] `.github/ISSUE_TEMPLATE/ruleset_proposal.yml` renders correctly with YAML input and base ruleset dropdown
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` renders correctly with DCO, CI, and security impact checklist
- [ ] All governance files cross-reference each other (no dead internal links)
- [ ] `README.md` has a "Community" or "Contributing" section linking to all governance files
- [ ] No broken markdown rendering when viewed on GitHub
