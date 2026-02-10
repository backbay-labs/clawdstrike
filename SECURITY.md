# Security Policy

## Reporting a Vulnerability

Do not open public issues for security vulnerabilities.

Preferred channel:

- GitHub Security Advisories: <https://github.com/backbay-labs/clawdstrike/security/advisories/new>

Alternative channel:

- Email: [security@clawdstrike.io](mailto:security@clawdstrike.io)

## What to Include in a Report

Please include:

- Affected component(s) and repository path(s)
- Reproduction steps (minimal, deterministic when possible)
- Expected vs actual behavior
- Impact assessment (confidentiality/integrity/availability)
- Environment details (OS, version/commit, config flags)
- Any known workaround or patch idea (optional)

## Response Expectations (Pre-Release)

Target timelines:

- Acknowledgement: within 48 hours
- Initial triage/severity: within 7 days
- Fix plan/mitigation path: within 14 days
- Target remediation release window: within 30 days for confirmed issues

These are targets, not guarantees; complex issues may require longer.

## Disclosure Policy

- We follow responsible disclosure.
- Please keep details private until a fix or coordinated mitigation is available.
- We will coordinate advisory publication timing with the reporter when possible.

## GHSA and CVE Policy (Pre-Release)

Default policy:

- Use GHSA (GitHub Security Advisory) as the primary disclosure artifact.

CVE policy:

- CVEs are requested when required by downstream consumers/compliance, or where broad ecosystem tracking materially improves remediation.

## Scope

Security-sensitive scope includes:

- `crates/libs/clawdstrike` (guards, policy, IRM, async runtime)
- `crates/services/hush-cli` (`hush run` proxy + remote extends)
- `crates/services/hushd` (daemon policy/runtime controls)
- `crates/libs/hush-core` (receipt/signature integrity primitives)

Reference threat context:

- `THREAT_MODEL.md`
- `NON_GOALS.md`
- `docs/audits/2026-02-10-remediation.md`
- `docs/audits/2026-02-10-wave2-remediation.md`
- `docs/audits/2026-02-10-wave3-remediation.md`
