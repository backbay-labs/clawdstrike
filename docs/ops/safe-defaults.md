# Safe Defaults

This guide documents pre-release security defaults that are safe for most deployments.

## Recommended Defaults

### Remote extends host allowlist

Use explicit host allowlists; avoid wildcards where possible.

Example:

```yaml
remote_extends:
  allowed_hosts:
    - "raw.githubusercontent.com"
    - "github.com"
    - "api.github.com"
  https_only: true
  allow_private_ips: false
  allow_cross_host_redirects: false
```

### Private IP policy

Default:

- `allow_private_ips: false`

Rationale:

- Blocks loopback/link-local/RFC1918 and other non-public address classes by default.
- Prevents accidental internal-network reachability from remote policy fetch/proxy flows.

### HTTPS-only remote fetches

Default:

- `https_only: true`

Tradeoff:

- Improves transport integrity.
- Disallows plain HTTP sources unless explicitly opted in for controlled testing.

### Deny-by-default posture

Where supported, prefer deny-by-default for:

- Network egress allowlists
- Filesystem path controls
- Unknown/ambiguous IRM parsing cases

## If You Do Only 3 Things

1. Keep remote extends host allowlist explicit and minimal.
2. Keep `allow_private_ips=false` unless you have a documented internal-network requirement.
3. Run `hush run` with policy rulesets that default to block on unknown network/file actions.

## Pre-Release Operational Note

For development convenience, do not carry insecure flags to production profiles:

- `--remote-extends-allow-http`
- `--remote-extends-allow-private-ips`
- `--remote-extends-allow-cross-host-redirects`
- `--proxy-allow-private-ips`

## Related

- `THREAT_MODEL.md`
- `NON_GOALS.md`
- `docs/ops/operational-limits.md`
