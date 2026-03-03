# Trust & Verification

Clawdstrike trust levels are derived from cryptographic evidence tied to package content hashes.

## Evidence Chain

1. Archive SHA-256 (`checksum`)
2. Publisher signature over checksum hash bytes
3. Registry counter-signature over checksum hash bytes
4. Registry public-key trust anchor check (`[registry].public_key` or `CLAWDSTRIKE_REGISTRY_PUBLIC_KEY`)
5. Transparency checkpoint signature + inclusion proof verification

## Trust Levels

- `unverified`: local integrity only
- `signed`: publisher signature verified
- `verified`: publisher + registry signatures verified against pinned registry public key
- `certified`: verified + cryptographically verified checkpoint signature + inclusion proof

## Registry Trust Anchor

`verified` and `certified` require a configured registry public key trust anchor:

- `~/.clawdstrike/config.toml`:
```toml
[registry]
public_key = "<ed25519-hex>"
```
- or env var: `CLAWDSTRIKE_REGISTRY_PUBLIC_KEY`

## Caller Authentication for Org/Trusted-Publisher Mutations

Sensitive org and trusted-publisher updates are authenticated with signed caller headers:

- `X-Clawdstrike-Caller-Key`
- `X-Clawdstrike-Caller-Sig`
- `X-Clawdstrike-Caller-Ts`

Signatures cover endpoint-specific payloads plus timestamp to prevent caller-key spoofing.
