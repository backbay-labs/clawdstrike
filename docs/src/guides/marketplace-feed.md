# Marketplace Feed (Signed, IPFS-hostable)

The desktop Marketplace consumes a **signed JSON feed** that lists **signed policy bundles**.
Transport is untrusted: the feed and bundles can be hosted on HTTPS, mirrored anywhere, or served via IPFS gateways.
Clients **verify signatures** before displaying/installing anything.

## Files and signatures

- **Feed:** `SignedMarketplaceFeed` JSON (signed by a curator key)
- **Bundle:** `SignedPolicyBundle` JSON (signed by the bundle publisher; embedded `public_key` is required for verification)

The desktop app only accepts feeds signed by **trusted curator public keys** compiled into the app.
To add a new curator, update `apps/desktop/src-tauri/src/commands/marketplace.rs`.

## Generate bundles

Create a signing key (32-byte hex seed) and build signed bundle JSON files:

```bash
openssl rand -hex 32 > curator.key

# Example: bundle a ruleset/policy into a SignedPolicyBundle JSON.
hush policy bundle build rulesets/default.yaml \
  --resolve \
  --key curator.key \
  --output apps/desktop/src-tauri/resources/marketplace/bundles/default.signed_bundle.json \
  --embed-pubkey
```

Repeat for other policies/rulesets (each output must end with `.signed_bundle.json` for the generator script).

## Publish bundles on IPFS (optional)

If you want bundle URIs to be `ipfs://…`, publish the bundles directory and capture the directory CID:

```bash
ipfs add -r apps/desktop/src-tauri/resources/marketplace/bundles
```

Use the final CID printed for the directory (e.g. `ipfs://<BUNDLES_CID>/default.signed_bundle.json`).

## Generate + sign the feed

The feed generator expects the signing key via `MARKETPLACE_FEED_SIGNING_KEY` (hex seed):

```bash
export MARKETPLACE_FEED_SIGNING_KEY="$(cat curator.key)"

# Builtin URIs:
tools/scripts/build-marketplace-feed --seq 1

# OR: IPFS bundle URIs (directory CID):
tools/scripts/build-marketplace-feed --seq 1 --bundle-uri-prefix "ipfs://<BUNDLES_CID>/"
```

This writes `apps/desktop/src-tauri/resources/marketplace/feed.signed.json` by default.

## Publish the feed on IPFS

```bash
ipfs add apps/desktop/src-tauri/resources/marketplace/feed.signed.json
```

In the desktop app, go to **Settings → Marketplace** and add the resulting CID as a source:

- `ipfs://<FEED_CID>`

You can also add HTTPS mirrors (one per line). The client will try sources in order and only accept a feed that
verifies against a trusted curator key.

## P2P discovery (optional)

The desktop app can optionally run a low-trust P2P discovery loop to learn about new feed URIs from nearby peers.
Peers gossip messages like `ipfs://<CID>` over libp2p gossipsub.

- Enable it in **Settings → Marketplace Discovery (P2P)**.
- By default it uses **mDNS** to find peers on the local network.
- You can also configure **bootstrap peers** (multiaddrs) for discovery beyond the LAN.

Discovery is only a transport hint. The Marketplace still:

1. downloads the feed from the announced URI
2. verifies the feed signature against trusted curator keys
3. verifies each bundle signature before display/install

If you want to test announcements manually, use the **“Announce feed URI”** field in Settings.

## Provenance / attestations (optional)

You can attach provenance pointers to feed entries (for example, an EAS attestation UID) and let the desktop app
verify them through a notary service.

### Feed entry fields

Marketplace entries may include:

```json
{
  "provenance": {
    "attestation_uid": "0x…",
    "notary_url": "https://notary.example.com"
  }
}
```

The `provenance` object is covered by the **feed signature**, so clients will only trust what a curator publishes.

### Notary verification

The desktop app calls the notary over HTTPS (localhost HTTP is allowed in debug builds) using:

- `GET {notary_url}/verify/{attestation_uid}`

and expects a JSON response that includes at least:

```json
{ "valid": true }
```

Additional fields like `attester` and `attestedAt` are displayed when present.

### UI behavior

- Configure a default notary + trusted attesters in **Settings → Marketplace Provenance (Notary)**.
- In Marketplace, enable **“Verified only”** to filter to policies with a valid attestation (and, if configured, a
  trusted `attester`).

This is a reputation/provenance layer only; installation security still depends on bundle signatures.
