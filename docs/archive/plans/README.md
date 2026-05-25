# Archived plans

Plans here describe features that have shipped, designs that have been superseded, or proposals that have been parked. They are kept for historical context. The code in the repository is the source of truth for current behavior.

Archived on 2026-05-24 by docs hygiene wave E4.

## Index

- `origin-enclaves/` - origin enclaves design (phases 0-2 shipped under `crates/libs/clawdstrike/src/origin.rs`, `enclave.rs`; SDK parity shipped).
- `siem-soar/` - SIEM/SOAR exporter design (Splunk, Elastic, Datadog, Sumo, PagerDuty, Slack/Teams, STIX/TAXII all shipped under `crates/services/hushd/src/siem/`).
- `secret-broker/` - secret broker / brokered egress design (shipped under `crates/services/clawdstrike-brokerd/`, `crates/libs/clawdstrike-broker-protocol/`, `crates/services/hushd/src/api/broker.rs`).
- `multi-agent/` - multi-agent coordination design notes (implementation shipped under `crates/libs/hush-multi-agent/`).
- `swarm-engine/` - swarm engine architecture notes (implementation shipped under `packages/swarm-engine/`).
- `pact/` - PACT protocol pre-RFC (not promoted to RFC, parked).
