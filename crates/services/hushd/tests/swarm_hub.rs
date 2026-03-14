#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::TestDaemon;
use hush_core::{canonicalize_json, sha256_hex, Keypair};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};

const FINDING_ENVELOPE_SCHEMA: &str = "clawdstrike.swarm.finding_envelope.v1";
const HEAD_ANNOUNCEMENT_SCHEMA: &str = "clawdstrike.swarm.head_announcement.v1";
const REVOCATION_ENVELOPE_SCHEMA: &str = "clawdstrike.swarm.revocation_envelope.v1";
const HUB_CONFIG_SCHEMA: &str = "clawdstrike.swarm.hub_config.v1";
const REPLAY_SCHEMA: &str = "clawdstrike.swarm.replay.v1";
const PUBLIC_KEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ISSUER_ID: &str =
    "aegis:ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SIGNATURE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const DIGEST_2: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

fn make_finding(seq: u64) -> Value {
    json!({
        "schema": FINDING_ENVELOPE_SCHEMA,
        "findingId": format!("fnd_{seq:04}"),
        "issuerId": ISSUER_ID,
        "feedId": "fed.alpha",
        "feedSeq": seq,
        "publishedAt": 1_715_000_000_000u64 + seq,
        "title": format!("Finding {seq}"),
        "summary": format!("Summary for finding {seq}"),
        "severity": "high",
        "confidence": 0.92,
        "status": "confirmed",
        "signalCount": 3,
        "tags": ["egress", "shell"],
        "relatedFindingIds": [],
        "blobRefs": [
            {
                "blobId": format!("blob_{seq:04}"),
                "digest": DIGEST_1,
                "mediaType": "application/json",
                "byteLength": 512,
                "publish": {
                    "uri": format!("ipfs://blob-{seq}"),
                    "publishedAt": 1_715_000_000_100u64 + seq,
                    "notaryRecordId": format!("notary-{seq}"),
                    "notaryEnvelopeHash": DIGEST_2
                }
            }
        ],
        "attestation": {
            "algorithm": "ed25519",
            "publicKey": PUBLIC_KEY,
            "signature": SIGNATURE
        },
        "publish": {
            "uri": format!("https://hub.example/findings/{seq}"),
            "publishedAt": 1_715_000_000_200u64 + seq,
            "notaryRecordId": format!("finding-{seq}"),
            "notaryEnvelopeHash": DIGEST_2
        }
    })
}

fn hex_digest(seed: u64) -> String {
    format!("0x{seed:064x}")
}

fn make_revocation(seq: u64) -> Value {
    json!({
        "schema": REVOCATION_ENVELOPE_SCHEMA,
        "revocationId": format!("rev_{seq:04}"),
        "issuerId": ISSUER_ID,
        "feedId": "fed.alpha",
        "feedSeq": seq,
        "issuedAt": 1_715_100_000_000u64 + seq,
        "action": "revoke",
        "target": {
            "schema": FINDING_ENVELOPE_SCHEMA,
            "id": format!("fnd_target_{seq:04}"),
            "digest": hex_digest(10_000 + seq),
        },
        "reason": format!("Revoked finding {seq} after analyst review."),
        "attestation": {
            "algorithm": "ed25519",
            "publicKey": PUBLIC_KEY,
            "signature": SIGNATURE
        },
        "publish": {
            "uri": format!("https://hub.example/revocations/{seq}"),
            "publishedAt": 1_715_100_000_100u64 + seq,
            "notaryRecordId": format!("revocation-{seq}"),
            "notaryEnvelopeHash": DIGEST_2
        }
    })
}

fn make_supersede_revocation(
    seq: u64,
    target_id: &str,
    target_digest: &str,
    replacement_id: &str,
    replacement_digest: &str,
) -> Value {
    let mut revocation = make_revocation(seq);
    revocation["action"] = json!("supersede");
    revocation["target"] = json!({
        "schema": FINDING_ENVELOPE_SCHEMA,
        "id": target_id,
        "digest": target_digest,
    });
    revocation["replacement"] = json!({
        "schema": FINDING_ENVELOPE_SCHEMA,
        "id": replacement_id,
        "digest": replacement_digest,
    });
    revocation["reason"] = json!(format!(
        "Superseded finding {target_id} with replacement {replacement_id}."
    ));
    revocation
}

fn issuer_id_from_public_key(public_key: &str) -> String {
    format!("aegis:ed25519:{public_key}")
}

fn trust_policy_signer() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn finding_attestation_digest(value: &Value) -> String {
    let mut signable = value.clone();
    let signable_map = signable
        .as_object_mut()
        .expect("finding envelope should serialize as an object");
    signable_map.remove("attestation");
    signable_map.remove("publish");
    if let Some(blob_refs) = signable_map.get_mut("blobRefs").and_then(Value::as_array_mut) {
        for blob_ref in blob_refs {
            if let Some(blob_ref_map) = blob_ref.as_object_mut() {
                blob_ref_map.remove("publish");
            }
        }
    }

    let canonical = canonicalize_json(&signable).expect("canonical finding signable json");
    sha256_hex(canonical.as_bytes())
}

fn revocation_attestation_digest(value: &Value) -> String {
    let mut signable = value.clone();
    let signable_map = signable
        .as_object_mut()
        .expect("revocation envelope should serialize as an object");
    signable_map.remove("attestation");
    signable_map.remove("publish");

    let canonical = canonicalize_json(&signable).expect("canonical revocation signable json");
    sha256_hex(canonical.as_bytes())
}

fn sign_finding_with_keypair(mut finding: Value, keypair: &Keypair) -> Value {
    let public_key = keypair.public_key().to_hex();
    let issuer_id = issuer_id_from_public_key(&public_key);

    finding["issuerId"] = json!(issuer_id);
    let digest = finding_attestation_digest(&finding);
    let signature = keypair.sign(digest.as_bytes()).to_hex();
    finding["attestation"] = json!({
        "algorithm": "ed25519",
        "publicKey": public_key,
        "signature": signature,
    });
    finding
}

fn make_signed_finding(seq: u64) -> Value {
    sign_finding_with_keypair(make_finding(seq), &trust_policy_signer())
}

fn sign_revocation_with_keypair(mut revocation: Value, keypair: &Keypair) -> Value {
    let public_key = keypair.public_key().to_hex();
    let issuer_id = issuer_id_from_public_key(&public_key);

    revocation["issuerId"] = json!(issuer_id);
    let digest = revocation_attestation_digest(&revocation);
    let signature = keypair.sign(digest.as_bytes()).to_hex();
    revocation["attestation"] = json!({
        "algorithm": "ed25519",
        "publicKey": public_key,
        "signature": signature,
    });
    revocation
}

fn make_signed_revocation(seq: u64) -> Value {
    sign_revocation_with_keypair(make_revocation(seq), &trust_policy_signer())
}

fn finding_envelope_hash(value: &Value) -> String {
    let mut signable = value.clone();
    let signable_map = signable
        .as_object_mut()
        .expect("finding envelope should serialize as an object");
    signable_map.remove("publish");
    if let Some(blob_refs) = signable_map.get_mut("blobRefs").and_then(Value::as_array_mut) {
        for blob_ref in blob_refs {
            if let Some(blob_ref_map) = blob_ref.as_object_mut() {
                blob_ref_map.remove("publish");
            }
        }
    }

    let canonical = canonicalize_json(&signable).expect("canonical finding json");
    sha256_hex(canonical.as_bytes())
}

fn revocation_envelope_hash(value: &Value) -> String {
    let mut signable = value.clone();
    let signable_map = signable
        .as_object_mut()
        .expect("revocation envelope should serialize as an object");
    signable_map.remove("publish");

    let canonical = canonicalize_json(&signable).expect("canonical revocation json");
    sha256_hex(canonical.as_bytes())
}

fn assert_canonical_head_announcement(
    head: &Value,
    expected_finding: &Value,
    expected_entry_count: u64,
) -> String {
    let fact_id = head["factId"]
        .as_str()
        .expect("headAnnouncement.factId should be a non-empty string");
    assert!(!fact_id.is_empty(), "headAnnouncement.factId should not be empty");
    assert_eq!(head["schema"], "clawdstrike.swarm.head_announcement.v1");
    assert_eq!(head["feedId"], expected_finding["feedId"]);
    assert_eq!(head["issuerId"], expected_finding["issuerId"]);
    assert_eq!(head["headSeq"], expected_finding["feedSeq"]);
    assert_eq!(
        head["headEnvelopeHash"],
        finding_envelope_hash(expected_finding)
    );
    assert_eq!(head["entryCount"], expected_entry_count);
    assert_eq!(head["announcedAt"], expected_finding["publishedAt"]);
    assert!(head.get("headPayloadDigest").is_none());
    assert!(head.get("updatedAt").is_none());

    fact_id.to_string()
}

fn assert_canonical_revocation_head_announcement(
    head: &Value,
    expected_revocation: &Value,
    expected_entry_count: u64,
) -> String {
    let fact_id = head["factId"]
        .as_str()
        .expect("headAnnouncement.factId should be a non-empty string");
    assert!(!fact_id.is_empty(), "headAnnouncement.factId should not be empty");
    assert_eq!(head["schema"], HEAD_ANNOUNCEMENT_SCHEMA);
    assert_eq!(head["feedId"], expected_revocation["feedId"]);
    assert_eq!(head["issuerId"], expected_revocation["issuerId"]);
    assert_eq!(head["headSeq"], expected_revocation["feedSeq"]);
    assert_eq!(
        head["headEnvelopeHash"],
        revocation_envelope_hash(expected_revocation)
    );
    assert_eq!(head["entryCount"], expected_entry_count);
    assert_eq!(head["announcedAt"], expected_revocation["issuedAt"]);
    assert!(head.get("headPayloadDigest").is_none());
    assert!(head.get("updatedAt").is_none());

    fact_id.to_string()
}

async fn publish_finding(client: &reqwest::Client, daemon: &TestDaemon, finding: &Value) -> reqwest::Response {
    let feed_id = finding["feedId"]
        .as_str()
        .expect("finding feedId should be a string");

    client
        .post(format!(
            "{}/api/v1/swarm/feeds/{feed_id}/findings",
            daemon.url
        ))
        .json(finding)
        .send()
        .await
        .expect("failed to publish finding")
}

async fn publish_revocation(
    client: &reqwest::Client,
    daemon: &TestDaemon,
    revocation: &Value,
) -> reqwest::Response {
    let feed_id = revocation["feedId"]
        .as_str()
        .expect("revocation feedId should be a string");

    client
        .post(format!(
            "{}/api/v1/swarm/feeds/{feed_id}/revocations",
            daemon.url
        ))
        .json(revocation)
        .send()
        .await
        .expect("failed to publish revocation")
}

async fn get_swarm_hub_config(client: &reqwest::Client, daemon: &TestDaemon) -> Value {
    client
        .get(format!("{}/api/v1/swarm/hub/config", daemon.url))
        .send()
        .await
        .expect("failed to fetch swarm hub config")
        .json()
        .await
        .expect("swarm hub config should deserialize")
}

async fn update_trust_policy(
    client: &reqwest::Client,
    daemon: &TestDaemon,
    trust_policy: &Value,
) -> reqwest::Response {
    client
        .put(format!(
            "{}/api/v1/swarm/hub/config/trust-policy",
            daemon.url
        ))
        .json(trust_policy)
        .send()
        .await
        .expect("failed to update swarm hub trust policy")
}

fn open_control_db(daemon: &TestDaemon) -> Connection {
    Connection::open(daemon.test_dir.join("audit.db")).expect("open control db")
}

fn make_trust_policy(overrides: Value) -> Value {
    let mut policy = json!({
        "trustedIssuers": [],
        "blockedIssuers": [],
        "requireAttestation": false,
        "requireWitnessProofs": false,
        "allowedSchemas": [FINDING_ENVELOPE_SCHEMA, REVOCATION_ENVELOPE_SCHEMA]
    });

    let policy_map = policy
        .as_object_mut()
        .expect("trust policy should serialize as an object");
    let overrides_map = overrides
        .as_object()
        .expect("trust policy overrides should serialize as an object");
    for (key, value) in overrides_map {
        policy_map.insert(key.clone(), value.clone());
    }

    policy
}

fn count_swarm_findings(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM swarm_findings", [], |row| row.get(0))
        .expect("query swarm finding count")
}

fn count_swarm_revocations(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM swarm_revocations", [], |row| row.get(0))
        .expect("query swarm revocation count")
}

fn read_persisted_trust_policy(conn: &Connection) -> Option<Value> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM control_metadata WHERE key = 'swarm_hub_trust_policy'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("query persisted trust policy");

    raw.map(|value| serde_json::from_str(&value).expect("persisted trust policy should be valid json"))
}

#[tokio::test]
async fn test_swarm_hub_config_returns_expected_shape() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/swarm/hub/config", daemon.url))
        .send()
        .await
        .expect("failed to fetch swarm hub config");

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["schema"], HUB_CONFIG_SCHEMA);
    assert!(body["hubId"].is_string());
    assert!(body["displayName"].is_string());
    assert!(body["updatedAt"].is_number());
    assert!(body["bootstrapPeers"].is_array());
    assert!(body["relayPeers"].is_array());
    assert!(body["replay"].is_object());
    assert!(body["blobs"].is_object());
    assert!(body["trustPolicy"].is_object());
    let allowed_schemas = body["trustPolicy"]["allowedSchemas"]
        .as_array()
        .expect("trustPolicy.allowedSchemas should be an array");
    assert!(allowed_schemas
        .iter()
        .any(|value| value.as_str() == Some(FINDING_ENVELOPE_SCHEMA)));
    assert!(allowed_schemas
        .iter()
        .any(|value| value.as_str() == Some(REVOCATION_ENVELOPE_SCHEMA)));
}

#[tokio::test]
async fn test_swarm_hub_trust_policy_updates_and_is_reflected_in_config() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "trustedIssuers": [ISSUER_ID],
        "blockedIssuers": [format!("aegis:ed25519:{}", "c".repeat(64))],
        "requireAttestation": true,
        "requireWitnessProofs": true,
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());
    let updated_body: Value = update.json().await.unwrap();
    assert_eq!(updated_body["trustPolicy"], trust_policy);

    let config = get_swarm_hub_config(&client, &daemon).await;
    assert_eq!(config["trustPolicy"], trust_policy);

    let conn = open_control_db(&daemon);
    let persisted = read_persisted_trust_policy(&conn);
    assert_eq!(persisted, Some(trust_policy));
}

#[tokio::test]
async fn test_swarm_hub_first_publish_is_accepted() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding = make_finding(1);
    let resp = publish_finding(&client, &daemon, &finding).await;

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["idempotent"], false);
    assert_eq!(body["feedId"], "fed.alpha");
    assert_eq!(body["issuerId"], ISSUER_ID);
    assert_eq!(body["feedSeq"], 1);
    assert_canonical_head_announcement(&body["headAnnouncement"], &finding, 1);
}

#[tokio::test]
async fn test_swarm_hub_append_is_accepted() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding_one = make_finding(1);
    let finding_two = make_finding(2);

    let first = publish_finding(&client, &daemon, &finding_one).await;
    assert!(first.status().is_success());

    let second = publish_finding(&client, &daemon, &finding_two).await;
    assert!(second.status().is_success());

    let body: Value = second.json().await.unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["idempotent"], false);
    assert_eq!(body["feedSeq"], 2);
    assert_canonical_head_announcement(&body["headAnnouncement"], &finding_two, 2);
}

#[tokio::test]
async fn test_swarm_hub_gap_is_rejected() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let first = publish_finding(&client, &daemon, &make_finding(1)).await;
    assert!(first.status().is_success());

    let gap = publish_finding(&client, &daemon, &make_finding(3)).await;
    assert_eq!(gap.status(), reqwest::StatusCode::CONFLICT);

    let body: Value = gap.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_SEQ_GAP");
}

#[tokio::test]
async fn test_swarm_hub_exact_duplicate_is_idempotent() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding = make_finding(1);
    let first = publish_finding(&client, &daemon, &finding).await;
    assert!(first.status().is_success());

    let duplicate = publish_finding(&client, &daemon, &finding).await;
    assert!(duplicate.status().is_success());

    let body: Value = duplicate.json().await.unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["idempotent"], true);
    assert_eq!(body["feedSeq"], 1);
    assert_eq!(body["headAnnouncement"]["headSeq"], 1);
}

#[tokio::test]
async fn test_swarm_hub_conflicting_duplicate_is_rejected() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let first_finding = make_finding(1);
    let mut conflicting_finding = make_finding(1);
    conflicting_finding["title"] = json!("Conflicting title");

    let first = publish_finding(&client, &daemon, &first_finding).await;
    assert!(first.status().is_success());

    let conflict = publish_finding(&client, &daemon, &conflicting_finding).await;
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);

    let body: Value = conflict.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_SEQ_CONFLICT");
}

#[tokio::test]
async fn test_swarm_hub_head_synthesis_returns_latest_contiguous_head() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding_one = make_finding(1);
    let finding_two = make_finding(2);

    let first = publish_finding(&client, &daemon, &finding_one).await;
    assert!(first.status().is_success());
    let second = publish_finding(&client, &daemon, &finding_two).await;
    assert!(second.status().is_success());
    let publish_body: Value = second.json().await.unwrap();
    let publish_fact_id =
        assert_canonical_head_announcement(&publish_body["headAnnouncement"], &finding_two, 2);

    let resp = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/head?issuerId={}",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch synthesized head");

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    let head_fact_id = assert_canonical_head_announcement(&body, &finding_two, 2);
    assert_eq!(head_fact_id, publish_fact_id);
}

#[tokio::test]
async fn test_swarm_hub_replay_returns_ascending_requested_range() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding_one = make_finding(1);
    let finding_two = make_finding(2);

    let first = publish_finding(&client, &daemon, &finding_one).await;
    assert!(first.status().is_success());
    let second = publish_finding(&client, &daemon, &finding_two).await;
    assert!(second.status().is_success());
    let publish_body: Value = second.json().await.unwrap();
    let publish_fact_id =
        assert_canonical_head_announcement(&publish_body["headAnnouncement"], &finding_two, 2);

    let resp = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/replay?issuerId={}&fromSeq=1&toSeq=2",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch replay range");

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["schema"], REPLAY_SCHEMA);
    assert_eq!(body["feedId"], "fed.alpha");
    assert_eq!(body["issuerId"], ISSUER_ID);
    assert_eq!(body["fromSeq"], 1);
    assert_eq!(body["toSeq"], 2);
    assert_eq!(body["envelopes"].as_array().unwrap().len(), 2);
    assert_eq!(body["envelopes"][0]["feedSeq"], 1);
    assert_eq!(body["envelopes"][1]["feedSeq"], 2);
    let replay_fact_id =
        assert_canonical_head_announcement(&body["headAnnouncement"], &finding_two, 2);
    assert_eq!(replay_fact_id, publish_fact_id);
}

#[tokio::test]
async fn test_swarm_hub_revocation_publish_and_head_synthesis_match_contract() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let revocation = make_revocation(1);
    let resp = publish_revocation(&client, &daemon, &revocation).await;

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["idempotent"], false);
    assert_eq!(body["feedId"], "fed.alpha");
    assert_eq!(body["issuerId"], ISSUER_ID);
    assert_eq!(body["feedSeq"], 1);
    assert_eq!(body["revocationId"], revocation["revocationId"]);
    let publish_fact_id =
        assert_canonical_revocation_head_announcement(&body["headAnnouncement"], &revocation, 1);

    let head = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/revocations/head?issuerId={}",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch revocation head");

    assert!(head.status().is_success());
    let head_body: Value = head.json().await.unwrap();
    let head_fact_id =
        assert_canonical_revocation_head_announcement(&head_body, &revocation, 1);
    assert_eq!(head_fact_id, publish_fact_id);
}

#[tokio::test]
async fn test_swarm_hub_revocation_replay_returns_ordered_append_only_results() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let revocation_one = make_revocation(1);
    let revocation_two = make_supersede_revocation(
        2,
        "fnd_target_0002",
        &hex_digest(20_002),
        "fnd_replacement_0002",
        &hex_digest(30_002),
    );

    let first = publish_revocation(&client, &daemon, &revocation_one).await;
    assert!(first.status().is_success());
    let second = publish_revocation(&client, &daemon, &revocation_two).await;
    assert!(second.status().is_success());
    let publish_body: Value = second.json().await.unwrap();
    let publish_fact_id =
        assert_canonical_revocation_head_announcement(&publish_body["headAnnouncement"], &revocation_two, 2);

    let resp = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/revocations/replay?issuerId={}&fromSeq=1&toSeq=2",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch revocation replay range");

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["schema"], REPLAY_SCHEMA);
    assert_eq!(body["feedId"], "fed.alpha");
    assert_eq!(body["issuerId"], ISSUER_ID);
    assert_eq!(body["fromSeq"], 1);
    assert_eq!(body["toSeq"], 2);
    assert_eq!(body["envelopes"].as_array().unwrap().len(), 2);
    assert_eq!(body["envelopes"][0]["feedSeq"], 1);
    assert_eq!(body["envelopes"][0]["action"], "revoke");
    assert_eq!(body["envelopes"][1]["feedSeq"], 2);
    assert_eq!(body["envelopes"][1]["action"], "supersede");
    let replay_fact_id =
        assert_canonical_revocation_head_announcement(&body["headAnnouncement"], &revocation_two, 2);
    assert_eq!(replay_fact_id, publish_fact_id);
}

#[tokio::test]
async fn test_swarm_hub_exact_duplicate_revocation_is_idempotent() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let revocation = make_revocation(1);
    let first = publish_revocation(&client, &daemon, &revocation).await;
    assert!(first.status().is_success());

    let duplicate = publish_revocation(&client, &daemon, &revocation).await;
    assert!(duplicate.status().is_success());

    let body: Value = duplicate.json().await.unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["idempotent"], true);
    assert_eq!(body["feedSeq"], 1);
    assert_eq!(body["headAnnouncement"]["headSeq"], 1);
}

#[tokio::test]
async fn test_swarm_hub_conflicting_duplicate_revocation_is_rejected() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let first_revocation = make_revocation(1);
    let mut conflicting_revocation = make_revocation(1);
    conflicting_revocation["reason"] = json!("Conflicting revocation reason");

    let first = publish_revocation(&client, &daemon, &first_revocation).await;
    assert!(first.status().is_success());

    let conflict = publish_revocation(&client, &daemon, &conflicting_revocation).await;
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);

    let body: Value = conflict.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_SEQ_CONFLICT");
}

#[tokio::test]
async fn test_swarm_hub_supersede_projection_stores_replacements_per_target_digest() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding_one = make_finding(1);
    let mut finding_two = make_finding(2);
    finding_two["findingId"] = finding_one["findingId"].clone();
    finding_two["summary"] = json!("Re-emitted finding with a distinct digest");

    let publish_finding_one = publish_finding(&client, &daemon, &finding_one).await;
    assert!(publish_finding_one.status().is_success());
    let publish_finding_two = publish_finding(&client, &daemon, &finding_two).await;
    assert!(publish_finding_two.status().is_success());

    let target_id = finding_one["findingId"]
        .as_str()
        .expect("findingId should be a string");
    let target_digest_one = finding_envelope_hash(&finding_one);
    let target_digest_two = finding_envelope_hash(&finding_two);
    let replacement_one = ("fnd_projection_replacement_0001", hex_digest(40_001));
    let replacement_two = ("fnd_projection_replacement_0002", hex_digest(40_002));

    let revocation_one = make_supersede_revocation(
        1,
        target_id,
        &target_digest_one,
        replacement_one.0,
        &replacement_one.1,
    );
    let revocation_two = make_supersede_revocation(
        2,
        target_id,
        &target_digest_two,
        replacement_two.0,
        &replacement_two.1,
    );

    let first = publish_revocation(&client, &daemon, &revocation_one).await;
    assert!(first.status().is_success());
    let second = publish_revocation(&client, &daemon, &revocation_two).await;
    assert!(second.status().is_success());

    let conn = open_control_db(&daemon);
    let projection_count: i64 = conn
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM swarm_revocation_targets
            WHERE feed_id = 'fed.alpha' AND issuer_id = ?1 AND target_schema = ?2 AND target_id = ?3
            "#,
            [ISSUER_ID, FINDING_ENVELOPE_SCHEMA, target_id],
            |row| row.get(0),
        )
        .expect("query revocation projection count");
    assert_eq!(projection_count, 2);

    let projection_one: (String, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            r#"
            SELECT current_action, replacement_schema, replacement_id, replacement_digest
            FROM swarm_revocation_targets
            WHERE feed_id = 'fed.alpha'
              AND issuer_id = ?1
              AND target_schema = ?2
              AND target_id = ?3
              AND target_digest = ?4
            "#,
            [ISSUER_ID, FINDING_ENVELOPE_SCHEMA, target_id, target_digest_one.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("load first supersede projection");
    assert_eq!(projection_one.0, "supersede");
    assert_eq!(projection_one.1.as_deref(), Some(FINDING_ENVELOPE_SCHEMA));
    assert_eq!(projection_one.2.as_deref(), Some(replacement_one.0));
    assert_eq!(projection_one.3.as_deref(), Some(replacement_one.1.as_str()));

    let projection_two: (String, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            r#"
            SELECT current_action, replacement_schema, replacement_id, replacement_digest
            FROM swarm_revocation_targets
            WHERE feed_id = 'fed.alpha'
              AND issuer_id = ?1
              AND target_schema = ?2
              AND target_id = ?3
              AND target_digest = ?4
            "#,
            [ISSUER_ID, FINDING_ENVELOPE_SCHEMA, target_id, target_digest_two.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("load second supersede projection");
    assert_eq!(projection_two.0, "supersede");
    assert_eq!(projection_two.1.as_deref(), Some(FINDING_ENVELOPE_SCHEMA));
    assert_eq!(projection_two.2.as_deref(), Some(replacement_two.0));
    assert_eq!(projection_two.3.as_deref(), Some(replacement_two.1.as_str()));
}

#[tokio::test]
async fn test_swarm_hub_findings_routes_remain_finding_only_after_revocation_lane_adds_parallel_history() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding = make_finding(1);
    let finding_publish = publish_finding(&client, &daemon, &finding).await;
    assert!(finding_publish.status().is_success());
    let finding_publish_body: Value = finding_publish.json().await.unwrap();
    let publish_fact_id =
        assert_canonical_head_announcement(&finding_publish_body["headAnnouncement"], &finding, 1);

    let revocation = make_revocation(1);
    let revocation_publish = publish_revocation(&client, &daemon, &revocation).await;
    assert!(revocation_publish.status().is_success());

    let head = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/head?issuerId={}",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch findings head");

    assert!(head.status().is_success());
    let head_body: Value = head.json().await.unwrap();
    let head_fact_id = assert_canonical_head_announcement(&head_body, &finding, 1);
    assert_eq!(head_fact_id, publish_fact_id);

    let replay = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/replay?issuerId={}&fromSeq=1&toSeq=1",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch findings replay");

    assert!(replay.status().is_success());
    let replay_body: Value = replay.json().await.unwrap();
    assert_eq!(replay_body["schema"], REPLAY_SCHEMA);
    assert_eq!(replay_body["envelopes"].as_array().unwrap().len(), 1);
    assert_eq!(replay_body["envelopes"][0]["schema"], FINDING_ENVELOPE_SCHEMA);
    assert_eq!(replay_body["envelopes"][0]["findingId"], finding["findingId"]);
    assert!(replay_body["envelopes"][0].get("revocationId").is_none());
    let replay_fact_id =
        assert_canonical_head_announcement(&replay_body["headAnnouncement"], &finding, 1);
    assert_eq!(replay_fact_id, publish_fact_id);
}

#[tokio::test]
async fn test_swarm_hub_allows_re_emitting_same_finding_id_at_later_feed_seq() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding_one = make_finding(1);
    let mut finding_two = make_finding(2);
    finding_two["findingId"] = finding_one["findingId"].clone();

    let first = publish_finding(&client, &daemon, &finding_one).await;
    assert!(first.status().is_success());

    let second = publish_finding(&client, &daemon, &finding_two).await;
    assert!(second.status().is_success());
    let publish_body: Value = second.json().await.unwrap();
    let publish_fact_id =
        assert_canonical_head_announcement(&publish_body["headAnnouncement"], &finding_two, 2);

    let replay = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/replay?issuerId={}&fromSeq=1&toSeq=2",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch replay range");

    assert!(replay.status().is_success());
    let replay_body: Value = replay.json().await.unwrap();
    assert_eq!(replay_body["envelopes"].as_array().unwrap().len(), 2);
    assert_eq!(replay_body["envelopes"][0]["findingId"], finding_one["findingId"]);
    assert_eq!(replay_body["envelopes"][1]["findingId"], finding_one["findingId"]);
    let replay_fact_id =
        assert_canonical_head_announcement(&replay_body["headAnnouncement"], &finding_two, 2);
    assert_eq!(replay_fact_id, publish_fact_id);

    let head = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/head?issuerId={}",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch synthesized head");

    assert!(head.status().is_success());
    let head_body: Value = head.json().await.unwrap();
    let head_fact_id = assert_canonical_head_announcement(&head_body, &finding_two, 2);
    assert_eq!(head_fact_id, publish_fact_id);
}

#[tokio::test]
async fn test_swarm_hub_replay_rejects_invalid_query() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/api/v1/swarm/feeds/fed.alpha/replay?issuerId={}&fromSeq=0&toSeq=2",
            daemon.url, ISSUER_ID
        ))
        .send()
        .await
        .expect("failed to fetch invalid replay range");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "INVALID_REPLAY_QUERY");
}

#[tokio::test]
async fn test_swarm_hub_blob_lookup_uses_stored_refs() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let finding = make_finding(1);
    let publish = publish_finding(&client, &daemon, &finding).await;
    assert!(publish.status().is_success());

    let resp = client
        .get(format!(
            "{}/api/v1/swarm/blobs/{}",
            daemon.url, DIGEST_1
        ))
        .send()
        .await
        .expect("failed to fetch blob ref");

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["schema"], "clawdstrike.swarm.blob_lookup.v1");
    assert_eq!(body["digest"], DIGEST_1);
    assert_eq!(body["bytesAvailable"], false);
    assert_eq!(body["refs"].as_array().unwrap().len(), 1);
    assert_eq!(body["refs"][0]["feedId"], "fed.alpha");
    assert_eq!(body["refs"][0]["issuerId"], ISSUER_ID);
    assert_eq!(body["refs"][0]["feedSeq"], 1);
    assert_eq!(body["refs"][0]["findingId"], "fnd_0001");
}

#[tokio::test]
async fn test_swarm_hub_blob_pin_records_request() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/swarm/blobs/pin", daemon.url))
        .json(&json!({
            "digest": DIGEST_1,
            "requestedBy": "integration-test",
            "note": "record pin intent"
        }))
        .send()
        .await
        .expect("failed to request blob pin");

    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["recorded"], true);
    assert_eq!(body["digest"], DIGEST_1);
    assert_eq!(body["status"], "recorded");

    let conn = open_control_db(&daemon);
    let stored: (String, String, String) = conn
        .query_row(
            r#"
            SELECT digest, status, request_json
            FROM swarm_blob_pin_requests
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("blob pin request should be recorded");

    assert_eq!(stored.0, DIGEST_1);
    assert_eq!(stored.1, "recorded");
    assert!(stored.2.contains("integration-test"));
}

#[tokio::test]
async fn test_swarm_hub_rejects_blocked_issuer_before_append() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "blockedIssuers": [ISSUER_ID]
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let finding = make_finding(1);
    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_blocked_revocation_issuer_before_append() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "blockedIssuers": [ISSUER_ID]
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let revocation = make_revocation(1);
    let resp = publish_revocation(&client, &daemon, &revocation).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_revocations(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_untrusted_issuer_when_allowlist_is_non_empty() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "trustedIssuers": [format!("aegis:ed25519:{}", "c".repeat(64))]
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let finding = make_finding(1);
    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_disallowed_revocation_schema_before_append() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "allowedSchemas": [HEAD_ANNOUNCEMENT_SCHEMA]
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let revocation = make_revocation(1);
    let resp = publish_revocation(&client, &daemon, &revocation).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_revocations(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_disallowed_schema_before_append() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "allowedSchemas": [HEAD_ANNOUNCEMENT_SCHEMA]
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let finding = make_finding(1);
    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_missing_revocation_attestation_when_policy_requires_it() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "requireAttestation": true
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let mut revocation = make_revocation(1);
    revocation
        .as_object_mut()
        .expect("revocation should serialize as an object")
        .remove("attestation");
    let resp = publish_revocation(&client, &daemon, &revocation).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_revocations(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_missing_attestation_when_policy_requires_it() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "requireAttestation": true
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let mut finding = make_finding(1);
    finding
        .as_object_mut()
        .expect("finding should serialize as an object")
        .remove("attestation");
    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_forged_revocation_attestation_when_strict_trust_binds_issuer() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let signed_revocation = make_signed_revocation(1);
    let trusted_issuer = signed_revocation["issuerId"]
        .as_str()
        .expect("signed revocation issuerId should be a string")
        .to_string();
    let trust_policy = make_trust_policy(json!({
        "trustedIssuers": [trusted_issuer],
        "requireAttestation": true
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let mut forged_revocation = signed_revocation.clone();
    forged_revocation["reason"] = json!("Forged revocation after signing");
    let resp = publish_revocation(&client, &daemon, &forged_revocation).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_revocations(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_forged_attestation_when_strict_trust_binds_issuer() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let signed_finding = make_signed_finding(1);
    let trusted_issuer = signed_finding["issuerId"]
        .as_str()
        .expect("signed finding issuerId should be a string")
        .to_string();
    let trust_policy = make_trust_policy(json!({
        "trustedIssuers": [trusted_issuer],
        "requireAttestation": true
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let mut forged_finding = signed_finding.clone();
    forged_finding["summary"] = json!("Forged after signing");
    let resp = publish_finding(&client, &daemon, &forged_finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_accepts_valid_signed_attestation_when_strict_trust_binds_issuer() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let signed_finding = make_signed_finding(1);
    let trusted_issuer = signed_finding["issuerId"]
        .as_str()
        .expect("signed finding issuerId should be a string")
        .to_string();
    let trust_policy = make_trust_policy(json!({
        "trustedIssuers": [trusted_issuer],
        "requireAttestation": true
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let resp = publish_finding(&client, &daemon, &signed_finding).await;

    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], true);
    assert_eq!(body["idempotent"], false);
    assert_eq!(body["feedSeq"], 1);
    assert_eq!(body["issuerId"], signed_finding["issuerId"]);

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 1);
}

#[tokio::test]
async fn test_swarm_hub_rejects_missing_witness_proofs_when_policy_requires_them() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();
    let trust_policy = make_trust_policy(json!({
        "requireWitnessProofs": true
    }));

    let update = update_trust_policy(&client, &daemon, &trust_policy).await;
    assert!(update.status().is_success());

    let finding = make_finding(1);
    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "SWARM_TRUST_POLICY_REJECTED");

    let conn = open_control_db(&daemon);
    assert_eq!(count_swarm_findings(&conn), 0);
}

#[tokio::test]
async fn test_swarm_hub_rejects_schema_mismatch() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let mut finding = make_finding(1);
    finding["schema"] = json!("clawdstrike.swarm.finding_envelope.v999");

    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "INVALID_FINDING_ENVELOPE");
}

#[tokio::test]
async fn test_swarm_hub_rejects_attestation_issuer_mismatch() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let mut finding = make_finding(1);
    finding["attestation"]["publicKey"] =
        json!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "INVALID_FINDING_ENVELOPE");
}

#[tokio::test]
async fn test_swarm_hub_rejects_invalid_blob_digest() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let mut finding = make_finding(1);
    finding["blobRefs"][0]["digest"] = json!("0xABC");

    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "INVALID_FINDING_ENVELOPE");
}

#[tokio::test]
async fn test_swarm_hub_rejects_invalid_confidence() {
    let daemon = TestDaemon::spawn();
    let client = reqwest::Client::new();

    let mut finding = make_finding(1);
    finding["confidence"] = json!(1.5);

    let resp = publish_finding(&client, &daemon, &finding).await;

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "INVALID_FINDING_ENVELOPE");
}
