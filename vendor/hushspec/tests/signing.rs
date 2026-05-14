#![cfg(feature = "signing")]

use hushspec::signing::{
    FORMAT_VERSION, PolicySignature, VerificationOutcome, content_hash, decode_signing_key,
    decode_verifying_key, encode_signing_key, encode_verifying_key, format_private_key_pem,
    format_public_key_pem, generate_keypair, load_signature, parse_private_key_pem,
    parse_public_key_pem, save_signature, sign_policy, verify_policy,
};

#[test]
fn generate_keypair_produces_valid_pair() {
    let (sk, vk) = generate_keypair();
    // The verifying key derived from the signing key should match
    assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());
}

#[test]
fn generate_keypair_produces_distinct_keys() {
    let (sk1, _) = generate_keypair();
    let (sk2, _) = generate_keypair();
    assert_ne!(sk1.to_bytes(), sk2.to_bytes());
}

#[test]
fn sign_and_verify_policy_roundtrip() {
    let (sk, vk) = generate_keypair();
    let policy = b"hushspec: \"0.1.0\"\nname: test-policy\nrules:\n  egress:\n    default: block\n";

    let sig = sign_policy(policy, &sk, "test-key-001", Some("ci-bot@example.com"));

    assert_eq!(sig.format_version, FORMAT_VERSION);
    assert_eq!(sig.algorithm, "ed25519");
    assert_eq!(sig.key_id, "test-key-001");
    assert_eq!(sig.signer.as_deref(), Some("ci-bot@example.com"));
    assert_eq!(sig.content_hash, content_hash(policy));

    let outcome = verify_policy(policy, &sig, &vk);
    match outcome {
        VerificationOutcome::Valid {
            key_id,
            signed_at,
            signer,
        } => {
            assert_eq!(key_id, "test-key-001");
            assert!(!signed_at.is_empty());
            assert_eq!(signer.as_deref(), Some("ci-bot@example.com"));
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn verify_fails_with_wrong_key() {
    let (sk, _vk) = generate_keypair();
    let (_sk2, vk2) = generate_keypair();
    let policy = b"some policy content";

    let sig = sign_policy(policy, &sk, "key-a", None);
    let outcome = verify_policy(policy, &sig, &vk2);
    assert!(
        matches!(outcome, VerificationOutcome::Invalid { .. }),
        "expected Invalid when verifying with wrong key, got {outcome:?}"
    );
}

#[test]
fn verify_fails_with_tampered_content() {
    let (sk, vk) = generate_keypair();
    let original = b"original policy content";

    let sig = sign_policy(original, &sk, "key-b", None);
    let tampered = b"tampered policy content";
    let outcome = verify_policy(tampered, &sig, &vk);
    match outcome {
        VerificationOutcome::Invalid { reason } => {
            assert!(
                reason.contains("content hash mismatch"),
                "expected hash mismatch reason, got: {reason}"
            );
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn verify_fails_with_tampered_metadata() {
    let (sk, vk) = generate_keypair();
    let content = b"content";
    let mut sig = sign_policy(content, &sk, "trusted-key", Some("alice@example.com"));
    sig.key_id = "forged-key".to_string();
    sig.signer = Some("mallory@example.com".to_string());
    sig.signed_at = "2099-01-01T00:00:00Z".to_string();

    let outcome = verify_policy(content, &sig, &vk);
    assert!(
        matches!(outcome, VerificationOutcome::Invalid { .. }),
        "expected Invalid when signature metadata is tampered, got {outcome:?}"
    );
}

#[test]
fn verify_rejects_bad_algorithm() {
    let (sk, vk) = generate_keypair();
    let content = b"content";
    let mut sig = sign_policy(content, &sk, "k", None);
    sig.algorithm = "unknown-algo".to_string();

    let outcome = verify_policy(content, &sig, &vk);
    match outcome {
        VerificationOutcome::Invalid { reason } => {
            assert!(reason.contains("unsupported algorithm"));
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn verify_rejects_bad_format_version() {
    let (sk, vk) = generate_keypair();
    let content = b"content";
    let mut sig = sign_policy(content, &sk, "k", None);
    sig.format_version = "99.0.0".to_string();

    let outcome = verify_policy(content, &sig, &vk);
    match outcome {
        VerificationOutcome::Invalid { reason } => {
            assert!(reason.contains("unsupported format version"));
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn content_hash_is_sha256_hex() {
    let hash = content_hash(b"hello world");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn content_hash_matches_known_value() {
    // SHA-256 of empty string
    let hash = content_hash(b"");
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn signature_json_serialization_roundtrip() {
    let (sk, _vk) = generate_keypair();
    let content = b"roundtrip test data";
    let sig = sign_policy(content, &sk, "json-key", Some("alice@example.com"));

    let json = serde_json::to_string_pretty(&sig).unwrap();
    let parsed: PolicySignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, parsed);
}

#[test]
fn signature_json_without_signer() {
    let (sk, _vk) = generate_keypair();
    let content = b"no signer test";
    let sig = sign_policy(content, &sk, "no-signer-key", None);

    let json = serde_json::to_string_pretty(&sig).unwrap();
    // signer should not appear in JSON when None (skip_serializing_if)
    assert!(!json.contains("\"signer\""));
    let parsed: PolicySignature = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.signer, None);
}

#[test]
fn save_and_load_signature_file_roundtrip() {
    let (sk, _vk) = generate_keypair();
    let content = b"file io test";
    let sig = sign_policy(content, &sk, "file-key", Some("bob"));

    let dir = std::env::temp_dir().join(format!(
        "hushspec-signing-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let sig_path = dir.join("test-policy.yaml.sig");
    save_signature(&sig, &sig_path).unwrap();

    let loaded = load_signature(&sig_path).unwrap();
    assert_eq!(sig, loaded);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn key_encoding_roundtrip() {
    let (sk, vk) = generate_keypair();

    let sk_b64 = encode_signing_key(&sk);
    let sk2 = decode_signing_key(&sk_b64).unwrap();
    assert_eq!(sk.to_bytes(), sk2.to_bytes());

    let vk_b64 = encode_verifying_key(&vk);
    let vk2 = decode_verifying_key(&vk_b64).unwrap();
    assert_eq!(vk.to_bytes(), vk2.to_bytes());
}

#[test]
fn pem_key_format_roundtrip() {
    let (sk, vk) = generate_keypair();

    let sk_pem = format_private_key_pem(&sk);
    assert!(sk_pem.contains("BEGIN HUSHSPEC PRIVATE KEY"));
    assert!(sk_pem.contains("END HUSHSPEC PRIVATE KEY"));
    let sk2 = parse_private_key_pem(&sk_pem).unwrap();
    assert_eq!(sk.to_bytes(), sk2.to_bytes());

    let vk_pem = format_public_key_pem(&vk);
    assert!(vk_pem.contains("BEGIN HUSHSPEC PUBLIC KEY"));
    assert!(vk_pem.contains("END HUSHSPEC PUBLIC KEY"));
    let vk2 = parse_public_key_pem(&vk_pem).unwrap();
    assert_eq!(vk.to_bytes(), vk2.to_bytes());
}

#[test]
fn pem_parser_accepts_raw_base64() {
    let (sk, vk) = generate_keypair();

    let sk_raw = encode_signing_key(&sk);
    let sk2 = parse_private_key_pem(&sk_raw).unwrap();
    assert_eq!(sk.to_bytes(), sk2.to_bytes());

    let vk_raw = encode_verifying_key(&vk);
    let vk2 = parse_public_key_pem(&vk_raw).unwrap();
    assert_eq!(vk.to_bytes(), vk2.to_bytes());
}

#[test]
fn end_to_end_sign_verify_tamper() {
    let (sk, vk) = generate_keypair();

    let policy = br#"hushspec: "0.1.0"
name: production-agent
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
    exceptions: []
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#;

    // Sign
    let sig = sign_policy(policy, &sk, "prod-key-2026Q1", Some("secops@corp.io"));

    // Verify -- should be valid
    let outcome = verify_policy(policy, &sig, &vk);
    assert!(matches!(outcome, VerificationOutcome::Valid { .. }));

    // Tamper: change "block" to "allow" in default egress
    let tampered_str = String::from_utf8(policy.to_vec())
        .unwrap()
        .replace("default: block", "default: allow");

    // Re-verify with tampered content -- should fail
    let outcome2 = verify_policy(tampered_str.as_bytes(), &sig, &vk);
    assert!(
        matches!(outcome2, VerificationOutcome::Invalid { .. }),
        "tampered content should fail verification"
    );
}
