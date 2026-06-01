#[test]
fn install_requested_identity_mismatch_is_detected() {
    let installed = clawdstrike::pkg::store::InstalledPackage {
        name: "actual".to_string(),
        version: "1.2.3".to_string(),
        path: std::path::PathBuf::from("/tmp/actual"),
        content_hash: hush_core::sha256(b"abc"),
    };
    assert!(!requested_identity_matches_install(
        "expected", "1.2.3", &installed
    ));
    assert!(!requested_identity_matches_install(
        "actual", "9.9.9", &installed
    ));
    assert!(requested_identity_matches_install(
        "actual", "1.2.3", &installed
    ));
}

#[test]
fn read_archive_identity_returns_manifest_name_and_version() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("clawdstrike-pkg.toml"),
        r#"[package]
name = "identity-demo"
version = "1.2.3"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
    )
    .unwrap();
    std::fs::write(src.join("README.md"), "ok").unwrap();
    let archive_path = tmp.path().join("identity-demo-1.2.3.cpkg");
    archive::pack(&src, &archive_path).unwrap();

    let (name, version) = read_archive_identity(&archive_path).unwrap();
    assert_eq!(name, "identity-demo");
    assert_eq!(version, "1.2.3");
}

#[test]
fn select_default_registry_version_chooses_newest_non_yanked() {
    let stats = serde_json::json!({
        "versions": [
            { "version": "1.9.8", "yanked": false, "published_at": "2026-01-01T00:00:00Z" },
            { "version": "1.9.9", "yanked": false, "published_at": "2026-02-01T00:00:00Z" },
            { "version": "2.0.0", "yanked": true, "published_at": "2026-03-01T00:00:00Z" }
        ],
        "latest_version": "2.0.0"
    });
    assert_eq!(
        select_default_registry_version(&stats).as_deref(),
        Some("1.9.9")
    );
}

#[test]
fn select_default_registry_version_prefers_latest_hint_when_allowed() {
    let stats = serde_json::json!({
        "versions": [
            { "version": "1.0.0", "yanked": false, "published_at": "2026-01-01T00:00:00Z" },
            { "version": "2.0.0", "yanked": false, "published_at": "2026-02-01T00:00:00Z" }
        ],
        "latest_version": "2.0.0"
    });
    assert_eq!(
        select_default_registry_version(&stats).as_deref(),
        Some("2.0.0")
    );
}

#[test]
fn select_default_registry_version_returns_none_when_all_yanked() {
    let stats = serde_json::json!({
        "versions": [
            { "version": "2.0.0", "yanked": true },
            { "version": "1.9.9", "yanked": true }
        ],
        "latest_version": "2.0.0"
    });
    assert_eq!(select_default_registry_version(&stats), None);
}

#[test]
fn select_default_registry_version_fails_closed_without_yank_state() {
    let stats = serde_json::json!({
        "versions": [
            { "version": "2.0.0", "published_at": "2026-03-01T00:00:00Z" },
            { "version": "1.9.9", "published_at": "2026-02-01T00:00:00Z" }
        ],
        "latest_version": "2.0.0"
    });
    assert_eq!(select_default_registry_version(&stats), None);
}

#[test]
fn select_default_registry_version_falls_back_when_versions_missing() {
    let stats = serde_json::json!({
        "latest_version": "1.4.2"
    });
    assert_eq!(
        select_default_registry_version(&stats).as_deref(),
        Some("1.4.2")
    );
}

#[test]
fn rollback_backup_restores_previous_install_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let install_path = tmp.path().join("pkg").join("1.0.0");
    std::fs::create_dir_all(&install_path).unwrap();
    std::fs::write(install_path.join("marker.txt"), b"old").unwrap();

    let installed = clawdstrike::pkg::store::InstalledPackage {
        name: "demo".to_string(),
        version: "1.0.0".to_string(),
        path: install_path.clone(),
        content_hash: hush_core::sha256(b"old"),
    };

    let backup = create_install_rollback_backup(Some(&installed))
        .unwrap()
        .expect("backup should exist");
    assert!(backup.backup_path.exists());

    std::fs::remove_dir_all(&install_path).unwrap();
    std::fs::create_dir_all(&install_path).unwrap();
    std::fs::write(install_path.join("marker.txt"), b"new").unwrap();

    restore_install_from_backup(&backup).unwrap();

    let restored = std::fs::read(install_path.join("marker.txt")).unwrap();
    assert_eq!(restored, b"old");
    assert!(!backup.backup_path.exists());
}

#[test]
fn recompute_installed_content_fingerprint_detects_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("clawdstrike-pkg.toml"),
        r#"[package]
name = "verify-demo"
version = "1.0.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
    )
    .unwrap();
    std::fs::write(src.join("README.md"), "hello").unwrap();
    let archive_path = tmp.path().join("verify-demo-1.0.0.cpkg");
    let archive_hash = clawdstrike::pkg::archive::pack(&src, &archive_path).unwrap();

    let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
    let installed = store.install_from_file(&archive_path).unwrap();
    assert_eq!(installed.content_hash, archive_hash);

    let meta: StoreMetadata = serde_json::from_str(
        &std::fs::read_to_string(installed.path.join(".pkg-meta.json")).unwrap(),
    )
    .unwrap();
    let expected = meta.content_fingerprint.unwrap();

    let recomputed = recompute_installed_content_fingerprint(&installed.path).unwrap();
    assert_eq!(recomputed, expected);

    std::fs::write(installed.path.join("README.md"), "tampered").unwrap();
    let tampered = recompute_installed_content_fingerprint(&installed.path).unwrap();
    assert_ne!(tampered, expected);
}

#[test]
fn certified_transparency_verification_rejects_tampered_proof() {
    let registry = hush_core::Keypair::from_seed(&[77u8; 32]);
    let leaf = LeafData {
        package_name: "demo".to_string(),
        version: "1.0.0".to_string(),
        content_hash: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        timestamp: "2026-02-28T00:00:00Z".to_string(),
    };
    let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
    let idx = tree.append_hash(leaf.leaf_hash().unwrap());
    let proof = tree.generate_inclusion_proof(idx).unwrap();
    let root = tree.root().unwrap();
    let checkpoint_timestamp = "2026-02-28T00:00:00Z";
    let checkpoint_sig = registry
        .sign(
            checkpoint_signature_message(root.as_str(), proof.tree_size, checkpoint_timestamp)
                .as_bytes(),
        )
        .to_hex();
    let mut tampered_hashes = proof.proof_path.clone();
    if tampered_hashes.is_empty() {
        tampered_hashes.push("00".repeat(32));
    } else {
        tampered_hashes[0] = "00".repeat(32);
    }

    let attestation = RegistryAttestation {
        checksum: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        publisher_sig: "sig".to_string(),
        registry_sig: None,
        registry_key: Some(registry.public_key().to_hex()),
        published_at: Some("2026-02-28T00:00:00Z".to_string()),
    };
    let proof_resp = RegistryProof {
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        hashes: tampered_hashes,
        root: Some(root),
        checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
        checkpoint_sig: Some(checkpoint_sig),
        checkpoint_key: Some(registry.public_key().to_hex()),
    };

    let err = verify_transparency_proof(
        "demo",
        "1.0.0",
        &attestation,
        &proof_resp,
        &registry.public_key().to_hex(),
    )
    .unwrap_err();
    assert!(err.contains("merkle inclusion proof verification failed"));
}

#[test]
fn certified_transparency_verification_accepts_valid_proof() {
    let registry = hush_core::Keypair::from_seed(&[78u8; 32]);
    let leaf = LeafData {
        package_name: "demo".to_string(),
        version: "1.0.0".to_string(),
        content_hash: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        timestamp: "2026-02-28T00:00:00Z".to_string(),
    };
    let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
    let idx = tree.append_hash(leaf.leaf_hash().unwrap());
    let inclusion = tree.generate_inclusion_proof(idx).unwrap();
    let root = tree.root().unwrap();
    let checkpoint_timestamp = "2026-02-28T00:00:00Z";
    let checkpoint_sig = registry
        .sign(
            checkpoint_signature_message(
                root.as_str(),
                inclusion.tree_size,
                checkpoint_timestamp,
            )
            .as_bytes(),
        )
        .to_hex();

    let attestation = RegistryAttestation {
        checksum: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        publisher_sig: "sig".to_string(),
        registry_sig: None,
        registry_key: Some(registry.public_key().to_hex()),
        published_at: Some("2026-02-28T00:00:00Z".to_string()),
    };
    let proof_resp = RegistryProof {
        leaf_index: inclusion.leaf_index,
        tree_size: inclusion.tree_size,
        hashes: inclusion.proof_path,
        root: Some(root),
        checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
        checkpoint_sig: Some(checkpoint_sig),
        checkpoint_key: Some(registry.public_key().to_hex()),
    };

    verify_transparency_proof(
        "demo",
        "1.0.0",
        &attestation,
        &proof_resp,
        &registry.public_key().to_hex(),
    )
    .unwrap();
}

#[test]
fn certified_transparency_verification_rejects_checkpoint_key_mismatch() {
    let trusted_registry = hush_core::Keypair::from_seed(&[79u8; 32]);
    let proof_signer = hush_core::Keypair::from_seed(&[80u8; 32]);
    let leaf = LeafData {
        package_name: "demo".to_string(),
        version: "1.0.0".to_string(),
        content_hash: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        timestamp: "2026-02-28T00:00:00Z".to_string(),
    };
    let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
    let idx = tree.append_hash(leaf.leaf_hash().unwrap());
    let inclusion = tree.generate_inclusion_proof(idx).unwrap();
    let root = tree.root().unwrap();
    let checkpoint_timestamp = "2026-02-28T00:00:00Z";
    let checkpoint_sig = proof_signer
        .sign(
            checkpoint_signature_message(
                root.as_str(),
                inclusion.tree_size,
                checkpoint_timestamp,
            )
            .as_bytes(),
        )
        .to_hex();
    let attestation = RegistryAttestation {
        checksum: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        publisher_sig: "sig".to_string(),
        registry_sig: None,
        registry_key: Some(trusted_registry.public_key().to_hex()),
        published_at: Some("2026-02-28T00:00:00Z".to_string()),
    };
    let proof_resp = RegistryProof {
        leaf_index: inclusion.leaf_index,
        tree_size: inclusion.tree_size,
        hashes: inclusion.proof_path,
        root: Some(root),
        checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
        checkpoint_sig: Some(checkpoint_sig),
        checkpoint_key: Some(proof_signer.public_key().to_hex()),
    };
    let err = verify_transparency_proof(
        "demo",
        "1.0.0",
        &attestation,
        &proof_resp,
        &trusted_registry.public_key().to_hex(),
    )
    .unwrap_err();
    assert!(err.contains("checkpoint key does not match"));
}

#[test]
fn certified_transparency_verification_rejects_invalid_checkpoint_timestamp() {
    let registry = hush_core::Keypair::from_seed(&[81u8; 32]);
    let leaf = LeafData {
        package_name: "demo".to_string(),
        version: "1.0.0".to_string(),
        content_hash: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        timestamp: "2026-02-28T00:00:00Z".to_string(),
    };
    let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
    let idx = tree.append_hash(leaf.leaf_hash().unwrap());
    let inclusion = tree.generate_inclusion_proof(idx).unwrap();
    let root = tree.root().unwrap();
    let bad_timestamp = "not-a-timestamp";
    let checkpoint_sig = registry
        .sign(
            checkpoint_signature_message(root.as_str(), inclusion.tree_size, bad_timestamp)
                .as_bytes(),
        )
        .to_hex();
    let attestation = RegistryAttestation {
        checksum: "abcd".to_string(),
        publisher_key: "publisher".to_string(),
        publisher_sig: "sig".to_string(),
        registry_sig: None,
        registry_key: Some(registry.public_key().to_hex()),
        published_at: Some("2026-02-28T00:00:00Z".to_string()),
    };
    let proof_resp = RegistryProof {
        leaf_index: inclusion.leaf_index,
        tree_size: inclusion.tree_size,
        hashes: inclusion.proof_path,
        root: Some(root),
        checkpoint_timestamp: Some(bad_timestamp.to_string()),
        checkpoint_sig: Some(checkpoint_sig),
        checkpoint_key: Some(registry.public_key().to_hex()),
    };
    let err = verify_transparency_proof(
        "demo",
        "1.0.0",
        &attestation,
        &proof_resp,
        &registry.public_key().to_hex(),
    )
    .unwrap_err();
    assert!(err.contains("invalid checkpoint timestamp"));
}
