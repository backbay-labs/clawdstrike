use std::path::PathBuf;

use clawdstrike::Policy;

fn assert_template_parses(yaml_rel_path: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(yaml_rel_path);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));

    let policy = Policy::from_yaml_with_extends(&raw, None)
        .unwrap_or_else(|e| panic!("failed to parse policy in {}: {}", path.display(), e));

    // Sanity: template defines a name and should produce a usable policy.
    assert!(!policy.name.trim().is_empty(), "policy.name should be set");
}

#[test]
fn hipaa_template_yaml_parses() {
    assert_template_parses("../../fixtures/certification/policies/hipaa-policy.yaml");
}

#[test]
fn pci_template_yaml_parses() {
    assert_template_parses("../../fixtures/certification/policies/pci-dss-policy.yaml");
}

#[test]
fn soc2_template_yaml_parses() {
    assert_template_parses("../../fixtures/certification/policies/soc2-policy.yaml");
}
