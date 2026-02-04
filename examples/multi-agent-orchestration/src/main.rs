use hush_core::Keypair;
use hush_multi_agent::{
    AgentCapability, AgentId, DelegationClaims, InMemoryRevocationStore, MessageClaims,
    SignedDelegationToken, SignedMessage, DELEGATION_AUDIENCE,
};

fn main() -> anyhow::Result<()> {
    let store = InMemoryRevocationStore::default();
    let now = chrono::Utc::now().timestamp();

    let planner = AgentId::new("agent:planner")?;
    let coder = AgentId::new("agent:coder")?;
    let deployer = AgentId::new("agent:deployer")?;

    let planner_key = Keypair::generate();
    let coder_key = Keypair::generate();

    // 1) Planner delegates a scoped capability to the coder.
    let dlg_claims = DelegationClaims::new(
        planner,
        coder.clone(),
        now,
        now + 300,
        vec![AgentCapability::FileWrite {
            patterns: vec!["/workspace/src/**".to_string()],
        }],
    )?;

    let delegation = SignedDelegationToken::sign_with_public_key(dlg_claims, &planner_key)?;
    delegation.validate_audience(DELEGATION_AUDIENCE)?;

    // 2) Coder sends a signed message to the deployer, including the delegation token.
    let mut msg_claims = MessageClaims::new(
        coder.clone(),
        deployer,
        now,
        now + 60,
        serde_json::json!({
            "type": "task_request",
            "task": "apply_patch",
            "path": "/workspace/src/main.rs",
            "note": "please apply the change",
        }),
    );
    msg_claims.delegation = Some(delegation);

    let msg = SignedMessage::sign(msg_claims, &coder_key)?;

    // 3) Receiver verifies message signature (coder) + delegation signature (planner).
    msg.verify_and_validate(&coder_key.public_key(), now, &store, None)?;
    println!("OK: message verified (and delegation token accepted)");

    // 4) Replay detection: validating the same message nonce twice should fail.
    let replay = msg.verify_and_validate(&coder_key.public_key(), now, &store, None);
    println!("Replay validation: {}", replay.err().unwrap());

    Ok(())
}

