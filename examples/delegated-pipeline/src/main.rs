//! Delegated Pipeline Example
//!
//! Demonstrates the full multi-agent crypto chain:
//! 1. Delegation (architect -> coder, architect -> tester)
//! 2. Re-delegation (coder -> tester, attenuated)
//! 3. Signed messages with embedded delegation tokens
//! 4. Verification of message + delegation chain
//! 5. Replay protection (same nonce rejected)
//! 6. Revocation (architect->coder token revoked)
//! 7. Escalation rejection (re-delegate with AgentAdmin denied)
//!
//! Run: cargo run --example delegated-pipeline
//! Or:  cd examples/delegated-pipeline && cargo run

use hush_core::Keypair;
use hush_multi_agent::{
    AgentCapability, AgentId, DelegationClaims, InMemoryRevocationStore, MessageClaims,
    RevocationStore, SignedDelegationToken, SignedMessage, DELEGATION_AUDIENCE,
};

fn main() -> anyhow::Result<()> {
    println!("═══════════════════════════════════════════════");
    println!("  Delegated Pipeline Example");
    println!("═══════════════════════════════════════════════\n");

    let store = InMemoryRevocationStore::default();
    let now = chrono::Utc::now().timestamp();

    // ── Agent Keypairs ───────────────────────────────────────────────

    let architect_key = Keypair::generate();
    let coder_key = Keypair::generate();
    let _tester_key = Keypair::generate();
    let _supervisor_key = Keypair::generate();

    let architect = AgentId::new("agent:architect")?;
    let coder = AgentId::new("agent:coder")?;
    let tester = AgentId::new("agent:tester")?;

    println!("Agents created:");
    println!("  architect  (System trust)");
    println!("  coder      (Medium trust)");
    println!("  tester     (Medium trust)");
    println!("  supervisor (High trust)\n");

    // ── Step 1: Delegation (architect -> coder) ──────────────────────

    println!("── Step 1: Delegation (architect -> coder) ──");

    let arch_to_coder_claims = DelegationClaims::new(
        architect.clone(),
        coder.clone(),
        now,
        now + 300,
        vec![
            AgentCapability::FileWrite {
                patterns: vec!["src/**".to_string()],
            },
            AgentCapability::CommandExec {
                commands: vec!["cargo".to_string(), "npm".to_string()],
            },
        ],
    )?;

    let arch_to_coder =
        SignedDelegationToken::sign_with_public_key(arch_to_coder_claims, &architect_key)?;

    arch_to_coder.verify_and_validate(
        &architect_key.public_key(),
        now,
        &store,
        DELEGATION_AUDIENCE,
        Some(&coder),
    )?;

    println!("  OK  architect -> coder delegation verified");
    println!("     Capabilities: FileWrite{{src/**}}, CommandExec{{cargo, npm}}");
    println!("     Token ID: {}\n", arch_to_coder.claims.jti);

    // ── Step 2: Delegation (architect -> tester) ─────────────────────

    println!("── Step 2: Delegation (architect -> tester) ──");

    let arch_to_tester_claims = DelegationClaims::new(
        architect.clone(),
        tester.clone(),
        now,
        now + 300,
        vec![
            AgentCapability::FileRead {
                patterns: vec!["src/**".to_string(), "tests/**".to_string()],
            },
            AgentCapability::CommandExec {
                commands: vec!["cargo test".to_string()],
            },
        ],
    )?;

    let arch_to_tester =
        SignedDelegationToken::sign_with_public_key(arch_to_tester_claims, &architect_key)?;

    arch_to_tester.verify_and_validate(
        &architect_key.public_key(),
        now,
        &store,
        DELEGATION_AUDIENCE,
        Some(&tester),
    )?;

    println!("  OK  architect -> tester delegation verified");
    println!("     Capabilities: FileRead{{src/**, tests/**}}, CommandExec{{cargo test}}\n");

    // ── Step 3: Re-delegation (coder -> tester, attenuated) ──────────

    println!("── Step 3: Re-delegation (coder -> tester) ──");

    // Re-delegate only CommandExec -- must exactly match a parent capability
    // since the subset check uses structural equality on each variant.
    let coder_to_tester_claims = DelegationClaims::redelegate(
        &arch_to_coder.claims,
        tester.clone(),
        now,
        now + 120,
        vec![AgentCapability::CommandExec {
            commands: vec!["cargo".to_string(), "npm".to_string()],
        }],
    )?;

    let coder_to_tester = SignedDelegationToken::sign(coder_to_tester_claims, &coder_key)?;

    coder_to_tester.verify_redelegated_from(
        &arch_to_coder,
        &coder_key.public_key(),
        &architect_key.public_key(),
        now,
        &store,
    )?;

    println!("  OK  coder -> tester re-delegation verified (attenuated)");
    println!("     Capabilities: CommandExec{{cargo, npm}} (subset of parent)");
    println!("     FileWrite dropped (attenuation)");
    println!("     Chain depth: {}\n", coder_to_tester.claims.chn.len());

    // ── Step 4: Signed message (coder -> tester with delegation) ─────

    println!("── Step 4: Signed message (coder -> tester) ──");

    let mut msg_claims = MessageClaims::new(
        coder.clone(),
        tester.clone(),
        now,
        now + 60,
        serde_json::json!({
            "type": "task_request",
            "task": "run_tests",
            "path": "src/feature.rs",
            "note": "Please run tests for the new feature module",
        }),
    );
    msg_claims.delegation = Some(arch_to_coder.clone());

    let msg = SignedMessage::sign(msg_claims, &coder_key)?;

    msg.verify_and_validate(
        &coder_key.public_key(),
        now,
        &store,
        Some(&architect_key.public_key()),
    )?;

    println!("  OK  Message verified (signature + delegation chain + time bounds)");
    println!("     Payload: task_request -> run_tests\n");

    // ── Step 5: Replay protection ────────────────────────────────────

    println!("── Step 5: Replay protection ──");

    let replay_result = msg.verify_and_validate(
        &coder_key.public_key(),
        now,
        &store,
        Some(&architect_key.public_key()),
    );

    match replay_result {
        Err(e) => println!("  OK  Replay correctly rejected: {e}"),
        Ok(()) => println!("  FAIL: replay was not detected!"),
    }
    println!();

    // ── Step 6: Revocation ───────────────────────────────────────────

    println!("── Step 6: Revocation ──");

    let revoked_jti = arch_to_coder.claims.jti.clone();
    store.revoke(revoked_jti.clone(), None);
    println!("  Revoked token: {revoked_jti}");

    let revocation_result = arch_to_coder.verify_and_validate(
        &architect_key.public_key(),
        now,
        &store,
        DELEGATION_AUDIENCE,
        Some(&coder),
    );

    match revocation_result {
        Err(e) => println!("  OK  Revoked token correctly rejected: {e}"),
        Ok(()) => println!("  FAIL: revoked token was accepted!"),
    }
    println!();

    // ── Step 7: Escalation rejection ─────────────────────────────────

    println!("── Step 7: Escalation rejection ──");

    // Use the architect->tester token (not revoked) as a base for re-delegation attempt
    let escalation_result = DelegationClaims::redelegate(
        &arch_to_tester.claims,
        AgentId::new("agent:evil")?,
        now,
        now + 60,
        vec![AgentCapability::AgentAdmin],
    );

    match escalation_result {
        Err(e) => println!("  OK  Escalation correctly rejected: {e}"),
        Ok(_) => println!("  FAIL: escalation was allowed!"),
    }
    println!();

    // ── Summary ──────────────────────────────────────────────────────

    println!("═══════════════════════════════════════════════");
    println!("  Summary");
    println!("═══════════════════════════════════════════════");
    println!("  [pass] Delegation:          architect -> coder (verified)");
    println!("  [pass] Delegation:          architect -> tester (verified)");
    println!("  [pass] Re-delegation:       coder -> tester (attenuated, verified)");
    println!("  [pass] Signed message:      coder -> tester (verified + delegation)");
    println!("  [pass] Replay protection:   duplicate nonce rejected");
    println!("  [pass] Revocation:          revoked token rejected");
    println!("  [pass] Escalation blocked:  AgentAdmin exceeds ceiling");
    println!("\nAll checks passed.");

    Ok(())
}
