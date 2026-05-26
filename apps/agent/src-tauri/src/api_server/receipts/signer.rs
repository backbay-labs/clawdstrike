//! Endpoint receipt signer key loader.
//!
//! Loads the ed25519 signing keypair used to sign endpoint decision
//! receipts. Prefers the enrollment key (when present), falls back to the
//! locally-persisted EDR signing key, and generates one on first use if
//! permitted.

use super::super::*;

pub(crate) fn load_or_create_edr_receipt_signer_with_requirement(
    require_enrolled_signer: bool,
) -> Result<(Keypair, String)> {
    if let Some(key_hex) = crate::enrollment::load_enrollment_key_hex()
        .with_context(|| "load enrollment key for endpoint receipt signer")?
    {
        let keypair = Keypair::from_hex(key_hex.trim())
            .with_context(|| "parse enrollment key for endpoint receipt signer")?;
        let signer_identity = format!("agent-enrollment:{}", keypair.public_key().to_hex());
        return Ok((keypair, signer_identity));
    }

    if require_enrolled_signer {
        anyhow::bail!(
            "endpoint receipt signer requires an enrolled agent key; refusing local EDR signer fallback"
        );
    }

    let path = default_edr_receipt_signing_key_path();
    if path.exists() {
        let key_hex = fs::read_to_string(&path)
            .with_context(|| format!("read endpoint receipt signing key {}", path.display()))?;
        let keypair = Keypair::from_hex(key_hex.trim())
            .with_context(|| "parse endpoint receipt signing key")?;
        let signer_identity = format!("local-edr:{}", keypair.public_key().to_hex());
        return Ok((keypair, signer_identity));
    }

    let keypair = Keypair::generate();
    crate::security::fs::write_private_atomic(
        &path,
        format!("{}\n", keypair.to_hex()).as_bytes(),
        "endpoint receipt signing key",
    )?;
    let signer_identity = format!("local-edr:{}", keypair.public_key().to_hex());
    Ok((keypair, signer_identity))
}
