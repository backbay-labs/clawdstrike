use hush_core::canonical::canonicalize;
use hush_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::revocation::RevocationStore;
use crate::token::{SignedDelegationToken, DELEGATION_AUDIENCE};
use crate::types::AgentId;

pub const MESSAGE_AUDIENCE: &str = "clawdstrike:message";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageClaims {
    /// Sender agent id
    pub iss: AgentId,
    /// Recipient agent id
    pub sub: AgentId,
    /// Audience
    pub aud: String,
    /// Issued at (Unix timestamp, seconds)
    pub iat: i64,
    /// Expiration (Unix timestamp, seconds)
    pub exp: i64,
    /// Message id
    pub jti: String,
    /// Replay nonce (per {iss,sub})
    pub nonce: String,
    /// Message payload
    pub payload: serde_json::Value,
    /// Optional delegation token (issuer != iss).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<SignedDelegationToken>,
    /// Optional correlation context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<serde_json::Value>,
}

impl MessageClaims {
    pub fn new(iss: AgentId, sub: AgentId, iat: i64, exp: i64, payload: serde_json::Value) -> Self {
        Self {
            iss,
            sub,
            aud: MESSAGE_AUDIENCE.to_string(),
            iat,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
            nonce: uuid::Uuid::new_v4().to_string(),
            payload,
            delegation: None,
            ctx: None,
        }
    }

    pub fn validate_basic(&self) -> Result<()> {
        if self.aud.trim().is_empty() {
            return Err(Error::InvalidClaims("aud is empty".to_string()));
        }
        if self.jti.trim().is_empty() {
            return Err(Error::InvalidClaims("jti is empty".to_string()));
        }
        if self.nonce.trim().is_empty() {
            return Err(Error::InvalidClaims("nonce is empty".to_string()));
        }
        if self.exp <= self.iat {
            return Err(Error::InvalidClaims("exp must be > iat".to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMessage {
    pub claims: MessageClaims,
    pub signature: Signature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

impl SignedMessage {
    pub fn sign(claims: MessageClaims, keypair: &Keypair) -> Result<Self> {
        claims.validate_basic()?;
        let canonical = canonical_claims_json(&claims)?;
        let signature = keypair.sign(canonical.as_bytes());
        Ok(Self {
            claims,
            signature,
            public_key: None,
        })
    }

    pub fn sign_with_public_key(claims: MessageClaims, keypair: &Keypair) -> Result<Self> {
        let mut msg = Self::sign(claims, keypair)?;
        msg.public_key = Some(keypair.public_key());
        Ok(msg)
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result<bool> {
        self.claims.validate_basic()?;
        let canonical = canonical_claims_json(&self.claims)?;
        Ok(public_key.verify(canonical.as_bytes(), &self.signature))
    }

    pub fn verify_embedded(&self) -> Result<bool> {
        match &self.public_key {
            Some(pk) => self.verify(pk),
            None => Err(Error::InvalidClaims("no embedded public_key".to_string())),
        }
    }

    pub fn validate(&self, now_unix: i64, expected_aud: &str) -> Result<()> {
        self.claims.validate_basic()?;
        if self.claims.aud != expected_aud {
            return Err(Error::AudienceMismatch);
        }
        if now_unix > self.claims.exp {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// Validate signature, time bounds, replay nonce, and (optionally) the embedded delegation token.
    ///
    /// - `sender_key` verifies the message signature.
    /// - If a delegation token is present:
    ///   - It must be bound to this sender (`token.sub == message.iss`)
    ///   - It must validate time bounds and audience
    ///   - It must not be revoked in the revocation store
    ///   - It must verify either via embedded `token.public_key` or `delegation_issuer_key`.
    pub fn verify_and_validate(
        &self,
        sender_key: &PublicKey,
        now_unix: i64,
        revocations: &dyn RevocationStore,
        delegation_issuer_key: Option<&PublicKey>,
    ) -> Result<()> {
        self.validate(now_unix, MESSAGE_AUDIENCE)?;

        if !self.verify(sender_key)? {
            return Err(Error::InvalidSignature);
        }

        // Replay protection: per (iss, sub).
        let scope = format!("msg:{}:{}", self.claims.iss, self.claims.sub);
        let ttl_secs = (self.claims.exp - now_unix).max(1);
        revocations.check_and_mark_nonce(&scope, &self.claims.nonce, now_unix, ttl_secs)?;

        // Optional delegation token.
        if let Some(token) = &self.claims.delegation {
            let key = match (&token.public_key, delegation_issuer_key) {
                (Some(pk), _) => pk,
                (None, Some(pk)) => pk,
                (None, None) => {
                    return Err(Error::InvalidClaims(
                        "delegation token missing public key".to_string(),
                    ))
                }
            };

            token.verify_and_validate(
                key,
                now_unix,
                revocations,
                DELEGATION_AUDIENCE,
                Some(&self.claims.iss),
            )?;
        }

        Ok(())
    }
}

fn canonical_claims_json(claims: &MessageClaims) -> Result<String> {
    let value = serde_json::to_value(claims)?;
    Ok(canonicalize(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::InMemoryRevocationStore;
    use crate::token::DelegationClaims;
    use crate::types::AgentCapability;

    #[test]
    fn signed_message_round_trip_verifies() {
        let store = InMemoryRevocationStore::default();
        let now = 1_700_000_000;

        let a = AgentId::new("agent:a").unwrap();
        let b = AgentId::new("agent:b").unwrap();
        let a_key = Keypair::generate();

        let claims = MessageClaims::new(a.clone(), b, now, now + 60, serde_json::json!({"k":"v"}));
        let msg = SignedMessage::sign(claims, &a_key).unwrap();
        msg.verify_and_validate(&a_key.public_key(), now, &store, None)
            .unwrap();
    }

    #[test]
    fn delegation_token_bound_to_sender() {
        let store = InMemoryRevocationStore::default();
        let now = 1_700_000_000;

        let issuer = AgentId::new("agent:issuer").unwrap();
        let sender = AgentId::new("agent:sender").unwrap();
        let recipient = AgentId::new("agent:recipient").unwrap();

        let issuer_key = Keypair::generate();
        let sender_key = Keypair::generate();

        let dlg_claims = DelegationClaims::new(
            issuer,
            sender.clone(),
            now,
            now + 60,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();
        let token = SignedDelegationToken::sign(dlg_claims, &issuer_key).unwrap();

        let mut msg_claims = MessageClaims::new(
            sender.clone(),
            recipient,
            now,
            now + 60,
            serde_json::json!({}),
        );
        msg_claims.delegation = Some(token);

        let msg = SignedMessage::sign(msg_claims, &sender_key).unwrap();
        msg.verify_and_validate(
            &sender_key.public_key(),
            now,
            &store,
            Some(&issuer_key.public_key()),
        )
        .unwrap();
    }
}
