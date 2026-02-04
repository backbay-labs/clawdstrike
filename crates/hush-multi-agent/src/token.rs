use hush_core::canonical::canonicalize;
use hush_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{AgentCapability, AgentId};

pub const DELEGATION_AUDIENCE: &str = "clawdstrike:delegation";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationClaims {
    /// Issuer (delegating agent)
    pub iss: AgentId,
    /// Subject (receiving agent)
    pub sub: AgentId,
    /// Audience (expected verifier)
    pub aud: String,
    /// Issued at (Unix timestamp, seconds)
    pub iat: i64,
    /// Expiration (Unix timestamp, seconds)
    pub exp: i64,
    /// Not before (Unix timestamp, seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Token ID
    pub jti: String,
    /// Delegated capabilities
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap: Vec<AgentCapability>,
    /// Delegation chain (parent token IDs)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chn: Vec<String>,
    /// Capability ceiling (max privileges for re-delegation)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cel: Vec<AgentCapability>,
    /// Purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pur: Option<String>,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<serde_json::Value>,
}

impl DelegationClaims {
    pub fn new(
        iss: AgentId,
        sub: AgentId,
        iat: i64,
        exp: i64,
        capabilities: Vec<AgentCapability>,
    ) -> Result<Self> {
        let jti = uuid::Uuid::new_v4().to_string();
        let claims = Self {
            iss,
            sub,
            aud: DELEGATION_AUDIENCE.to_string(),
            iat,
            exp,
            nbf: Some(iat),
            jti,
            cap: capabilities,
            chn: Vec::new(),
            cel: Vec::new(),
            pur: None,
            ctx: None,
        };
        claims.validate_basic()?;
        Ok(claims)
    }

    pub fn validate_basic(&self) -> Result<()> {
        if self.aud.trim().is_empty() {
            return Err(Error::InvalidClaims("aud is empty".to_string()));
        }
        if self.jti.trim().is_empty() {
            return Err(Error::InvalidClaims("jti is empty".to_string()));
        }
        if self.exp <= self.iat {
            return Err(Error::InvalidClaims("exp must be > iat".to_string()));
        }
        if self.cap.is_empty() {
            return Err(Error::InvalidClaims("capabilities are empty".to_string()));
        }
        if !self.cel.is_empty() {
            // Ceiling must be a superset of delegated capabilities (attenuation-only).
            let ok = self.cap.iter().all(|cap| self.cel.iter().any(|c| c == cap));
            if !ok {
                return Err(Error::InvalidClaims(
                    "capabilities exceed ceiling".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDelegationToken {
    pub claims: DelegationClaims,
    pub signature: Signature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

impl SignedDelegationToken {
    pub fn sign(claims: DelegationClaims, keypair: &Keypair) -> Result<Self> {
        claims.validate_basic()?;
        let canonical = canonical_claims_json(&claims)?;
        let signature = keypair.sign(canonical.as_bytes());
        Ok(Self {
            claims,
            signature,
            public_key: None,
        })
    }

    pub fn sign_with_public_key(claims: DelegationClaims, keypair: &Keypair) -> Result<Self> {
        let mut token = Self::sign(claims, keypair)?;
        token.public_key = Some(keypair.public_key());
        Ok(token)
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

    pub fn validate_timebounds(&self, now_unix: i64) -> Result<()> {
        if now_unix > self.claims.exp {
            return Err(Error::Expired);
        }
        if let Some(nbf) = self.claims.nbf {
            if now_unix < nbf {
                return Err(Error::NotYetValid);
            }
        }
        Ok(())
    }

    pub fn validate_audience(&self, expected: &str) -> Result<()> {
        if self.claims.aud != expected {
            return Err(Error::AudienceMismatch);
        }
        Ok(())
    }

    pub fn validate_subject(&self, expected: &AgentId) -> Result<()> {
        if &self.claims.sub != expected {
            return Err(Error::SubjectMismatch);
        }
        Ok(())
    }
}

fn canonical_claims_json(claims: &DelegationClaims) -> Result<String> {
    let value = serde_json::to_value(claims)?;
    Ok(canonicalize(&value)?)
}
