use hush_core::canonical::canonicalize;
use hush_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::revocation::RevocationStore;
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

    pub fn redelegate(
        parent: &DelegationClaims,
        sub: AgentId,
        iat: i64,
        exp: i64,
        capabilities: Vec<AgentCapability>,
    ) -> Result<Self> {
        let mut chain = parent.chn.clone();
        chain.push(parent.jti.clone());

        let claims = Self {
            iss: parent.sub.clone(),
            sub,
            aud: parent.aud.clone(),
            iat,
            exp,
            nbf: Some(iat),
            jti: uuid::Uuid::new_v4().to_string(),
            cap: capabilities,
            chn: chain,
            cel: parent.effective_ceiling(),
            pur: parent.pur.clone(),
            ctx: parent.ctx.clone(),
        };
        claims.validate_basic()?;
        claims.validate_redelegation_from(parent)?;
        Ok(claims)
    }

    pub fn effective_ceiling(&self) -> Vec<AgentCapability> {
        if self.cel.is_empty() {
            self.cap.clone()
        } else {
            self.cel.clone()
        }
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
            let ok = is_capability_subset(&self.cap, &self.cel);
            if !ok {
                return Err(Error::InvalidClaims(
                    "capabilities exceed ceiling".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_redelegation_from(&self, parent: &DelegationClaims) -> Result<()> {
        if self.iss != parent.sub {
            return Err(Error::DelegationChainViolation(
                "child issuer must match parent subject".to_string(),
            ));
        }
        if self.exp > parent.exp {
            return Err(Error::DelegationChainViolation(
                "child expiration cannot exceed parent expiration".to_string(),
            ));
        }
        if self.aud != parent.aud {
            return Err(Error::DelegationChainViolation(
                "child audience must match parent audience".to_string(),
            ));
        }

        let mut expected_chain = parent.chn.clone();
        expected_chain.push(parent.jti.clone());
        if self.chn != expected_chain {
            return Err(Error::DelegationChainViolation(
                "child chain must append parent token id".to_string(),
            ));
        }

        let parent_ceiling = parent.effective_ceiling();
        if !is_capability_subset(&self.cap, &parent_ceiling) {
            return Err(Error::DelegationChainViolation(
                "child capabilities exceed parent ceiling".to_string(),
            ));
        }
        if !self.cel.is_empty() && !is_capability_subset(&self.cel, &parent_ceiling) {
            return Err(Error::DelegationChainViolation(
                "child ceiling exceeds parent ceiling".to_string(),
            ));
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

    pub fn verify_and_validate(
        &self,
        issuer_public_key: &PublicKey,
        now_unix: i64,
        revocations: &dyn RevocationStore,
        expected_audience: &str,
        expected_subject: Option<&AgentId>,
    ) -> Result<()> {
        self.claims.validate_basic()?;
        self.validate_audience(expected_audience)?;
        self.validate_timebounds(now_unix)?;
        if let Some(expected_subject) = expected_subject {
            self.validate_subject(expected_subject)?;
        }
        if revocations.is_revoked(&self.claims.jti, now_unix) {
            return Err(Error::Revoked);
        }
        if !self.verify(issuer_public_key)? {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_redelegated_from(
        &self,
        parent: &SignedDelegationToken,
        issuer_public_key: &PublicKey,
        parent_issuer_public_key: &PublicKey,
        now_unix: i64,
        revocations: &dyn RevocationStore,
    ) -> Result<()> {
        parent.verify_and_validate(
            parent_issuer_public_key,
            now_unix,
            revocations,
            DELEGATION_AUDIENCE,
            Some(&self.claims.iss),
        )?;
        self.verify_and_validate(
            issuer_public_key,
            now_unix,
            revocations,
            DELEGATION_AUDIENCE,
            None,
        )?;
        self.claims.validate_redelegation_from(&parent.claims)?;
        Ok(())
    }
}

fn canonical_claims_json(claims: &DelegationClaims) -> Result<String> {
    let value = serde_json::to_value(claims)?;
    Ok(canonicalize(&value)?)
}

fn is_capability_subset(lhs: &[AgentCapability], rhs_superset: &[AgentCapability]) -> bool {
    lhs.iter()
        .all(|cap| rhs_superset.iter().any(|sup| sup == cap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AgentCapability;

    use crate::revocation::InMemoryRevocationStore;

    fn make_agent(name: &str) -> AgentId {
        AgentId::new(name).unwrap()
    }

    fn make_claims(iat: i64, exp: i64) -> DelegationClaims {
        DelegationClaims::new(
            make_agent("agent:issuer"),
            make_agent("agent:subject"),
            iat,
            exp,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();
        assert!(token.verify(&kp.public_key()).unwrap());
    }

    #[test]
    fn sign_with_public_key_and_verify_embedded() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign_with_public_key(claims, &kp).unwrap();
        assert!(token.public_key.is_some());
        assert!(token.verify_embedded().unwrap());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let kp = Keypair::generate();
        let wrong_kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();
        assert!(!token.verify(&wrong_kp.public_key()).unwrap());
    }

    #[test]
    fn verify_embedded_missing_key_errors() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();
        assert!(token.public_key.is_none());
        let result = token.verify_embedded();
        assert!(result.is_err());
    }

    #[test]
    fn token_verifies_and_revocation_is_enforced() {
        let now = 1_700_000_000;
        let revocations = InMemoryRevocationStore::default();

        let issuer = AgentId::new("agent:issuer").unwrap();
        let subject = AgentId::new("agent:subject").unwrap();
        let issuer_key = Keypair::generate();

        let claims = DelegationClaims::new(
            issuer,
            subject.clone(),
            now,
            now + 60,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();
        let token = SignedDelegationToken::sign(claims, &issuer_key).unwrap();

        token
            .verify_and_validate(
                &issuer_key.public_key(),
                now,
                &revocations,
                DELEGATION_AUDIENCE,
                Some(&subject),
            )
            .unwrap();

        revocations.revoke(token.claims.jti.clone(), None);
        let err = token
            .verify_and_validate(
                &issuer_key.public_key(),
                now,
                &revocations,
                DELEGATION_AUDIENCE,
                Some(&subject),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("revoked"));
    }

    #[test]
    fn redelegation_chain_validates() {
        let now = 1_700_000_000;
        let revocations = InMemoryRevocationStore::default();

        let root = AgentId::new("agent:root").unwrap();
        let mid = AgentId::new("agent:mid").unwrap();
        let leaf = AgentId::new("agent:leaf").unwrap();

        let root_key = Keypair::generate();
        let mid_key = Keypair::generate();

        let parent_claims = DelegationClaims::new(
            root,
            mid.clone(),
            now,
            now + 120,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();
        let parent = SignedDelegationToken::sign(parent_claims, &root_key).unwrap();

        let child_claims = DelegationClaims::redelegate(
            &parent.claims,
            leaf,
            now,
            now + 60,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();
        let child = SignedDelegationToken::sign(child_claims, &mid_key).unwrap();

        child
            .verify_redelegated_from(
                &parent,
                &mid_key.public_key(),
                &root_key.public_key(),
                now,
                &revocations,
            )
            .unwrap();
    }

    #[test]
    fn redelegation_rejects_capability_escalation() {
        let now = 1_700_000_000;
        let parent = DelegationClaims::new(
            AgentId::new("agent:root").unwrap(),
            AgentId::new("agent:mid").unwrap(),
            now,
            now + 120,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();

        let err = DelegationClaims::redelegate(
            &parent,
            AgentId::new("agent:leaf").unwrap(),
            now,
            now + 60,
            vec![AgentCapability::AgentAdmin],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("capabilities exceed ceiling"));
    }

    #[test]
    fn attenuation_capabilities_must_be_subset_of_ceiling() {
        let iss = make_agent("agent:iss");
        let sub = make_agent("agent:sub");

        let mut claims = DelegationClaims::new(
            iss,
            sub,
            1_000_000,
            2_000_000,
            vec![AgentCapability::DeployApproval, AgentCapability::AgentAdmin],
        )
        .unwrap();

        // Set ceiling to only DeployApproval -- AgentAdmin exceeds it.
        claims.cel = vec![AgentCapability::DeployApproval];
        let result = claims.validate_basic();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceed ceiling"));
    }

    #[test]
    fn attenuation_capabilities_within_ceiling_ok() {
        let iss = make_agent("agent:iss");
        let sub = make_agent("agent:sub");

        let mut claims = DelegationClaims::new(
            iss,
            sub,
            1_000_000,
            2_000_000,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();

        claims.cel = vec![AgentCapability::DeployApproval, AgentCapability::AgentAdmin];
        claims.validate_basic().unwrap();
    }

    #[test]
    fn expired_token_rejected() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 1_500_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();

        // now = 2_000_000 which is past exp = 1_500_000
        let result = token.validate_timebounds(2_000_000);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Expired));
    }

    #[test]
    fn not_yet_valid_token_rejected() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();

        // nbf defaults to iat = 1_000_000, now = 500_000 is before nbf
        let result = token.validate_timebounds(500_000);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NotYetValid));
    }

    #[test]
    fn valid_timebounds_accepted() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();

        token.validate_timebounds(1_500_000).unwrap();
    }

    #[test]
    fn audience_validation() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();

        token.validate_audience(DELEGATION_AUDIENCE).unwrap();

        let result = token.validate_audience("wrong:audience");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AudienceMismatch));
    }

    #[test]
    fn subject_validation() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign(claims, &kp).unwrap();

        let expected = make_agent("agent:subject");
        token.validate_subject(&expected).unwrap();

        let wrong = make_agent("agent:other");
        let result = token.validate_subject(&wrong);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::SubjectMismatch));
    }

    #[test]
    fn claims_reject_empty_capabilities() {
        let result = DelegationClaims::new(
            make_agent("a"),
            make_agent("b"),
            1_000_000,
            2_000_000,
            vec![],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("capabilities are empty"));
    }

    #[test]
    fn claims_reject_exp_before_iat() {
        let result = DelegationClaims::new(
            make_agent("a"),
            make_agent("b"),
            2_000_000,
            1_000_000,
            vec![AgentCapability::DeployApproval],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exp must be > iat"));
    }

    #[test]
    fn serialization_roundtrip() {
        let kp = Keypair::generate();
        let claims = make_claims(1_000_000, 2_000_000);
        let token = SignedDelegationToken::sign_with_public_key(claims, &kp).unwrap();

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: SignedDelegationToken = serde_json::from_str(&json).unwrap();

        assert!(deserialized.verify_embedded().unwrap());
        assert_eq!(deserialized.claims.iss.as_str(), "agent:issuer");
        assert_eq!(deserialized.claims.sub.as_str(), "agent:subject");
    }
}
