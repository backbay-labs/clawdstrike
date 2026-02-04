//! OIDC (JWT) validation and claim normalization.

use std::sync::Arc;
use std::time::{Duration, Instant};

use clawdstrike::{AuthMethod, IdentityPrincipal, IdentityProvider};
use dashmap::DashMap;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;

use crate::config::{OidcClaimMapping, OidcConfig};
use crate::control_db::ControlDb;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("invalid token: expected JWT format")]
    InvalidTokenFormat,
    #[error("invalid token header: {0}")]
    InvalidHeader(#[from] jsonwebtoken::errors::Error),
    #[error("unsupported token algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("oidc discovery failed: {0}")]
    DiscoveryFailed(String),
    #[error("jwks fetch failed: {0}")]
    JwksFetchFailed(String),
    #[error("no jwks keys available")]
    NoJwksKeys,
    #[error("token kid is required when multiple jwks keys are present")]
    MissingKid,
    #[error("jwks key not found for kid: {0}")]
    KeyNotFound(String),
    #[error("token decode failed: {0}")]
    DecodeFailed(String),
    #[error("missing required claim: {0}")]
    MissingRequiredClaim(String),
    #[error("missing or invalid claim: {0}")]
    InvalidClaim(String),
    #[error("token too old")]
    TokenTooOld,
    #[error("token replay detected")]
    ReplayDetected,
    #[error("replay protection enabled but no database is configured")]
    ReplayProtectionUnavailable,
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

#[derive(Clone)]
pub struct OidcValidator {
    issuer: String,
    audience: Vec<String>,
    jwks_uri: String,
    clock_tolerance_secs: u64,
    max_age_secs: Option<u64>,
    required_claims: Vec<String>,
    claim_mapping: OidcClaimMapping,
    jwks_cache_ttl_secs: u64,
    replay_protection: crate::config::OidcReplayProtectionConfig,
    replay_db: Option<Arc<ControlDb>>,
    http: Client,
    cache: Arc<DashMap<String, CachedJwks>>,
}

#[derive(Clone, Debug)]
struct CachedJwks {
    fetched_at: Instant,
    expires_at: Instant,
    jwks: Arc<JwkSet>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDoc {
    jwks_uri: String,
}

impl OidcValidator {
    pub async fn from_config(
        config: OidcConfig,
        replay_db: Option<Arc<ControlDb>>,
    ) -> Result<Self, OidcError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

        let jwks_uri = match config.jwks_uri.as_deref() {
            Some(uri) if !uri.trim().is_empty() => uri.to_string(),
            _ => discover_jwks_uri(&http, &config.issuer).await?,
        };

        Ok(Self {
            issuer: config.issuer,
            audience: config.audience,
            jwks_uri,
            clock_tolerance_secs: config.clock_tolerance_secs,
            max_age_secs: config.max_age_secs,
            required_claims: config.required_claims,
            claim_mapping: config.claim_mapping,
            jwks_cache_ttl_secs: config.jwks_cache_ttl_secs,
            replay_protection: config.replay_protection,
            replay_db,
            http,
            cache: Arc::new(DashMap::new()),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub async fn validate_token(&self, token: &str) -> Result<IdentityPrincipal, OidcError> {
        if !looks_like_jwt(token) {
            return Err(OidcError::InvalidTokenFormat);
        }

        let header = decode_header(token)?;

        let alg = header.alg;
        if alg != Algorithm::RS256 && alg != Algorithm::ES256 {
            return Err(OidcError::UnsupportedAlgorithm(alg));
        }

        let jwks = self.get_jwks().await?;
        let jwk = select_jwk(&jwks, header.kid.as_deref())?;

        let key = DecodingKey::from_jwk(jwk).map_err(|e| OidcError::DecodeFailed(e.to_string()))?;

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&self.audience);
        validation.leeway = self.clock_tolerance_secs;

        let token_data = decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| OidcError::DecodeFailed(e.to_string()))?;

        let claims = token_data.claims;
        self.validate_required_claims(&claims)?;
        self.validate_max_age(&claims)?;
        self.check_replay(&claims)?;

        let principal = self.claims_to_principal(&claims)?;
        Ok(principal)
    }

    fn check_replay(&self, claims: &serde_json::Value) -> Result<(), OidcError> {
        if !self.replay_protection.enabled {
            return Ok(());
        }

        let jti = claim_get(claims, "jti")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let jti = match jti {
            Some(jti) if !jti.is_empty() => jti,
            _ => {
                if self.replay_protection.require_jti {
                    return Err(OidcError::MissingRequiredClaim("jti".to_string()));
                }
                return Ok(());
            }
        };

        let Some(db) = self.replay_db.as_ref() else {
            // Replay protection was enabled but no DB was provided; fail closed.
            return Err(OidcError::ReplayProtectionUnavailable);
        };

        let expires_at = claim_get(claims, "exp")
            .and_then(claim_as_i64)
            .and_then(unix_seconds_to_rfc3339)
            .ok_or_else(|| OidcError::InvalidClaim("exp".to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();

        let conn = db.lock_conn();
        // Best-effort cleanup to keep the table bounded.
        let _ = conn.execute(
            "DELETE FROM oidc_jti WHERE expires_at <= ?1",
            rusqlite::params![now],
        );

        let changed = conn.execute(
            "INSERT OR IGNORE INTO oidc_jti (issuer, jti, expires_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![self.issuer, jti, expires_at],
        )?;

        if changed == 0 {
            return Err(OidcError::ReplayDetected);
        }

        Ok(())
    }

    fn validate_required_claims(&self, claims: &serde_json::Value) -> Result<(), OidcError> {
        for claim in &self.required_claims {
            let Some(value) = claim_get(claims, claim) else {
                return Err(OidcError::MissingRequiredClaim(claim.clone()));
            };
            if !claim_has_value(value) {
                return Err(OidcError::MissingRequiredClaim(claim.clone()));
            }
        }
        Ok(())
    }

    fn validate_max_age(&self, claims: &serde_json::Value) -> Result<(), OidcError> {
        let Some(max_age_secs) = self.max_age_secs else {
            return Ok(());
        };

        let now = chrono::Utc::now().timestamp();
        let issued_at = claim_get(claims, "iat")
            .and_then(claim_as_i64)
            .or_else(|| claim_get(claims, "auth_time").and_then(claim_as_i64))
            .ok_or_else(|| OidcError::InvalidClaim("iat/auth_time".to_string()))?;

        let age = now.saturating_sub(issued_at);
        if age > max_age_secs as i64 {
            return Err(OidcError::TokenTooOld);
        }

        Ok(())
    }

    fn claims_to_principal(
        &self,
        claims: &serde_json::Value,
    ) -> Result<IdentityPrincipal, OidcError> {
        let id = claim_get(claims, &self.claim_mapping.user_id)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| OidcError::InvalidClaim(self.claim_mapping.user_id.clone()))?;

        let email = claim_get(claims, &self.claim_mapping.email)
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let display_name = claim_get(claims, &self.claim_mapping.display_name)
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let organization_id = self
            .claim_mapping
            .organization_id
            .as_deref()
            .and_then(|k| claim_get(claims, k))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let roles = claim_get(claims, &self.claim_mapping.roles)
            .and_then(parse_string_list)
            .unwrap_or_default();

        let teams = self
            .claim_mapping
            .teams
            .as_deref()
            .and_then(|k| claim_get(claims, k))
            .and_then(parse_string_list)
            .unwrap_or_default();

        let email_verified = claim_get(claims, "email_verified").and_then(|v| v.as_bool());

        let authenticated_at = claim_get(claims, "auth_time")
            .and_then(claim_as_i64)
            .or_else(|| claim_get(claims, "iat").and_then(claim_as_i64))
            .and_then(unix_seconds_to_rfc3339)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        let expires_at = claim_get(claims, "exp")
            .and_then(claim_as_i64)
            .and_then(unix_seconds_to_rfc3339);

        let auth_method = claim_get(claims, "amr").and_then(map_amr_to_auth_method);

        let mut attributes = std::collections::HashMap::new();
        for key in &self.claim_mapping.additional_claims {
            if let Some(value) = claim_get(claims, key) {
                attributes.insert(key.clone(), value.clone());
            }
        }

        Ok(IdentityPrincipal {
            id,
            provider: IdentityProvider::Oidc,
            issuer: self.issuer.clone(),
            display_name,
            email,
            email_verified,
            organization_id,
            teams,
            roles,
            attributes,
            authenticated_at,
            auth_method,
            expires_at,
        })
    }

    async fn get_jwks(&self) -> Result<Arc<JwkSet>, OidcError> {
        let key = self.jwks_uri.clone();

        if let Some(entry) = self.cache.get(&key) {
            if Instant::now() <= entry.expires_at {
                return Ok(entry.jwks.clone());
            }
        }

        let fetched = fetch_jwks(&self.http, &self.jwks_uri).await;
        match fetched {
            Ok(jwks) => {
                let jwks = Arc::new(jwks);
                let now = Instant::now();
                let ttl = Duration::from_secs(self.jwks_cache_ttl_secs);
                self.cache.insert(
                    key,
                    CachedJwks {
                        fetched_at: now,
                        expires_at: now + ttl,
                        jwks: jwks.clone(),
                    },
                );
                Ok(jwks)
            }
            Err(err) => {
                // Fail closed only if we have no cached keys at all.
                if let Some(entry) = self.cache.get(&key) {
                    tracing::warn!(
                        issuer = %self.issuer,
                        jwks_uri = %self.jwks_uri,
                        error = %err,
                        fetched_at_ms_ago = entry.fetched_at.elapsed().as_millis(),
                        "JWKS refresh failed; using cached keys"
                    );
                    return Ok(entry.jwks.clone());
                }

                Err(OidcError::JwksFetchFailed(err))
            }
        }
    }
}

fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(_), Some(_), Some(_), None)
    )
}

fn claim_get<'a>(claims: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    let serde_json::Value::Object(obj) = claims else {
        return None;
    };
    obj.get(key)
}

fn claim_has_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(_) => true,
        serde_json::Value::Number(_) => true,
        serde_json::Value::String(s) => !s.trim().is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

fn claim_as_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().map(|v| v as i64))
        .or_else(|| value.as_str().and_then(|s| s.parse::<i64>().ok()))
}

fn unix_seconds_to_rfc3339(secs: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
}

fn parse_string_list(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Array(values) => {
            let out: Vec<String> = values
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            Some(out)
        }
        _ => None,
    }
}

fn map_amr_to_auth_method(value: &serde_json::Value) -> Option<AuthMethod> {
    let methods = match value {
        serde_json::Value::String(s) => vec![s.to_string()],
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    };

    if methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case("mfa") || m.eq_ignore_ascii_case("otp"))
    {
        return Some(AuthMethod::Mfa);
    }

    if methods.iter().any(|m| {
        m.eq_ignore_ascii_case("pwd")
            || m.eq_ignore_ascii_case("password")
            || m.eq_ignore_ascii_case("pass")
    }) {
        return Some(AuthMethod::Password);
    }

    if methods.iter().any(|m| m.eq_ignore_ascii_case("sso")) {
        return Some(AuthMethod::Sso);
    }

    None
}

fn select_jwk<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
) -> Result<&'a jsonwebtoken::jwk::Jwk, OidcError> {
    if jwks.keys.is_empty() {
        return Err(OidcError::NoJwksKeys);
    }

    if let Some(kid) = kid {
        for jwk in &jwks.keys {
            if jwk.common.key_id.as_deref() == Some(kid) {
                return Ok(jwk);
            }
        }
        return Err(OidcError::KeyNotFound(kid.to_string()));
    }

    if jwks.keys.len() == 1 {
        return Ok(&jwks.keys[0]);
    }

    Err(OidcError::MissingKid)
}

async fn discover_jwks_uri(http: &Client, issuer: &str) -> Result<String, OidcError> {
    let issuer = issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(OidcError::DiscoveryFailed(format!(
            "GET {} returned {}",
            url,
            resp.status()
        )));
    }

    let doc = resp
        .json::<OidcDiscoveryDoc>()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

    if doc.jwks_uri.trim().is_empty() {
        return Err(OidcError::DiscoveryFailed(
            "discovery jwks_uri is empty".to_string(),
        ));
    }

    Ok(doc.jwks_uri)
}

async fn fetch_jwks(http: &Client, jwks_uri: &str) -> Result<JwkSet, String> {
    let resp = http.get(jwks_uri).send().await.map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("GET {} returned {}", jwks_uri, resp.status()));
    }

    resp.json::<JwkSet>().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use base64::Engine as _;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tokio::net::TcpListener;

    const TEST_RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCw7murEwSZ5Jj
4jfkPp9DxmhhrV0+y6vo5J/wj8Y1J/k3jqsGr3g/Ab0F39CljVEm8QbzucYFxnCP
s8PLGoYG0pdLSRjYufUapOj8ld3olPuWeEkJwtv3Z7limVULpOBAKHT2CXHSvmUK
nujP4dZVfRhwaUOcebbg1QhUYOENiCAH5mX1e5Mpzfewu6GdHcBIMGg2mw9OOjQX
AFXEED2zMozcCOXRJMlBvH1yh2NwwAHiyqBYugau3WalHF8TZpcPK/1mJm7KRvbi
XRNibkEFH9VlRRIlpFCKYm3yDa4fUxd35PDc61Q5RV7XqOIcY0T6OIDTlP0aSevc
Cqqzb3WHAgMBAAECggEABHskALCmeBPu9SJayS28VKmyHsaHgIQyGoPMFD5SlUgr
/osR70TxPiMy707UykJOmC1FIi1nhhwohyiKfC1KNnT46yVYOirzyImmcffxaOz9
6YUvSldeio+Aielfi2A0kp/7qj98YW4PqBIQ5tuE0WcKkrzb7ok0W8blpVSsnjbg
c1q8iLJl4LHL+sGV+TkLy+OBBiEEX9iDr4TyWYYnjYwb0oqMrEiNXNtGE07VaiJ1
jMaM7/eTSh4mg/+pLIahotEV6h/q7MKCTclhgGrJzC+ENk4jpdnwww+OiRjppQHj
Cd/InN2ZjaJb4HM5DZfJVitv2sCalTnN+YBHwdjH8QKBgQDgr3oDOnhD1B+DhT3N
hJ5Lk47dsXeZm4rOpnKWsoG2vwBREK3ptFA4gdo/7M5AoYXTCZZOOcsoh2WAJv4z
GX8mYxtqHvTr6bHqZMT7IHWCaCmzvr4g6fbLWO4jzGxQM54rQPm0wb1mawEKgKQC
PAj5HNNpN3qbCqeif1v3n1h8EQKBgQDd6LRkL1ojxTnBzpUbH+FGMmpSIWoAtuuT
9COZd59EBrs9aP1X0nwrjD9ZEcdjVM8a+P4nMRjt/u3ucm3+5WwKBUZbNwlD1Jh9
fFFVGf7u8sKe3YEmQz8PI6Xgmj/tvO1PaBmzPPU1NxB88ySmsRihuXCiFwCpOlMM
1xQvI0dQFwKBgQCHWG0RQMltYnxRR5QBFyAbuplW5i57c3zcGtvv9zu4D7prGrcI
jru8LkyAMW/U8vegNqg6GwpMMbNszRBXS8aSIyVCeb9j1PR9k5ItDFJ86a4lPoNd
ZFJsD/fzzJJ6hX2D5LIGtqYW6eJIp1Ekn3FwTnLzcJ4EgxiUBFAsC+rLYQKBgQCs
1QhimyrGf16rnt0s4hiPlsaOLy4jXlR+yIBNkAiAcAm3G6VtmCdTt4jDM4Cq0av4
YwN3vNqgypO/ymn3Q/Jwn4kbk/LoXJVj7sZd1MBklLiWCQkEpw1fGjGgjCLMZAAk
f3y8x/ZnOvrhhnH+TiJUG10pMWc3ZpC2iHFVAVISgwKBgFh8b5wCET8koD+VvVUD
v/UJyvFkG1dbSogGbS2ZlI9NJhzZBk1HqkZKhdashG6UQzsEl9qYvylAcez+RecE
ya705nS2O2OGO8QGBAm54Px7lrswivApE9OHiH4lKO91T+s069VlZB+ml6NA87wc
Jrkx/3dCu23NhjN0NIZzYRXJ
-----END PRIVATE KEY-----"#;

    // Note: the private key above is intentionally test-only and not used for production.
    const TEST_JWKS_JSON: &str = r#"{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "test",
      "n": "wsO5rqxMEmeSY-I35D6fQ8ZoYa1dPsur6OSf8I_GNSf5N46rBq94PwG9Bd_QpY1RJvEG87nGBcZwj7PDyxqGBtKXS0kY2Ln1GqTo_JXd6JT7lnhJCcLb92e5YplVC6TgQCh09glx0r5lCp7oz-HWVX0YcGlDnHm24NUIVGDhDYggB-Zl9XuTKc33sLuhnR3ASDBoNpsPTjo0FwBVxBA9szKM3Ajl0STJQbx9codjcMAB4sqgWLoGrt1mpRxfE2aXDyv9ZiZuykb24l0TYm5BBR_VZUUSJaRQimJt8g2uH1MXd-Tw3OtUOUVe16jiHGNE-jiA05T9Gknr3Aqqs291hw",
      "e": "AQAB"
    }
  ]
}"#;

    async fn spawn_jwks_server() -> (String, tokio::sync::oneshot::Sender<()>) {
        let jwks: serde_json::Value = serde_json::from_str(TEST_JWKS_JSON).expect("jwks json");
        let app = Router::new().route("/jwks", get(move || async move { Json(jwks.clone()) }));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base = format!("http://{}", addr);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });

        (base, tx)
    }

    async fn make_validator(
        issuer: &str,
        jwks_uri: &str,
        replay: crate::config::OidcReplayProtectionConfig,
        db: Option<Arc<ControlDb>>,
    ) -> OidcValidator {
        let cfg = OidcConfig {
            issuer: issuer.to_string(),
            audience: vec!["test-aud".to_string()],
            jwks_uri: Some(jwks_uri.to_string()),
            clock_tolerance_secs: 0,
            max_age_secs: None,
            required_claims: vec![],
            claim_mapping: OidcClaimMapping::default(),
            jwks_cache_ttl_secs: 3600,
            replay_protection: replay,
        };

        OidcValidator::from_config(cfg, db)
            .await
            .expect("validator")
    }

    fn sign_token(
        issuer: &str,
        aud: &str,
        kid: &str,
        exp_offset_secs: i64,
        jti: Option<&str>,
    ) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = serde_json::json!({
            "iss": issuer,
            "aud": aud,
            "sub": "user-123",
            "exp": now + exp_offset_secs,
            "iat": now,
            "email": "user@example.com",
            "name": "Test User",
            "roles": ["policy-admin"],
        });
        if let Some(jti) = jti {
            claims.as_object_mut().unwrap().insert(
                "jti".to_string(),
                serde_json::Value::String(jti.to_string()),
            );
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("encoding key"),
        )
        .expect("token")
    }

    #[tokio::test]
    async fn oidc_validator_accepts_valid_token() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let validator = make_validator(
            &issuer,
            &jwks_uri,
            crate::config::OidcReplayProtectionConfig::default(),
            None,
        )
        .await;

        let token = sign_token(&issuer, "test-aud", "test", 300, None);
        let principal = validator.validate_token(&token).await.expect("valid");
        assert_eq!(principal.id, "user-123");
        assert_eq!(principal.issuer, issuer);
        assert!(principal.roles.iter().any(|r| r == "policy-admin"));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn oidc_validator_rejects_wrong_issuer() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let validator = make_validator(
            &issuer,
            &jwks_uri,
            crate::config::OidcReplayProtectionConfig::default(),
            None,
        )
        .await;

        let token = sign_token("http://wrong-issuer", "test-aud", "test", 300, None);
        assert!(validator.validate_token(&token).await.is_err());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn oidc_validator_rejects_wrong_audience() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let validator = make_validator(
            &issuer,
            &jwks_uri,
            crate::config::OidcReplayProtectionConfig::default(),
            None,
        )
        .await;

        let token = sign_token(&issuer, "wrong-aud", "test", 300, None);
        assert!(validator.validate_token(&token).await.is_err());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn oidc_validator_rejects_expired_token() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let validator = make_validator(
            &issuer,
            &jwks_uri,
            crate::config::OidcReplayProtectionConfig::default(),
            None,
        )
        .await;

        let token = sign_token(&issuer, "test-aud", "test", -10, None);
        assert!(validator.validate_token(&token).await.is_err());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn oidc_validator_rejects_alg_none() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let validator = make_validator(
            &issuer,
            &jwks_uri,
            crate::config::OidcReplayProtectionConfig::default(),
            None,
        )
        .await;

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let now = chrono::Utc::now().timestamp();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": issuer,
                "aud": "test-aud",
                "sub": "user-123",
                "exp": now + 300,
                "iat": now,
            })
            .to_string()
            .as_bytes(),
        );
        let token = format!("{header}.{payload}.");

        let err = validator.validate_token(&token).await.expect_err("invalid");
        assert!(matches!(
            err,
            OidcError::InvalidHeader(_) | OidcError::UnsupportedAlgorithm(_)
        ));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn oidc_validator_rejects_unknown_kid() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let validator = make_validator(
            &issuer,
            &jwks_uri,
            crate::config::OidcReplayProtectionConfig::default(),
            None,
        )
        .await;

        let token = sign_token(&issuer, "test-aud", "nope", 300, None);
        assert!(validator.validate_token(&token).await.is_err());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn oidc_replay_protection_rejects_reuse() {
        let (base, shutdown) = spawn_jwks_server().await;
        let issuer = base.clone();
        let jwks_uri = format!("{}/jwks", base);
        let db = Arc::new(ControlDb::in_memory().expect("db"));
        let replay = crate::config::OidcReplayProtectionConfig {
            enabled: true,
            require_jti: true,
        };
        let validator = make_validator(&issuer, &jwks_uri, replay, Some(db)).await;

        let token = sign_token(&issuer, "test-aud", "test", 300, Some("jti-123"));
        validator.validate_token(&token).await.expect("first ok");
        let err = validator.validate_token(&token).await.expect_err("replay");
        assert!(matches!(err, OidcError::ReplayDetected));

        let _ = shutdown.send(());
    }
}
