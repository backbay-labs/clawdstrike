use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::{AuthSource, AuthenticatedTenant};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub iss: String,
    pub aud: AudienceClaim,
    pub exp: i64,
    pub iat: i64,
}

fn decode_claims(
    token: &str,
    jwt_secret: &str,
    jwt_issuer: &str,
    jwt_audience: &str,
) -> Result<Claims, ApiError> {
    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[jwt_issuer]);
    validation.set_audience(&[jwt_audience]);
    let token_data = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(|_| ApiError::Unauthorized)?;
    Ok(token_data.claims)
}

/// Validate a JWT token and return the authenticated tenant context.
pub async fn validate_token(
    token: &str,
    state: &AppState,
) -> Result<AuthenticatedTenant, ApiError> {
    let claims = decode_claims(
        token,
        &state.config.jwt_secret,
        &state.config.jwt_issuer,
        &state.config.jwt_audience,
    )?;
    if claims.exp < Utc::now().timestamp() {
        return Err(ApiError::Unauthorized);
    }

    let row = sqlx::query::query(
        "SELECT id, slug, plan, agent_limit FROM tenants WHERE id = $1 AND status = 'active'",
    )
    .bind(claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::Unauthorized)?;

    Ok(AuthenticatedTenant {
        tenant_id: row.try_get("id").map_err(ApiError::Database)?,
        slug: row.try_get("slug").map_err(ApiError::Database)?,
        plan: row.try_get("plan").map_err(ApiError::Database)?,
        agent_limit: row.try_get("agent_limit").map_err(ApiError::Database)?,
        user_id: Some(claims.sub),
        api_key_id: None,
        role: claims.role,
        auth_source: AuthSource::Jwt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn encode_test_token(secret: &str, iss: &str, aud: &str, exp: i64) -> String {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role: "owner".to_string(),
            iss: iss.to_string(),
            aud: AudienceClaim::Single(aud.to_string()),
            exp,
            iat: now,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode jwt")
    }

    #[test]
    fn decode_claims_accepts_matching_issuer_and_audience() {
        let token = encode_test_token(
            "jwt-secret",
            "https://issuer.example",
            "control-api-clients",
            Utc::now().timestamp() + 60,
        );
        let claims = decode_claims(
            &token,
            "jwt-secret",
            "https://issuer.example",
            "control-api-clients",
        )
        .expect("claims should decode");
        assert_eq!(claims.iss, "https://issuer.example");
        assert_eq!(
            claims.aud,
            AudienceClaim::Single("control-api-clients".to_string())
        );
    }

    #[test]
    fn decode_claims_accepts_array_audience_containing_expected_value() {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role: "owner".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: AudienceClaim::Multiple(vec![
                "control-api-clients".to_string(),
                "other-audience".to_string(),
            ]),
            exp: now + 60,
            iat: now,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret("jwt-secret".as_bytes()),
        )
        .expect("encode jwt");

        let decoded = decode_claims(
            &token,
            "jwt-secret",
            "https://issuer.example",
            "control-api-clients",
        )
        .expect("claims should decode");
        assert_eq!(decoded.iss, "https://issuer.example");
        assert_eq!(
            decoded.aud,
            AudienceClaim::Multiple(vec![
                "control-api-clients".to_string(),
                "other-audience".to_string(),
            ])
        );
    }

    #[test]
    fn decode_claims_rejects_wrong_issuer() {
        let token = encode_test_token(
            "jwt-secret",
            "https://wrong-issuer.example",
            "control-api-clients",
            Utc::now().timestamp() + 60,
        );
        let err = decode_claims(
            &token,
            "jwt-secret",
            "https://issuer.example",
            "control-api-clients",
        )
        .expect_err("issuer mismatch should fail");
        assert!(matches!(err, ApiError::Unauthorized));
    }

    #[test]
    fn decode_claims_rejects_wrong_audience() {
        let token = encode_test_token(
            "jwt-secret",
            "https://issuer.example",
            "wrong-audience",
            Utc::now().timestamp() + 60,
        );
        let err = decode_claims(
            &token,
            "jwt-secret",
            "https://issuer.example",
            "control-api-clients",
        )
        .expect_err("audience mismatch should fail");
        assert!(matches!(err, ApiError::Unauthorized));
    }
}
