use sqlx::executor::Executor;
use sqlx::row::Row;
use sqlx_postgres::Postgres;
use uuid::Uuid;

use crate::error::ApiError;

const RESOLVE_PRINCIPAL_SQL: &str = r#"WITH exact_id AS (
       SELECT id, stable_ref, lifecycle_state, public_key
       FROM principals
       WHERE tenant_id = $1
         AND id = $2
   ),
   stable_matches AS (
       SELECT id, stable_ref, lifecycle_state, public_key
       FROM principals
       WHERE tenant_id = $1
         AND stable_ref = $3
   ),
   selected AS (
       SELECT id,
              stable_ref,
              lifecycle_state,
              public_key,
              EXISTS(
                  SELECT 1
                  FROM stable_matches
                  WHERE id <> exact_id.id
              ) AS ambiguous,
              0 AS precedence
       FROM exact_id
       UNION ALL
       SELECT stable_matches.id,
              stable_matches.stable_ref,
              stable_matches.lifecycle_state,
              stable_matches.public_key,
              (SELECT COUNT(*) FROM stable_matches) > 1 AS ambiguous,
              1 AS precedence
       FROM stable_matches
       WHERE NOT EXISTS (SELECT 1 FROM exact_id)
   )
   SELECT id, stable_ref, lifecycle_state, public_key, ambiguous
   FROM selected
   ORDER BY precedence ASC, id ASC
   LIMIT 1"#;

#[derive(Debug, Clone)]
pub struct ResolvedPrincipal {
    pub id: Uuid,
    pub stable_ref: String,
    pub lifecycle_state: String,
    pub public_key: Option<String>,
}

impl ResolvedPrincipal {
    pub fn aliases(&self) -> Vec<String> {
        let mut aliases = vec![self.id.to_string()];
        if self.stable_ref != aliases[0] {
            aliases.push(self.stable_ref.clone());
        }
        aliases
    }
}

pub fn delegation_authority_blocked(lifecycle_state: &str) -> bool {
    matches!(lifecycle_state, "quarantined" | "revoked")
}

pub fn ensure_delegation_allowed(
    principal: &ResolvedPrincipal,
    purpose: &str,
) -> Result<(), ApiError> {
    if delegation_authority_blocked(&principal.lifecycle_state) {
        return Err(ApiError::Forbidden);
    }

    if principal.public_key.is_none() && purpose == "issuer" {
        return Err(ApiError::BadRequest(format!(
            "registered principal '{}' is missing a public key",
            principal.stable_ref
        )));
    }

    Ok(())
}

pub async fn resolve_principal_identifier_optional<'e, E>(
    executor: E,
    tenant_id: Uuid,
    identifier: &str,
) -> Result<Option<ResolvedPrincipal>, ApiError>
where
    E: Executor<'e, Database = Postgres>,
{
    let parsed_identifier = Uuid::parse_str(identifier).ok();
    let row = sqlx::query::query(RESOLVE_PRINCIPAL_SQL)
        .bind(tenant_id)
        .bind(parsed_identifier)
        .bind(identifier)
        .fetch_optional(executor)
        .await
        .map_err(ApiError::Database)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let ambiguous: bool = row.try_get("ambiguous").map_err(ApiError::Database)?;
    if ambiguous {
        return Err(ApiError::Conflict(format!(
            "principal identifier '{}' is ambiguous within tenant {}",
            identifier, tenant_id
        )));
    }

    Ok(Some(ResolvedPrincipal {
        id: row.try_get("id").map_err(ApiError::Database)?,
        stable_ref: row.try_get("stable_ref").map_err(ApiError::Database)?,
        lifecycle_state: row.try_get("lifecycle_state").map_err(ApiError::Database)?,
        public_key: row.try_get("public_key").map_err(ApiError::Database)?,
    }))
}

pub async fn resolve_principal_identifier<'e, E>(
    executor: E,
    tenant_id: Uuid,
    identifier: &str,
) -> Result<ResolvedPrincipal, ApiError>
where
    E: Executor<'e, Database = Postgres>,
{
    resolve_principal_identifier_optional(executor, tenant_id, identifier)
        .await?
        .ok_or(ApiError::NotFound)
}
