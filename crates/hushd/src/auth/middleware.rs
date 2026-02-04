//! Authentication middleware for axum

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::state::AppState;

use super::{ApiKey, Scope};

/// Type alias for scope layer future
type ScopeLayerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>;

#[derive(Clone, Debug)]
pub enum AuthenticatedActor {
    ApiKey(ApiKey),
    User(clawdstrike::IdentityPrincipal),
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(req: &Request<Body>) -> Option<&str> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())?;

    // Support both "Bearer" and "bearer" (case insensitive)
    if auth_header.len() > 7 {
        let prefix = &auth_header[..7];
        if prefix.eq_ignore_ascii_case("Bearer ") {
            return Some(&auth_header[7..]);
        }
    }

    None
}

/// Middleware that validates bearer token and adds ApiKey to extensions
///
/// Returns 401 Unauthorized if:
/// - Auth is enabled and no Authorization header
/// - Auth is enabled and invalid/expired token
///
/// If auth is disabled in config, requests pass through without validation.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth if disabled in config
    if !state.auth_enabled() {
        return Ok(next.run(req).await);
    }

    // Extract bearer token
    let token = extract_bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;

    // Try OIDC validation first when the token looks like a JWT and OIDC is configured.
    if looks_like_jwt(token) {
        if let Some(oidc) = state.oidc.as_ref() {
            match oidc.validate_token(token).await {
                Ok(principal) => {
                    req.extensions_mut()
                        .insert(AuthenticatedActor::User(principal));
                    return Ok(next.run(req).await);
                }
                Err(err) => {
                    tracing::debug!(error = %err, "OIDC validation failed; falling back to API key");
                }
            }
        }
    }

    // Validate token against API key store
    let key = state.auth_store.validate_key(token).await.map_err(|e| {
        tracing::debug!(error = %e, "API key validation failed");
        StatusCode::UNAUTHORIZED
    })?;

    // Store validated actor in request extensions for downstream handlers
    req.extensions_mut().insert(AuthenticatedActor::ApiKey(key));

    Ok(next.run(req).await)
}

/// Middleware that checks if authenticated user has required scope
///
/// Returns 403 Forbidden if key doesn't have the required scope.
/// Returns 401 Unauthorized if no authenticated key in extensions.
///
/// Must be used after `require_auth` middleware.
pub async fn require_scope(
    scope: Scope,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get the authenticated actor from extensions.
    //
    // Note: when auth is disabled in config, `require_auth` will bypass validation and won't add
    // `AuthenticatedActor`. In that case, scope checks are a no-op.
    let Some(actor) = req.extensions().get::<AuthenticatedActor>() else {
        return Ok(next.run(req).await);
    };

    match actor {
        AuthenticatedActor::ApiKey(key) => {
            if !key.has_scope(scope) {
                tracing::debug!(
                    key_name = %key.name,
                    required_scope = %scope,
                    "Insufficient scope"
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
        AuthenticatedActor::User(principal) => {
            // Temporary scope mapping (replaced by RBAC in Phase 4).
            match scope {
                Scope::Check => {}
                Scope::Read => {
                    let ok = principal.roles.iter().any(|r| {
                        r == "policy-viewer"
                            || r == "audit-viewer"
                            || r == "policy-admin"
                            || r == "super-admin"
                    });
                    if !ok {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
                Scope::Admin => {
                    let ok = principal
                        .roles
                        .iter()
                        .any(|r| r == "policy-admin" || r == "super-admin");
                    if !ok {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
                Scope::All => {}
            }
        }
    }

    Ok(next.run(req).await)
}

/// Create a closure for scope checking that can be used with middleware::from_fn
pub fn scope_layer(
    scope: Scope,
) -> impl Fn(Request<Body>, Next) -> ScopeLayerFuture + Clone + Send + 'static {
    move |req, next| {
        let scope = scope;
        Box::pin(async move { require_scope(scope, req, next).await })
    }
}

fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(_), Some(_), Some(_), None)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    fn make_request_with_auth(auth_value: &str) -> Request<Body> {
        Request::builder()
            .header(header::AUTHORIZATION, auth_value)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request_without_auth() -> Request<Body> {
        Request::builder().body(Body::empty()).unwrap()
    }

    #[test]
    fn test_extract_bearer_token_valid() {
        let req = make_request_with_auth("Bearer my-api-key");
        assert_eq!(extract_bearer_token(&req), Some("my-api-key"));
    }

    #[test]
    fn test_extract_bearer_token_lowercase() {
        let req = make_request_with_auth("bearer my-api-key");
        assert_eq!(extract_bearer_token(&req), Some("my-api-key"));
    }

    #[test]
    fn test_extract_bearer_token_mixed_case() {
        let req = make_request_with_auth("BEARER my-api-key");
        assert_eq!(extract_bearer_token(&req), Some("my-api-key"));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let req = make_request_without_auth();
        assert_eq!(extract_bearer_token(&req), None);
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        let req = make_request_with_auth("Basic dXNlcjpwYXNz");
        assert_eq!(extract_bearer_token(&req), None);
    }

    #[test]
    fn test_extract_bearer_token_no_space() {
        let req = make_request_with_auth("Bearermy-api-key");
        assert_eq!(extract_bearer_token(&req), None);
    }
}
