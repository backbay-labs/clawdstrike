//! OIDC token validation for trusted publishing from CI/CD environments.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::db::TrustedPublisher;
use crate::error::RegistryError;

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const GITLAB_ISSUER: &str = "https://gitlab.com";
const GITLAB_JWKS_URL: &str = "https://gitlab.com/-/jwks";
const JWKS_CACHE_DURATION_SECS: u64 = 3600;
const DEFAULT_OIDC_AUDIENCE: &str = "clawdstrike-registry";
const GITHUB_ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::RS256];
const GITLAB_ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::RS256];

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubClaims {
    pub sub: String,
    pub repository: String,
    pub repository_owner: String,
    #[serde(default)]
    pub workflow_ref: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    pub iss: String,
    #[serde(default)]
    pub aud: Option<OidcAudienceClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabClaims {
    pub sub: String,
    pub project_path: String,
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    pub iss: String,
    #[serde(default)]
    pub aud: Option<OidcAudienceClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OidcAudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl OidcAudienceClaim {
    fn matches_any_allowed(&self, allowed_audiences: &[String]) -> bool {
        match self {
            OidcAudienceClaim::Single(aud) => allowed_audiences.iter().any(|a| a == aud),
            OidcAudienceClaim::Multiple(values) => values
                .iter()
                .any(|aud| allowed_audiences.iter().any(|allowed| allowed == aud)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum OidcClaims {
    GitHub(GitHubClaims),
    GitLab(GitLabClaims),
}

impl OidcClaims {
    pub fn repository(&self) -> &str {
        match self {
            OidcClaims::GitHub(c) => &c.repository,
            OidcClaims::GitLab(c) => &c.project_path,
        }
    }

    pub fn provider(&self) -> &str {
        match self {
            OidcClaims::GitHub(_) => "github",
            OidcClaims::GitLab(_) => "gitlab",
        }
    }

    pub fn workflow(&self) -> Option<&str> {
        match self {
            OidcClaims::GitHub(c) => c.workflow_ref.as_deref(),
            OidcClaims::GitLab(c) => c.git_ref.as_deref(),
        }
    }

    pub fn environment(&self) -> Option<&str> {
        match self {
            OidcClaims::GitHub(c) => c.environment.as_deref(),
            OidcClaims::GitLab(c) => c.environment.as_deref(),
        }
    }

    #[allow(dead_code)]
    pub fn subject(&self) -> &str {
        match self {
            OidcClaims::GitHub(c) => &c.sub,
            OidcClaims::GitLab(c) => &c.sub,
        }
    }
}

// ---------------------------------------------------------------------------
// JWKS Cache
// ---------------------------------------------------------------------------

/// Per-provider cached JWKS entry.
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

/// JWKS cache keyed by provider name to avoid serving the wrong JWKS
/// when validating tokens from different providers (e.g. GitHub vs GitLab).
pub struct JwksCache {
    entries: HashMap<String, CachedJwks>,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get_fresh(&self, provider: &str) -> Option<JwkSet> {
        let is_valid = self
            .entries
            .get(provider)
            .map(|e| e.fetched_at.elapsed().as_secs() <= JWKS_CACHE_DURATION_SECS)
            .unwrap_or(false);

        if is_valid {
            self.entries.get(provider).map(|e| e.jwks.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, provider: &str, jwks: JwkSet) {
        self.entries.insert(
            provider.to_string(),
            CachedJwks {
                jwks,
                fetched_at: Instant::now(),
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

fn algorithm_allowed_for_provider(provider: &str, algorithm: Algorithm) -> bool {
    match provider.to_ascii_lowercase().as_str() {
        "github" => GITHUB_ALLOWED_ALGORITHMS.contains(&algorithm),
        "gitlab" => GITLAB_ALLOWED_ALGORITHMS.contains(&algorithm),
        _ => false,
    }
}

/// Validate an OIDC token from a CI/CD provider.
///
/// Uses the `provider` hint (`"github"` or `"gitlab"`) to select the correct
/// issuer and JWKS URL.  Falls back to inspecting the token's `iss` claim
/// when no explicit provider is given.
pub async fn validate_oidc_token(
    token: &str,
    provider: &str,
    jwks_cache: &Mutex<JwksCache>,
) -> Result<OidcClaims, RegistryError> {
    let (issuer, jwks_url) = match provider.to_ascii_lowercase().as_str() {
        "github" => (GITHUB_ISSUER, GITHUB_JWKS_URL),
        "gitlab" => (GITLAB_ISSUER, GITLAB_JWKS_URL),
        _ => {
            return Err(RegistryError::BadRequest(format!(
                "unsupported OIDC provider: {provider}"
            )));
        }
    };

    // Fetch or use cached JWKS (keyed by provider to avoid cross-provider confusion).
    let cached_jwks = {
        let cache = jwks_cache
            .lock()
            .map_err(|e| RegistryError::Internal(format!("jwks cache lock poisoned: {e}")))?;
        cache.get_fresh(provider)
    };
    let jwks = if let Some(jwks) = cached_jwks {
        jwks
    } else {
        let fetched = fetch_jwks(jwks_url).await?;
        let mut cache = jwks_cache
            .lock()
            .map_err(|e| RegistryError::Internal(format!("jwks cache lock poisoned: {e}")))?;
        if let Some(existing) = cache.get_fresh(provider) {
            existing
        } else {
            cache.insert(provider, fetched.clone());
            fetched
        }
    };

    // Decode the JWT header to find the key ID.
    let header = decode_header(token)
        .map_err(|e| RegistryError::Unauthorized(format!("invalid JWT header: {e}")))?;

    let kid = header
        .kid
        .as_ref()
        .ok_or_else(|| RegistryError::Unauthorized("JWT header missing kid".into()))?;

    // Find the matching key in the JWKS.
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid.as_str()))
        .ok_or_else(|| {
            RegistryError::Unauthorized(format!("no matching key found for kid '{kid}'"))
        })?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| RegistryError::Unauthorized(format!("failed to build decoding key: {e}")))?;

    let algorithm = header.alg;
    if !algorithm_allowed_for_provider(provider, algorithm) {
        return Err(RegistryError::Unauthorized(format!(
            "unsupported OIDC signing algorithm '{algorithm:?}' for provider '{provider}'"
        )));
    }
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    let allowed_audiences = configured_allowed_audiences(provider);
    // jsonwebtoken interprets array audiences as "token audiences must include
    // all configured audiences". We want alternatives (any configured value),
    // so validate aud manually after signature/issuer verification.
    validation.validate_aud = false;

    match provider.to_ascii_lowercase().as_str() {
        "github" => {
            let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
                .map_err(|e| RegistryError::Unauthorized(format!("JWT validation failed: {e}")))?;
            validate_token_audience(token_data.claims.aud.as_ref(), &allowed_audiences)?;
            Ok(OidcClaims::GitHub(token_data.claims))
        }
        "gitlab" => {
            let token_data = decode::<GitLabClaims>(token, &decoding_key, &validation)
                .map_err(|e| RegistryError::Unauthorized(format!("JWT validation failed: {e}")))?;
            validate_token_audience(token_data.claims.aud.as_ref(), &allowed_audiences)?;
            Ok(OidcClaims::GitLab(token_data.claims))
        }
        _ => Err(RegistryError::BadRequest(format!(
            "unsupported OIDC provider: {provider}"
        ))),
    }
}

fn validate_token_audience(
    audience: Option<&OidcAudienceClaim>,
    allowed_audiences: &[String],
) -> Result<(), RegistryError> {
    let aud = audience.ok_or_else(|| {
        RegistryError::Unauthorized("OIDC token missing required audience claim".into())
    })?;
    if aud.matches_any_allowed(allowed_audiences) {
        Ok(())
    } else {
        Err(RegistryError::Unauthorized(
            "OIDC token audience is not allowed for this registry".into(),
        ))
    }
}

fn configured_allowed_audiences(provider: &str) -> Vec<String> {
    let provider_env = format!(
        "CLAWDSTRIKE_OIDC_{}_AUDIENCES",
        provider.to_ascii_uppercase()
    );
    let raw = std::env::var(&provider_env)
        .ok()
        .or_else(|| std::env::var("CLAWDSTRIKE_OIDC_ALLOWED_AUDIENCES").ok())
        .unwrap_or_else(|| DEFAULT_OIDC_AUDIENCE.to_string());

    let parsed = parse_allowed_audiences(&raw);
    if parsed.is_empty() {
        vec![DEFAULT_OIDC_AUDIENCE.to_string()]
    } else {
        parsed
    }
}

fn parse_allowed_audiences(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Fetch JWKS from a remote URL.
async fn fetch_jwks(url: &str) -> Result<JwkSet, RegistryError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| RegistryError::Internal(format!("failed to fetch JWKS from {url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(RegistryError::Internal(format!(
            "JWKS endpoint returned HTTP {}",
            resp.status()
        )));
    }

    let jwks: JwkSet = resp
        .json()
        .await
        .map_err(|e| RegistryError::Internal(format!("failed to parse JWKS response: {e}")))?;

    Ok(jwks)
}

// ---------------------------------------------------------------------------
// Publisher matching
// ---------------------------------------------------------------------------

/// Match OIDC claims against a list of trusted publishers.
///
/// Returns the first matching publisher, or an error if none match.
pub fn match_trusted_publisher<'a>(
    claims: &OidcClaims,
    publishers: &'a [TrustedPublisher],
) -> Result<&'a TrustedPublisher, RegistryError> {
    for publisher in publishers {
        // Provider must match.
        if !publisher.provider.eq_ignore_ascii_case(claims.provider()) {
            continue;
        }

        // Repository must match (case-insensitive).
        if !publisher
            .repository
            .eq_ignore_ascii_case(claims.repository())
        {
            continue;
        }

        // If the publisher specifies a workflow/ref, it must match.
        //
        // Provider-specific behavior:
        // - GitHub: `workflow_ref` is "<path>@<ref>", so we compare the path portion and
        //   allow exact path or path-suffix matches at a boundary.
        // - GitLab: this claim is the git ref (branch/tag), so we require exact match.
        if let Some(ref required_workflow) = publisher.workflow {
            match claims.workflow() {
                Some(actual) => {
                    if !workflow_matches(claims, actual, required_workflow) {
                        continue;
                    }
                }
                None => continue,
            }
        }

        // If the publisher specifies an environment, it must match.
        if let Some(ref required_env) = publisher.environment {
            match claims.environment() {
                Some(actual) => {
                    if !actual.eq_ignore_ascii_case(required_env) {
                        continue;
                    }
                }
                None => continue,
            }
        }

        return Ok(publisher);
    }

    Err(RegistryError::Unauthorized(
        "no trusted publisher matches the OIDC token claims".into(),
    ))
}

fn workflow_matches(claims: &OidcClaims, actual: &str, required_workflow: &str) -> bool {
    match claims {
        OidcClaims::GitHub(_) => {
            let workflow_path = actual.split('@').next().unwrap_or(actual);
            workflow_path == required_workflow
                || workflow_path.ends_with(&format!("/{}", required_workflow))
        }
        OidcClaims::GitLab(_) => actual == required_workflow,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_github_claims(repo: &str, workflow: Option<&str>, env: Option<&str>) -> OidcClaims {
        OidcClaims::GitHub(GitHubClaims {
            sub: format!("repo:{repo}:ref:refs/heads/main"),
            repository: repo.to_string(),
            repository_owner: repo.split('/').next().unwrap_or("").to_string(),
            workflow_ref: workflow.map(String::from),
            environment: env.map(String::from),
            iss: GITHUB_ISSUER.to_string(),
            aud: Some(OidcAudienceClaim::Single(
                "clawdstrike-registry".to_string(),
            )),
        })
    }

    fn make_gitlab_claims(project: &str, git_ref: Option<&str>, env: Option<&str>) -> OidcClaims {
        OidcClaims::GitLab(GitLabClaims {
            sub: format!("project_path:{project}:ref_type:branch:ref:main"),
            project_path: project.to_string(),
            git_ref: git_ref.map(String::from),
            environment: env.map(String::from),
            iss: GITLAB_ISSUER.to_string(),
            aud: Some(OidcAudienceClaim::Single(
                "clawdstrike-registry".to_string(),
            )),
        })
    }

    fn make_publisher(
        provider: &str,
        repo: &str,
        workflow: Option<&str>,
        env: Option<&str>,
    ) -> TrustedPublisher {
        TrustedPublisher {
            id: 1,
            package_name: "test-pkg".to_string(),
            provider: provider.to_string(),
            repository: repo.to_string(),
            workflow: workflow.map(String::from),
            environment: env.map(String::from),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            created_by: "test".to_string(),
        }
    }

    #[test]
    fn match_github_repo_only() {
        let claims = make_github_claims("acme/my-guard", None, None);
        let publishers = [make_publisher("github", "acme/my-guard", None, None)];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn match_github_with_workflow() {
        let claims = make_github_claims(
            "acme/my-guard",
            Some("acme/my-guard/.github/workflows/release.yml@refs/heads/main"),
            None,
        );
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some("release.yml"),
            None,
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn match_github_with_environment() {
        let claims = make_github_claims("acme/my-guard", None, Some("production"));
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            None,
            Some("production"),
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn no_match_wrong_repo() {
        let claims = make_github_claims("other/repo", None, None);
        let publishers = [make_publisher("github", "acme/my-guard", None, None)];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn no_match_wrong_provider() {
        let claims = make_github_claims("acme/my-guard", None, None);
        let publishers = [make_publisher("gitlab", "acme/my-guard", None, None)];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn no_match_missing_workflow() {
        let claims = make_github_claims("acme/my-guard", None, None);
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some("release.yml"),
            None,
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn no_match_wrong_environment() {
        let claims = make_github_claims("acme/my-guard", None, Some("staging"));
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            None,
            Some("production"),
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn match_gitlab_repo() {
        let claims = make_gitlab_claims("acme/my-guard", None, None);
        let publishers = [make_publisher("gitlab", "acme/my-guard", None, None)];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn match_gitlab_with_exact_ref() {
        let claims = make_gitlab_claims("acme/my-guard", Some("main"), None);
        let publishers = [make_publisher(
            "gitlab",
            "acme/my-guard",
            Some("main"),
            None,
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn no_match_gitlab_ref_suffix_bypass() {
        let claims = make_gitlab_claims("acme/my-guard", Some("feature/main"), None);
        let publishers = [make_publisher(
            "gitlab",
            "acme/my-guard",
            Some("main"),
            None,
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn claims_accessors() {
        let gh = make_github_claims("acme/guard", Some("wf.yml"), Some("prod"));
        assert_eq!(gh.repository(), "acme/guard");
        assert_eq!(gh.provider(), "github");
        assert_eq!(gh.workflow(), Some("wf.yml"));
        assert_eq!(gh.environment(), Some("prod"));
        assert_eq!(gh.subject(), "repo:acme/guard:ref:refs/heads/main");

        let gl = make_gitlab_claims("acme/guard", Some("main"), Some("staging"));
        assert_eq!(gl.repository(), "acme/guard");
        assert_eq!(gl.provider(), "gitlab");
        assert_eq!(gl.workflow(), Some("main"));
        assert_eq!(gl.environment(), Some("staging"));
    }

    #[test]
    fn no_match_partial_workflow_name() {
        // "pre-release.yml" should NOT match a requirement of "release.yml"
        let claims = make_github_claims(
            "acme/my-guard",
            Some("acme/my-guard/.github/workflows/pre-release.yml@refs/heads/main"),
            None,
        );
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some("release.yml"),
            None,
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn match_full_workflow_path() {
        // Full path should match when specified
        let claims = make_github_claims(
            "acme/my-guard",
            Some("acme/my-guard/.github/workflows/release.yml@refs/heads/main"),
            None,
        );
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some(".github/workflows/release.yml"),
            None,
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn parse_allowed_audiences_splits_and_trims() {
        let parsed = super::parse_allowed_audiences("  clawdstrike-registry, ci-release , ,prod ");
        assert_eq!(
            parsed,
            vec![
                "clawdstrike-registry".to_string(),
                "ci-release".to_string(),
                "prod".to_string()
            ]
        );
    }

    #[test]
    fn audience_validation_treats_allowed_values_as_alternatives() {
        let allowed = vec!["clawdstrike-registry".to_string(), "ci-release".to_string()];
        let single = OidcAudienceClaim::Single("ci-release".to_string());
        let multiple = OidcAudienceClaim::Multiple(vec![
            "not-allowed".to_string(),
            "clawdstrike-registry".to_string(),
        ]);

        assert!(super::validate_token_audience(Some(&single), &allowed).is_ok());
        assert!(super::validate_token_audience(Some(&multiple), &allowed).is_ok());
    }

    #[test]
    fn audience_validation_rejects_missing_or_disallowed_audience() {
        let allowed = vec!["clawdstrike-registry".to_string()];
        let disallowed = OidcAudienceClaim::Single("other".to_string());

        assert!(super::validate_token_audience(None, &allowed).is_err());
        assert!(super::validate_token_audience(Some(&disallowed), &allowed).is_err());
    }

    #[test]
    fn provider_algorithm_allowlist_is_enforced() {
        assert!(super::algorithm_allowed_for_provider(
            "github",
            Algorithm::RS256
        ));
        assert!(super::algorithm_allowed_for_provider(
            "gitlab",
            Algorithm::RS256
        ));
        assert!(!super::algorithm_allowed_for_provider(
            "github",
            Algorithm::HS256
        ));
        assert!(!super::algorithm_allowed_for_provider(
            "gitlab",
            Algorithm::ES256
        ));
    }
}
