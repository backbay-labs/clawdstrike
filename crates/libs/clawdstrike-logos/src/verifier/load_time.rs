//! Load-time policy verification, receipt enrichment, and the result cache.
//!
//! Extracted from `verifier.rs`. Orchestrates verification when a policy is
//! loaded (resolving the parent for inheritance checks), enriches receipts with
//! the report metadata, and provides the LRU [`VerificationCache`] plus the
//! `install_clawdstrike_policy_load_verifier` hook wired up by the CLI, daemon,
//! workbench, and Python native module.

use super::*;

pub fn enrich_receipt(
    receipt: hush_core::receipt::Receipt,
    report: &VerificationReport,
) -> hush_core::receipt::Receipt {
    receipt.merge_metadata(report.to_receipt_metadata())
}

#[derive(Clone, Debug)]
pub struct LoadTimeVerificationResult {
    pub report: Option<VerificationReport>,
    pub cache_hit: bool,
    pub error: Option<String>,
}

/// Verify a policy at load time. Returns `Err` only in strict mode on failure.
pub fn verify_policy_at_load_time(
    policy: &clawdstrike::policy::Policy,
    cache: &VerificationCache,
) -> std::result::Result<LoadTimeVerificationResult, String> {
    verify_policy_at_load_time_inner::<LocalPolicyResolver>(policy, Some(policy), None, cache)
}

/// Verify a resolved policy at load time using the original source policy and
/// its source location so inheritance soundness can be checked against the
/// actual parent policy.
pub fn verify_policy_at_load_time_with_resolver<R: PolicyResolver>(
    effective_policy: &clawdstrike::policy::Policy,
    source_policy: &clawdstrike::policy::Policy,
    source_location: &PolicyLocation,
    resolver: &R,
    cache: &VerificationCache,
) -> std::result::Result<LoadTimeVerificationResult, String> {
    verify_policy_at_load_time_inner(
        effective_policy,
        Some(source_policy),
        Some((source_location, resolver)),
        cache,
    )
}

pub(crate) fn verify_policy_at_load_time_with_parent(
    effective_policy: &clawdstrike::policy::Policy,
    source_policy: &clawdstrike::policy::Policy,
    parent_policy: &clawdstrike::policy::Policy,
    cache: &VerificationCache,
) -> std::result::Result<LoadTimeVerificationResult, String> {
    let settings = effective_policy.settings.effective_verification();

    if !settings.enabled {
        return Ok(LoadTimeVerificationResult {
            report: None,
            cache_hit: false,
            error: None,
        });
    }

    let cache_key =
        load_time_cache_key_with_parent(effective_policy, Some(source_policy), Some(parent_policy));

    if settings.cache {
        if let Some(cached) = cache.get(&cache_key) {
            return finish_load_time_verification(settings.strict, cached, true, None);
        }
    }

    let report = load_time_verifier().verify_policy_with_parent_and_source(
        parent_policy,
        source_policy,
        effective_policy,
        AgentId::new("clawdstrike-agent"),
    );

    if settings.cache {
        cache.insert(cache_key, report.clone());
    }

    finish_load_time_verification(settings.strict, report, false, None)
}

pub(crate) fn verify_policy_at_load_time_inner<R: PolicyResolver>(
    effective_policy: &clawdstrike::policy::Policy,
    source_policy: Option<&clawdstrike::policy::Policy>,
    source_context: Option<(&PolicyLocation, &R)>,
    cache: &VerificationCache,
) -> std::result::Result<LoadTimeVerificationResult, String> {
    let settings = effective_policy.settings.effective_verification();

    if !settings.enabled {
        return Ok(LoadTimeVerificationResult {
            report: None,
            cache_hit: false,
            error: None,
        });
    }

    if let Some(source_policy) = source_policy {
        if let Some(parent_ref) = source_policy.extends.as_deref() {
            let (source_location, resolver) = match source_context {
                Some(context) => context,
                None => {
                    let message = format!(
                        "Policy verification could not check inheritance for parent {:?}: missing source location/resolver context",
                    parent_ref
                );
                    return finish_load_time_verification(
                        settings.strict,
                        inheritance_context_failure_report(effective_policy, message.clone()),
                        false,
                        Some(message),
                    );
                }
            };

            return match resolve_parent_policy_for_load_time(
                source_policy,
                source_location,
                resolver,
            ) {
                Ok(parent) => verify_policy_at_load_time_with_parent(
                    effective_policy,
                    source_policy,
                    &parent,
                    cache,
                ),
                Err(message) => finish_load_time_verification(
                    settings.strict,
                    inheritance_context_failure_report(effective_policy, message.clone()),
                    false,
                    Some(message),
                ),
            };
        }
    }

    let cache_key = load_time_cache_key(effective_policy, source_policy, source_context);

    if settings.cache {
        if let Some(cached) = cache.get(&cache_key) {
            if !cached.all_pass() {
                let msg = format!(
                    "Policy verification failed (cached): consistency={}, completeness={}, inheritance={}",
                    cached.consistency.outcome, cached.completeness.outcome, cached.inheritance.outcome,
                );

                if settings.strict {
                    return Err(msg);
                }

                tracing::warn!("{}", msg);

                return Ok(LoadTimeVerificationResult {
                    report: Some(cached),
                    cache_hit: true,
                    error: Some(msg),
                });
            }

            return Ok(LoadTimeVerificationResult {
                report: Some(cached),
                cache_hit: true,
                error: None,
            });
        }
    }

    let report =
        load_time_verifier().verify_policy(effective_policy, AgentId::new("clawdstrike-agent"));

    if settings.cache {
        cache.insert(cache_key, report.clone());
    }

    finish_load_time_verification(settings.strict, report, false, None)
}

pub(crate) fn resolve_parent_policy_for_load_time<R: PolicyResolver>(
    source_policy: &Policy,
    source_location: &PolicyLocation,
    resolver: &R,
) -> std::result::Result<Policy, String> {
    let extends_name = source_policy
        .extends
        .as_deref()
        .ok_or_else(|| "source policy does not declare extends".to_string())?;

    let resolved = resolver
        .resolve(extends_name, source_location)
        .map_err(|e| format!("failed to resolve parent policy {:?}: {}", extends_name, e))?;

    Policy::from_yaml_with_extends_location_resolver(&resolved.yaml, resolved.location, resolver)
        .map_err(|e| format!("failed to load parent policy {:?}: {}", extends_name, e))
}

pub(crate) fn inheritance_context_failure_report(
    effective_policy: &Policy,
    _message: String,
) -> VerificationReport {
    let verifier = load_time_verifier();
    let mut report = verifier.verify_policy(effective_policy, AgentId::new("clawdstrike-agent"));
    report.inheritance = InheritanceResult {
        outcome: CheckOutcome::Fail,
        weakened: Vec::new(),
    };
    if !report
        .properties_checked
        .iter()
        .any(|item| item == "inheritance")
    {
        report.properties_checked.push("inheritance".to_string());
    }
    report.attestation_level = compute_attestation_level(
        report.backend,
        &report.consistency,
        &report.completeness,
        &report.inheritance,
    );
    report
}

pub(crate) fn finish_load_time_verification(
    strict: bool,
    report: VerificationReport,
    cache_hit: bool,
    detailed_error: Option<String>,
) -> std::result::Result<LoadTimeVerificationResult, String> {
    if !report.all_pass() {
        let msg = detailed_error.unwrap_or_else(|| {
            format!(
                "Policy verification failed: consistency={}, completeness={}, inheritance={}",
                report.consistency.outcome, report.completeness.outcome, report.inheritance.outcome,
            )
        });

        if strict {
            return Err(msg);
        }

        tracing::warn!("{}", msg);

        return Ok(LoadTimeVerificationResult {
            report: Some(report),
            cache_hit,
            error: Some(msg),
        });
    }

    Ok(LoadTimeVerificationResult {
        report: Some(report),
        cache_hit,
        error: None,
    })
}

pub(crate) fn load_time_cache_key<R: PolicyResolver>(
    effective_policy: &Policy,
    source_policy: Option<&Policy>,
    source_context: Option<(&PolicyLocation, &R)>,
) -> String {
    let mut cache_input = effective_policy.to_yaml().unwrap_or_default();

    if let Some(source_policy) = source_policy {
        cache_input.push_str("\n---source-policy---\n");
        cache_input.push_str(&source_policy.to_yaml().unwrap_or_default());
    }

    if let Some((source_location, _)) = source_context {
        cache_input.push_str("\n---source-location---\n");
        cache_input.push_str(&describe_policy_location(source_location));
    }

    hush_core::hashing::sha256(cache_input.as_bytes()).to_hex()
}

pub(crate) fn load_time_cache_key_with_parent(
    effective_policy: &Policy,
    source_policy: Option<&Policy>,
    parent_policy: Option<&Policy>,
) -> String {
    let mut cache_input = effective_policy.to_yaml().unwrap_or_default();

    if let Some(source_policy) = source_policy {
        cache_input.push_str("\n---source-policy---\n");
        cache_input.push_str(&source_policy.to_yaml().unwrap_or_default());
    }

    if let Some(parent_policy) = parent_policy {
        cache_input.push_str("\n---parent-policy---\n");
        cache_input.push_str(&parent_policy.to_yaml().unwrap_or_default());
    }

    hush_core::hashing::sha256(cache_input.as_bytes()).to_hex()
}

pub(crate) fn describe_policy_location(location: &PolicyLocation) -> String {
    match location {
        PolicyLocation::None => "none".to_string(),
        PolicyLocation::File(path) => format!("file:{}", path.display()),
        PolicyLocation::Url(url) => format!("url:{url}"),
        PolicyLocation::Git { repo, commit, path } => {
            format!("git:{repo}@{commit}:{path}")
        }
        PolicyLocation::Ruleset { id } => format!("ruleset:{id}"),
        PolicyLocation::Package { name, version } => format!("package:{name}@{version}"),
    }
}

pub(crate) fn load_time_verifier() -> PolicyVerifier {
    #[cfg(feature = "z3")]
    {
        PolicyVerifier::with_z3()
    }

    #[cfg(not(feature = "z3"))]
    {
        PolicyVerifier::new()
    }
}

/// Thread-safe cache keyed by policy content hash.
#[derive(Debug)]
pub struct VerificationCache {
    state: std::sync::Mutex<VerificationCacheState>,
}

#[derive(Debug, Default)]
struct VerificationCacheState {
    entries: HashMap<String, VerificationReport>,
    insertion_order: std::collections::VecDeque<String>,
    max_entries: usize,
}

impl VerificationCache {
    const DEFAULT_MAX_ENTRIES: usize = 256;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity_limit(Self::DEFAULT_MAX_ENTRIES)
    }

    #[must_use]
    pub fn with_capacity_limit(max_entries: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(VerificationCacheState {
                entries: HashMap::new(),
                insertion_order: std::collections::VecDeque::new(),
                max_entries,
            }),
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<VerificationReport> {
        let guard = self.state.lock().ok()?;
        guard.get(key)
    }

    pub fn insert(&self, key: String, report: VerificationReport) {
        if let Ok(mut guard) = self.state.lock() {
            guard.insert(key, report);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map(|g| g.entries.len()).unwrap_or(0)
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new()
    }
}

static POLICY_LOAD_VERIFIER_REGISTRATION: Once = Once::new();
static POLICY_LOAD_VERIFICATION_CACHE: OnceLock<VerificationCache> = OnceLock::new();

pub(crate) fn registered_policy_load_cache() -> &'static VerificationCache {
    POLICY_LOAD_VERIFICATION_CACHE.get_or_init(VerificationCache::new)
}

pub fn install_clawdstrike_policy_load_verifier() {
    POLICY_LOAD_VERIFIER_REGISTRATION.call_once(|| {
        let _ = clawdstrike::policy::install_policy_load_verifier(|input| {
            let cache = registered_policy_load_cache();
            let result = match (&input.parent_policy, &input.source_policy) {
                (Some(parent), Some(source)) => verify_policy_at_load_time_with_parent(
                    &input.effective_policy,
                    source,
                    parent,
                    cache,
                ),
                _ => verify_policy_at_load_time(&input.effective_policy, cache),
            };

            result.map(|_| ()).map_err(clawdstrike::Error::ConfigError)
        });
    });
}

impl VerificationCacheState {
    fn get(&self, key: &str) -> Option<VerificationReport> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: String, report: VerificationReport) {
        if self.max_entries == 0 {
            return;
        }

        self.entries.insert(key.clone(), report);
        self.insertion_order.retain(|existing| existing != &key);
        self.insertion_order.push_back(key);

        while self.entries.len() > self.max_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}
