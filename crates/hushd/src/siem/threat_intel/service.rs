use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use tokio::sync::RwLock;

use crate::siem::threat_intel::config::ThreatIntelConfig;
use crate::siem::threat_intel::stix::{IndicatorValue, ParsedIndicator};
use crate::siem::threat_intel::taxii::TaxiiClient;

#[derive(Clone, Debug, Default)]
pub struct ThreatIntelState {
    pub updated_at: Option<DateTime<Utc>>,
    pub domains: HashMap<String, DateTime<Utc>>,
    pub ips: HashMap<IpAddr, DateTime<Utc>>,
    pub file_names: HashMap<String, DateTime<Utc>>,
    pub file_sha256: HashMap<String, DateTime<Utc>>,
}

impl ThreatIntelState {
    pub fn is_domain_blocked(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        if host.is_empty() {
            return false;
        }

        // Exact match
        if self.domains.get(&host).is_some_and(|exp| *exp > Utc::now()) {
            return true;
        }

        // Subdomain match
        let mut parts = host.split('.').collect::<Vec<_>>();
        while parts.len() > 2 {
            parts.remove(0);
            let candidate = parts.join(".");
            if self
                .domains
                .get(&candidate)
                .is_some_and(|exp| *exp > Utc::now())
            {
                return true;
            }
        }

        false
    }

    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        self.ips.get(&ip).is_some_and(|exp| *exp > Utc::now())
    }

    pub fn is_file_name_blocked(&self, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        self.file_names
            .get(name)
            .is_some_and(|exp| *exp > Utc::now())
    }

    pub fn is_file_sha256_blocked(&self, sha256_hex: &str) -> bool {
        let v = sha256_hex.trim().to_lowercase();
        if v.is_empty() {
            return false;
        }
        self.file_sha256
            .get(&v)
            .is_some_and(|exp| *exp > Utc::now())
    }
}

#[derive(Clone)]
pub struct ThreatIntelService {
    config: ThreatIntelConfig,
    state: Arc<RwLock<ThreatIntelState>>,
}

impl ThreatIntelService {
    pub fn new(config: ThreatIntelConfig, state: Arc<RwLock<ThreatIntelState>>) -> Self {
        Self { config, state }
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if !self.config.enabled || self.config.servers.is_empty() {
                return;
            }

            // Restore cache (best effort).
            if self.config.cache.persistent {
                if let Some(path) = &self.config.cache.path {
                    if let Ok(snapshot) = load_snapshot(path).await {
                        let mut s = self.state.write().await;
                        s.updated_at = snapshot.updated_at;
                        s.domains = snapshot.domains;
                        s.ips = snapshot.ips;
                        s.file_names = snapshot.file_names;
                        s.file_sha256 = snapshot.file_sha256;
                        tracing::info!(
                            domains = s.domains.len(),
                            ips = s.ips.len(),
                            file_names = s.file_names.len(),
                            file_sha256 = s.file_sha256.len(),
                            "Loaded threat intel cache"
                        );
                    }
                }
            }

            let mut ticker = tokio::time::interval(Duration::from_secs(
                60 * self.config.feed.interval_minutes.max(1),
            ));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            // Track incremental polling cursor per server.
            let mut added_after: HashMap<String, String> = HashMap::new();
            if let Some(v) = &self.config.feed.added_after {
                for server in &self.config.servers {
                    added_after.insert(server.collection_id.clone(), v.clone());
                }
            }

            loop {
                ticker.tick().await;
                let now = Utc::now();
                for server in &self.config.servers {
                    let client = match TaxiiClient::new(server.clone()) {
                        Ok(c) => c,
                        Err(err) => {
                            tracing::warn!(error = %err, "Failed to create TAXII client");
                            continue;
                        }
                    };

                    let cursor = added_after.get(&server.collection_id).map(|s| s.as_str());
                    let objects = match client
                        .fetch_objects(cursor, self.config.feed.page_size)
                        .await
                    {
                        Ok(o) => o,
                        Err(err) => {
                            tracing::warn!(error = %err, collection = %server.collection_id, "TAXII fetch failed");
                            continue;
                        }
                    };

                    let indicators: Vec<ParsedIndicator> =
                        crate::siem::threat_intel::stix::parse_indicators(
                            &objects,
                            self.config.feed.min_confidence,
                        );

                    if indicators.is_empty() {
                        // Still advance the cursor to avoid refetching.
                        added_after.insert(
                            server.collection_id.clone(),
                            now.to_rfc3339_opts(SecondsFormat::Secs, true),
                        );
                        continue;
                    }

                    let expires_at =
                        now + chrono::Duration::hours(self.config.feed.cache_ttl_hours as i64);

                    let mut state = self.state.write().await;

                    for ind in indicators {
                        match ind.value {
                            IndicatorValue::Domain(domain) => {
                                let d = domain.trim().trim_end_matches('.').to_lowercase();
                                if d.is_empty() {
                                    continue;
                                }
                                if state.domains.len()
                                    + state.ips.len()
                                    + state.file_names.len()
                                    + state.file_sha256.len()
                                    >= self.config.cache.max_size
                                {
                                    continue;
                                }
                                state.domains.insert(d, expires_at);
                            }
                            IndicatorValue::Ip(ip) => {
                                if state.domains.len()
                                    + state.ips.len()
                                    + state.file_names.len()
                                    + state.file_sha256.len()
                                    >= self.config.cache.max_size
                                {
                                    continue;
                                }
                                state.ips.insert(ip, expires_at);
                            }
                            IndicatorValue::FileName(name) => {
                                let name = name.trim().to_string();
                                if name.is_empty() {
                                    continue;
                                }
                                if state.domains.len()
                                    + state.ips.len()
                                    + state.file_names.len()
                                    + state.file_sha256.len()
                                    >= self.config.cache.max_size
                                {
                                    continue;
                                }
                                state.file_names.insert(name, expires_at);
                            }
                            IndicatorValue::FileSha256(hash) => {
                                let hash = hash.trim().to_lowercase();
                                if hash.is_empty() {
                                    continue;
                                }
                                if state.domains.len()
                                    + state.ips.len()
                                    + state.file_names.len()
                                    + state.file_sha256.len()
                                    >= self.config.cache.max_size
                                {
                                    continue;
                                }
                                state.file_sha256.insert(hash, expires_at);
                            }
                        }
                    }

                    state.updated_at = Some(now);

                    // Persist snapshot (best effort).
                    if self.config.cache.persistent {
                        if let Some(path) = &self.config.cache.path {
                            let snap = ThreatIntelSnapshot {
                                updated_at: state.updated_at,
                                domains: state.domains.clone(),
                                ips: state.ips.clone(),
                                file_names: state.file_names.clone(),
                                file_sha256: state.file_sha256.clone(),
                            };
                            if let Err(err) = save_snapshot(path, &snap).await {
                                tracing::warn!(error = %err, "Failed to persist threat intel cache");
                            }
                        }
                    }

                    // Advance cursor.
                    added_after.insert(
                        server.collection_id.clone(),
                        now.to_rfc3339_opts(SecondsFormat::Secs, true),
                    );
                }
            }
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ThreatIntelSnapshot {
    updated_at: Option<DateTime<Utc>>,
    domains: HashMap<String, DateTime<Utc>>,
    ips: HashMap<IpAddr, DateTime<Utc>>,
    #[serde(default)]
    file_names: HashMap<String, DateTime<Utc>>,
    #[serde(default)]
    file_sha256: HashMap<String, DateTime<Utc>>,
}

async fn load_snapshot(path: &Path) -> anyhow::Result<ThreatIntelSnapshot> {
    let bytes = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn save_snapshot(path: &Path, snap: &ThreatIntelSnapshot) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(snap)?;
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}
