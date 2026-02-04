use std::time::Duration;

use reqwest::header;
use serde::Deserialize;
use url::Url;

use crate::siem::threat_intel::config::{TaxiiAuthConfig, TaxiiServerConfig};

#[derive(Clone)]
pub struct TaxiiClient {
    config: TaxiiServerConfig,
    client: reqwest::Client,
}

impl TaxiiClient {
    pub fn new(config: TaxiiServerConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { config, client })
    }

    pub async fn fetch_objects(
        &self,
        added_after: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut all: Vec<serde_json::Value> = Vec::new();
        let mut next: Option<String> = None;

        loop {
            let mut url = Url::parse(&self.objects_url())?;

            if let Some(added_after) = added_after {
                url.query_pairs_mut()
                    .append_pair("added_after", added_after);
            }
            if limit > 0 {
                url.query_pairs_mut()
                    .append_pair("limit", &limit.to_string());
            }
            if let Some(n) = &next {
                url.query_pairs_mut().append_pair("next", n);
            }

            let mut req = self.client.get(url);

            // Headers
            req = req.header(header::ACCEPT, "application/taxii+json;version=2.1");
            for (k, v) in &self.config.headers {
                req = req.header(k, v);
            }

            // Auth
            req = apply_auth(req, self.config.auth.as_ref());

            let resp = req.send().await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "TAXII objects fetch failed: status {} body {}",
                    status,
                    body
                ));
            }

            #[derive(Debug, Deserialize)]
            struct ObjectsResponse {
                #[serde(default)]
                objects: Vec<serde_json::Value>,
                #[serde(default)]
                more: Option<bool>,
                #[serde(default)]
                next: Option<String>,
            }

            let parsed: ObjectsResponse = resp.json().await?;
            all.extend(parsed.objects);

            let more = parsed.more.unwrap_or(false);
            if more {
                if let Some(n) = parsed.next {
                    next = Some(n);
                    continue;
                }
            }

            break;
        }

        Ok(all)
    }

    fn objects_url(&self) -> String {
        let base = self.config.url.trim_end_matches('/');
        let api_root = self.config.api_root.trim_matches('/');
        format!(
            "{base}/{api_root}/collections/{}/objects/",
            self.config.collection_id
        )
    }
}

fn apply_auth(
    mut req: reqwest::RequestBuilder,
    auth: Option<&TaxiiAuthConfig>,
) -> reqwest::RequestBuilder {
    let Some(auth) = auth else { return req };

    match auth.auth_type.as_str() {
        "basic" => {
            if let (Some(user), Some(pass)) = (&auth.username, &auth.password) {
                req = req.basic_auth(user, Some(pass));
            }
        }
        "api_key" => {
            if let Some(key) = &auth.api_key {
                req = req.header(header::AUTHORIZATION, format!("Bearer {key}"));
            }
        }
        _ => {}
    }

    req
}
