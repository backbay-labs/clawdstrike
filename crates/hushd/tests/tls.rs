//! TLS integration tests for hushd.
//!
//! This test spawns a daemon with a self-signed certificate and verifies `/health` over HTTPS.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Child, Command};
use std::time::Duration;

use hushd::config::{Config, RateLimitConfig, TlsConfig};

const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUcVLdLoHpKRd7rwmhPN6jX1XAsGUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIwNDA2NDc1OVoXDTI2MDIw
NTA2NDc1OVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwwPLa/rA7tRyXg52v5TErDBOjqREIf+FlNI+A4clv5O4
0sx7CH2pg4UC4zAUW5BFq6QsTJqRKtAhr0FjQ4oPv44gpFoRDxrQVIPq7i2/DspR
DU2xVkvtwMpiZzCTFnHKIbEo5YzYBXrNoOdMdsZ0CC0ulOvTTHF8OYmaVF6XNBav
F22tqB+L0v/iwNtYGTn/pCHn1u6jlnP3W9yzYn98+jtqc70HsGj3f+JzghaeFHfb
8nn/4Nk351RmJMi8U3qnmVOPo5oa27yOV5+3sTFNjXHo9KJ4vXq7YPO9swFpHeZI
xjKTM60C3ppI/2b/uOJ2YclzseGR0nsDfbqzu4aImQIDAQABo1MwUTAdBgNVHQ4E
FgQUo/kpqZOmZzUxnPF1WcTgJqY6izcwHwYDVR0jBBgwFoAUo/kpqZOmZzUxnPF1
WcTgJqY6izcwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAtQQ8
QApnW7c6RhX/e0QRMnhtWePPcb9PtFu33mOyyeKvVeXpyfp3mzh5tB1z7eIvbPyf
6FV7Y35OQZZi1QnAp4uOyu/ip/+5eDUKOS8qsIHr9UapD14Vd0YJj1IpyHwNBlFY
OP3JgVmoX7xOEmyW4ErEgeOov1FKlwQtP31o+obsTg/Xe+q0mNwjip0g0g6/L2J5
tG4gFWcP8jKySTlwM0e3xhtrnpwRnaFQSEHoSgsU5AECmbbvlSw+fk1aNFSuqQ3r
qM1HgbWV1N8U8ZyMkuXTd0D5mQ5RPE53y8AIDHiY3l/+n9ATyapkaB4JGVE18uL3
vdzDZ+ysT0xL/Y5Ixw==
-----END CERTIFICATE-----
"#;

const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDA8tr+sDu1HJe
Dna/lMSsME6OpEQh/4WU0j4DhyW/k7jSzHsIfamDhQLjMBRbkEWrpCxMmpEq0CGv
QWNDig+/jiCkWhEPGtBUg+ruLb8OylENTbFWS+3AymJnMJMWccohsSjljNgFes2g
50x2xnQILS6U69NMcXw5iZpUXpc0Fq8Xba2oH4vS/+LA21gZOf+kIefW7qOWc/db
3LNif3z6O2pzvQewaPd/4nOCFp4Ud9vyef/g2TfnVGYkyLxTeqeZU4+jmhrbvI5X
n7exMU2Ncej0oni9ertg872zAWkd5kjGMpMzrQLemkj/Zv+44nZhyXOx4ZHSewN9
urO7hoiZAgMBAAECggEAEgCNLD7IcE5LRR8nsMrJFwNvP7VZQXGG7B82W06ur48x
mMAIkYGW1Dht9PlQv8fDLrOSj/sVcIgoZoxuNI4Poxq516zQIKlUgaDF3054xyLq
YC8uXNgt2UYK1xoW/JOXhGGyyUdQVRJ/iJ12zmDGgE9kxUQ5zAzj2fniYGx09SQD
qoE/HfmAb7thvUX57T4it7gDPvwYzKHzvl5QrSnOUwxPyOUGDS4RjzSUBrDbEHwJ
WqTWDWMRZCGqBHSlLf3ztjXvVs9f3/PV31GMnijy+L+J+gG2MXDxDlLjVFm7kTiy
sw3B+Sv+DrVDYTCeAxR5OIBv6Md9aUYSrtvGN4qciwKBgQDk3FA3NUSQGMW/QdbD
WNB7DGjz5pnVq3S1xTmAthvz0Wsinh0Ol4nMkjUy+fKr81X4GNyxISZNHtX0cb29
fJwfeSq0e0rYTkJgyoOgcj7FLbNLV4dTyIUpFAmaqeJrd1wt9Z0G1ttwFhmlXXVv
57a+7re8QgYAgQJeIEMIA5Ic3wKBgQDaJAAlrkLM5x/KphgLbfG5qX/M9aQ0Mr76
QnaGePgyWx7hki67lVgLikP0eREs3qTTwzxcuXzRx9JT54cxI6bWF3GJk9ShNHq+
FFE0xebiJsfjJlclXATyNfQzjoKVSf+8wjEXQErnDXLZB4HeiUODY4L9uGztLGWS
F+rLDcGRhwKBgETmFrgoLzX6Xz4PAirZSBpjSA11dQagkYhPkdov+QZUG57WXwUP
lgqiUaXBHc+qeE0ynu4sfq1lBSCMRYUQSKgpADRJkeTA2rbtAOeCvWb7NSkPdsxA
Z+ZQA/wt/N5Blty3PsjaUkHSRXJFSp+f8KJWl7XzYn8wV5giuktlV82dAoGAaLcH
aw8v+fSpCjqZKENq2llHhDgWzwfdLX1iMEM5wdKEDHyD+oBCd6ez31OOrx9huFXs
UAaqqHlnuedWunwGxpcSZZyVYZ0znrNaGB84Ki+7nIr3InP929eSln0+qjOPlCkU
L7kpO6j1DMHR0eXKhvPqGanCgEfjqjHZAAhmd1kCgYEAiYAxwXjpkhANHQAX5UEh
SF6TfAxAUHNB2RNeZ4GlJphQ+nea9I95+82uzqLAHcJtW7QWZh1nudrN1/FscCBT
iW3+Zuwr0Qjk2fIYqTwR7GVwHFHUyF+ybiHLBnO5ogFG4epHRvzCzs05VIBZUpjK
PgOEzGSV8wm/fPgrYyiEqrM=
-----END PRIVATE KEY-----
"#;

fn daemon_path() -> String {
    std::env::var("HUSHD_BIN")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_hushd"))
        .unwrap_or_else(|_| {
            option_env!("CARGO_BIN_EXE_hushd")
                .map(ToString::to_string)
                .unwrap_or_else(|| "target/debug/hushd".to_string())
        })
}

fn find_available_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind 127.0.0.1:0")
        .local_addr()
        .expect("local_addr")
        .port()
}

struct Spawned {
    process: Child,
    url: String,
    test_dir: std::path::PathBuf,
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.test_dir);
    }
}

async fn wait_for_https_health(url: &str, timeout: Duration) {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(resp) = client.get(format!("{}/health", url)).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("TLS daemon failed to become healthy within {:?}", timeout);
}

#[tokio::test]
async fn test_health_endpoint_over_https() {
    let port = find_available_port();
    let url = format!("https://localhost:{}", port);

    let test_dir = std::env::temp_dir().join(format!("hushd-test-tls-{}", port));
    std::fs::create_dir_all(&test_dir).expect("create test dir");

    let cert_path = test_dir.join("cert.pem");
    let key_path = test_dir.join("key.pem");
    std::fs::write(&cert_path, CERT_PEM).expect("write cert");
    std::fs::write(&key_path, KEY_PEM).expect("write key");

    let config = Config {
        listen: format!("127.0.0.1:{}", port),
        audit_db: test_dir.join("audit.db"),
        cors_enabled: false,
        rate_limit: RateLimitConfig {
            enabled: false,
            ..Default::default()
        },
        tls: Some(TlsConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        }),
        ..Default::default()
    };

    let config_path = test_dir.join("hushd.yaml");
    let yaml = serde_yaml::to_string(&config).expect("serialize config");
    std::fs::write(&config_path, yaml).expect("write config");

    let process = Command::new(daemon_path())
        .args(["--config", config_path.to_str().unwrap(), "start"])
        .spawn()
        .expect("spawn hushd");

    // Ensure cleanup if we fail early.
    let mut spawned = Spawned {
        process,
        url: url.clone(),
        test_dir: test_dir.clone(),
    };

    wait_for_https_health(&spawned.url, Duration::from_secs(10)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");
    let resp = client
        .get(format!("{}/health", spawned.url))
        .send()
        .await
        .expect("GET /health");
    assert!(resp.status().is_success());

    // Explicitly kill now to avoid holding on to the process longer than needed.
    let _ = spawned.process.kill();
    let _ = spawned.process.wait();
}
