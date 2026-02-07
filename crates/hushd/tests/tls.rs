//! TLS integration tests for hushd.
//!
//! This test spawns a daemon with a self-signed certificate and verifies `/health` over HTTPS.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Child, Command};
use std::time::Duration;

use hushd::config::{Config, RateLimitConfig, TlsConfig};

const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUJVPpZHIJ5cG5QLAYJ25Ksc2xVoIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDIwNzE2NDkwOFoXDTM2MDIw
NTE2NDkwOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAy6MRBhQ2cZgx1eL0Qw/EOnKqCiHu3ZDrlPqxIE+oKPlv
+w0nuuM1j+EsBvk3GFKp7HYmB4WQ8Kk+4YbTn/5wqE47O8dhrIb3RpljegPZF/Uk
A3u0fqf3CwkvMNMJdHxD5xxysJDZ6UrQKSLZF6+LAG6Jflg1asec7Yv896cQtnZ1
Xb9t0ycUKYTpST6iXlwAbgAOXnvk/qFafQcHli6GZvO8jR6w+gLGvUIKbyIGPlA7
7Ljn30FkazS8Adcjut7qzjn9glcfqJoHT2Kq5rJGR+/qQubNB7AApL78bHBLYw9T
ADraz4YiwRz0POEsygc3Gp/ekeuFP3/McLH4alb3AQIDAQABo1MwUTAdBgNVHQ4E
FgQUfCyqH3scJ49Jnw+UI7Eytr2BuNswHwYDVR0jBBgwFoAUfCyqH3scJ49Jnw+U
I7Eytr2BuNswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWMMa
G5DVdRC+nYKc9hqP3b/R76lRLNIybfd6+/ZFgi9Qat1Yr9VlF7uBBM7dyZMOJy6v
mypVQmL2KwRs/POJJSiKhXOSttztQCbgVgGxaQVmAm6H/5ztkACHSZjKs9r53mLQ
DkRQ+RgTtJ6Qm0tWZ6O0bHfMi9kNvx5bHX6OUKpKqdZETeP1SITeIIzQLVaSwVQm
Gh+dTbkxSIa3vFQIYr3Ybp/rbwQW5oHEp4hDJEYig6up0MoIJ05/0cnufcLj3aLO
pyKJWygXobgMy45PKFIqunUzX9PxEHiUNzik7VpcrIzDnIWH3sWuc2nHkp/iJXvK
wboiqrWguCNCpwqTFA==
-----END CERTIFICATE-----
"#;

const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLoxEGFDZxmDHV
4vRDD8Q6cqoKIe7dkOuU+rEgT6go+W/7DSe64zWP4SwG+TcYUqnsdiYHhZDwqT7h
htOf/nCoTjs7x2GshvdGmWN6A9kX9SQDe7R+p/cLCS8w0wl0fEPnHHKwkNnpStAp
ItkXr4sAbol+WDVqx5zti/z3pxC2dnVdv23TJxQphOlJPqJeXABuAA5ee+T+oVp9
BweWLoZm87yNHrD6Asa9QgpvIgY+UDvsuOffQWRrNLwB1yO63urOOf2CVx+omgdP
YqrmskZH7+pC5s0HsACkvvxscEtjD1MAOtrPhiLBHPQ84SzKBzcan96R64U/f8xw
sfhqVvcBAgMBAAECggEADQ0J5TMzJTTApp32HGFROyVxcfuDwqTHk0qGsJle6Nw3
rmqOEKgAL3BjVZ0UkV5JMGGG8yN1yxWcmbl+B/FcLXLw9Q0NuCJOjKAidnyppdp/
Z7zjHbhez4fBg90M7G+eri5k7MImHSQIQNmHHniQ5GdoC3ZCNrtfnyRmuiDQ/3ZI
mIB5ybgkNSmOkj48NOPIQu88i/jCwDhCEf7gwgLoTJjN5r0JJ4Ue77kelCqpxDbx
aLHphDq85VRo2X2oTZ8fSF07pbRFsW7tm/wm89uTteirb8+fYXYPXfuz89izPBkp
OoYQKGvfXRG8EfnLeH/yXdCCINqweM5SWku5n17QMwKBgQD3E+r3zsxlt5YBbaAN
G+inYtxWZ1v5fZf6mo/8ydo6M5l374yMbXDepfxBeQ2dzPObV5yow5kHpSihOfzC
GTLp4GWlmxOgTSYE+0mY+hz8uEfochoW7ab91HUt4PUT1ArAH5WGj8/ojxCMK3Bt
c4SnJWfT8XAoxBjPgpYmrGod4wKBgQDS/ZCiByUQRreVl8k4Wio1S+7eNzl99Ank
cUorBnpWUoAFmIC7GnySmgXVzdn84i3hXzCZcZJpu/n0+Nn6951qnarK7Vvwp1zI
6kzYi05qphWOLtc8M9DlWKvMvDE3HkFH825OlN+e4gU7bEslHSzCHcQ6czC1gMqe
CbodKAzsywKBgQCK6zgBfNSPnFlLFEgZFsgI1Rztt8+Ox37b+GtcxmFcuAZh2N49
VotPpCPg7B8rykBt5yS9/rvcAJCHlgL3XxOxS+na4wZ16uqlgmQvDvGdZj+IAh+J
JLXvobUAxqsFKwOgYiHANru/FjFHnmToJTtAf1eRYv6c7STGB7ZEqExB4QKBgDYM
JkSbN+9Xbiev3ifFURKeBO5/jwaowO/35VvoKOZ787d7PV6whkC3m88NEE4rUj1t
OPHVmf/j2z/Zj10umPB6uwmIjAi1lpsRCeZeqRPAv7zQWupdC6H0eO3VN3Y7FdXs
kdEnabE1jMmQEB/NvW1sWpvubgfQmhapvzdAzy7JAoGAQQtSJjUKQM3dSsaQ283f
sQRfw0HeLawMETAsFsZ8JbQCBhD2zUJ9XFS72cwjsSdjJFtbKyiwVpe9YA4K3S6P
jp5QsHY8KpBvpquszQ2oIwz+xJusSaYx/c5qF0to4YViFnLVwmVMs0KGTDCZ3AVW
lVL6YlSJKSIUnQ9qtS7g0vs=
-----END PRIVATE KEY-----
"#;

fn daemon_path() -> String {
    std::env::var("CLAWDSTRIKE_BIN")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_clawdstriked"))
        .unwrap_or_else(|_| {
            option_env!("CARGO_BIN_EXE_clawdstriked")
                .map(ToString::to_string)
                .unwrap_or_else(|| "target/debug/clawdstriked".to_string())
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

    wait_for_https_health(&spawned.url, Duration::from_secs(30)).await;

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
