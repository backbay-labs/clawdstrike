//! Common test utilities for clawdstriked integration tests

use std::net::TcpListener;
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use hushd::config::{ApiKeyConfig, AuthConfig, Config, RateLimitConfig};

static TEST_DAEMON: OnceLock<Mutex<TestDaemon>> = OnceLock::new();

/// Get the daemon URL from environment or use default
pub fn daemon_url() -> String {
    if let Ok(url) = std::env::var("CLAWDSTRIKE_TEST_URL") {
        return url;
    }
    if let Ok(url) = std::env::var("HUSHD_TEST_URL") {
        return url;
    }

    let daemon = TEST_DAEMON.get_or_init(|| Mutex::new(TestDaemon::spawn()));
    daemon
        .lock()
        .expect("Test daemon mutex poisoned")
        .url
        .clone()
}

/// Find an available port for testing
pub fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to random port")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}

/// Test daemon wrapper that manages lifecycle
pub struct TestDaemon {
    pub url: String,
    pub port: u16,
    pub test_dir: std::path::PathBuf,
    process: Option<Child>,
}

#[derive(Clone, Debug)]
pub struct TestAuthKeys {
    pub check_key: String,
    pub admin_key: String,
}

impl TestDaemon {
    /// Spawn a new test daemon on an available port
    pub fn spawn() -> Self {
        Self::spawn_with_config(Config {
            cors_enabled: false,
            rate_limit: RateLimitConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    pub fn spawn_auth_daemon() -> (Self, TestAuthKeys) {
        let keys = TestAuthKeys {
            check_key: format!("test-check-{}", uuid::Uuid::new_v4()),
            admin_key: format!("test-admin-{}", uuid::Uuid::new_v4()),
        };

        let daemon = Self::spawn_with_config(Config {
            cors_enabled: false,
            auth: AuthConfig {
                enabled: true,
                api_keys: vec![
                    ApiKeyConfig {
                        name: "test-check".to_string(),
                        key: keys.check_key.clone(),
                        scopes: vec!["check".to_string(), "read".to_string()],
                        expires_at: None,
                    },
                    ApiKeyConfig {
                        name: "test-admin".to_string(),
                        key: keys.admin_key.clone(),
                        scopes: vec!["admin".to_string()],
                        expires_at: None,
                    },
                ],
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        });

        (daemon, keys)
    }

    pub fn spawn_rate_limited_daemon(burst_size: u32, requests_per_second: u32) -> Self {
        Self::spawn_with_config(Config {
            cors_enabled: false,
            auth: AuthConfig {
                enabled: false,
                api_keys: Vec::new(),
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                burst_size,
                requests_per_second,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    pub fn spawn_with_config(mut config: Config) -> Self {
        let port = find_available_port();
        let url = format!("http://127.0.0.1:{}", port);

        let test_dir = std::env::temp_dir().join(format!("clawdstriked-test-{}", port));
        std::fs::create_dir_all(&test_dir).expect("Failed to create test directory");

        // Always isolate storage to the temp dir, regardless of caller config.
        config.listen = format!("127.0.0.1:{}", port);
        config.audit_db = test_dir.join("audit.db");

        let config_path = test_dir.join("clawdstriked.yaml");
        let yaml = serde_yaml::to_string(&config).expect("Failed to serialize config");
        std::fs::write(&config_path, yaml).expect("Failed to write test config");

        let daemon_path = std::env::var("CLAWDSTRIKE_BIN")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_clawdstriked"))
            .unwrap_or_else(|_| {
                option_env!("CARGO_BIN_EXE_clawdstriked")
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "target/debug/clawdstriked".to_string())
            });

        let process = Command::new(&daemon_path)
            .args(["--config", config_path.to_str().unwrap(), "start"])
            .spawn()
            .expect("Failed to spawn daemon");

        let daemon = Self {
            url,
            port,
            test_dir,
            process: Some(process),
        };

        // Wait for daemon to be ready
        daemon.wait_for_health(Duration::from_secs(10));

        daemon
    }

    /// Wait for the health endpoint to respond
    fn wait_for_health(&self, timeout: Duration) {
        use std::io::{Read, Write};

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));

                let _ = stream.write_all(
                    b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                );

                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
                    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        panic!("Daemon failed to become healthy within {:?}", timeout);
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            // Just kill the process - it handles SIGTERM gracefully
            let _ = process.kill();
            let _ = process.wait();
        }

        let _ = std::fs::remove_dir_all(&self.test_dir);
    }
}
