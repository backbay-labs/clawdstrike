use std::net::SocketAddr;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub nats_url: String,
    pub jwt_secret: String,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    MissingVar(String),
    #[error("invalid listen address: {0}")]
    InvalidAddr(#[from] std::net::AddrParseError),
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse::<SocketAddr>()?;

        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| ConfigError::MissingVar("DATABASE_URL".into()))?;
        let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|_| ConfigError::MissingVar("JWT_SECRET".into()))?;
        let stripe_secret_key = std::env::var("STRIPE_SECRET_KEY")
            .map_err(|_| ConfigError::MissingVar("STRIPE_SECRET_KEY".into()))?;
        let stripe_webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
            .map_err(|_| ConfigError::MissingVar("STRIPE_WEBHOOK_SECRET".into()))?;

        Ok(Self {
            listen_addr,
            database_url,
            nats_url,
            jwt_secret,
            stripe_secret_key,
            stripe_webhook_secret,
        })
    }
}
