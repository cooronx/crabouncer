use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

const DEFAULT_PATH: &str = "config/app.toml";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) server: Server,
    pub(crate) database: Database,
    pub(crate) bootstrap: Bootstrap,
    pub(crate) tokens: Tokens,
    pub(crate) audit: Audit,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Server {
    pub(crate) bind: SocketAddr,
    pub(crate) public_url: String,
    pub(crate) web_url: String,
    pub(crate) cookie_secure: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    pub(crate) url: String,
    pub(crate) max_connections: u32,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bootstrap {
    pub(crate) organization: String,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) password: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tokens {
    pub(crate) issuer: String,
    pub(crate) key_id: String,
    pub(crate) private_key_path: PathBuf,
    pub(crate) public_key_path: PathBuf,
    pub(crate) access_ttl_seconds: i64,
    pub(crate) service_ttl_seconds: i64,
    pub(crate) refresh_ttl_seconds: i64,
    pub(crate) authorization_code_ttl_seconds: i64,
    pub(crate) activation_ttl_seconds: i64,
    pub(crate) session_ttl_seconds: i64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Audit {
    pub(crate) decision_retention_days: i64,
    pub(crate) redacted_fields: Vec<String>,
}

impl Config {
    pub(crate) fn load() -> Result<Self, String> {
        let path = env::var("CRABOUNCER_CONFIG").unwrap_or_else(|_| DEFAULT_PATH.into());
        let source =
            fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        let mut config: Self =
            toml::from_str(&source).map_err(|e| format!("invalid {path}: {e}"))?;
        if let Ok(password) = env::var("CRABOUNCER_BOOTSTRAP_PASSWORD") {
            config.bootstrap.password = password;
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("server.public_url", &self.server.public_url),
            ("server.web_url", &self.server.web_url),
            ("tokens.issuer", &self.tokens.issuer),
        ] {
            if !value.starts_with("http://") && !value.starts_with("https://") {
                return Err(format!("{name} must be an absolute HTTP URL"));
            }
        }
        if self.database.url.trim().is_empty() {
            return Err("database.url must not be empty".into());
        }
        if self.database.max_connections == 0 {
            return Err("database.max_connections must be positive".into());
        }
        if self.audit.decision_retention_days <= 0 {
            return Err("audit.decision_retention_days must be positive".into());
        }
        for ttl in [
            self.tokens.access_ttl_seconds,
            self.tokens.service_ttl_seconds,
            self.tokens.refresh_ttl_seconds,
            self.tokens.authorization_code_ttl_seconds,
            self.tokens.activation_ttl_seconds,
            self.tokens.session_ttl_seconds,
        ] {
            if ttl <= 0 {
                return Err("token TTL values must be positive".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
    fs::read(path.as_ref()).map_err(|e| format!("could not read {}: {e}", path.as_ref().display()))
}
