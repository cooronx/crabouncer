use std::{env, fs, net::SocketAddr, path::Path};

use serde::Deserialize;

const DEFAULT_CONFIG_PATH: &str = "config/app.toml";

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) database_url: String,
    pub(crate) bind: SocketAddr,
    pub(crate) bootstrap_password: String,
    pub(crate) cookie_secure: bool,
    pub(crate) session_ttl_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    server: ServerConfig,
    database: DatabaseConfig,
    bootstrap: BootstrapConfig,
    session: SessionConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    bind: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseConfig {
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapConfig {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionConfig {
    cookie_secure: bool,
    ttl_seconds: i64,
}

impl Config {
    pub(crate) fn load() -> Result<Self, String> {
        let path = env::var("CRABOUNCER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
        Self::from_path(path)
    }

    fn from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .map_err(|error| format!("could not read configuration {}: {error}", path.display()))?;
        Self::from_toml(&source)
            .map_err(|error| format!("invalid configuration {}: {error}", path.display()))
    }

    fn from_toml(source: &str) -> Result<Self, String> {
        let file: FileConfig = toml::from_str(source).map_err(|error| error.to_string())?;
        if file.database.url.trim().is_empty() {
            return Err("database.url must not be empty".into());
        }
        if !(6..=12).contains(&file.bootstrap.password.chars().count()) {
            return Err("bootstrap.password must contain 6 to 12 characters".into());
        }
        if file.session.ttl_seconds <= 0 {
            return Err("session.ttl_seconds must be positive".into());
        }

        Ok(Self {
            database_url: file.database.url,
            bind: file.server.bind,
            bootstrap_password: file.bootstrap.password,
            cookie_secure: file.session.cookie_secure,
            session_ttl_seconds: file.session.ttl_seconds,
        })
    }
}
