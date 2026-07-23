use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

const RESOURCE_SYNC_SCOPE: &str = "resources:sync";
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Crabouncer {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    token_url: Url,
    resource_sync_url: Url,
    client_id: String,
    client_secret: String,
    token: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    access_token: String,
    refresh_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Crabouncer URL: {0}")]
    InvalidUrl(String),
    #[error("Crabouncer request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Crabouncer returned HTTP {status}: {message}")]
    Api { status: StatusCode, message: String },
}

impl Crabouncer {
    pub fn new(
        base_url: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::with_http_client(base_url, client_id, client_secret, reqwest::Client::new())
    }

    pub fn with_http_client(
        base_url: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        http: reqwest::Client,
    ) -> Result<Self, Error> {
        let base_url =
            Url::parse(base_url.as_ref()).map_err(|error| Error::InvalidUrl(error.to_string()))?;
        let token_url = base_url
            .join("/oauth2/token")
            .map_err(|error| Error::InvalidUrl(error.to_string()))?;
        let resource_sync_url = base_url
            .join("/resource-sync/v1/resources")
            .map_err(|error| Error::InvalidUrl(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Inner {
                token_url,
                resource_sync_url,
                http,
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                token: Mutex::new(None),
            }),
        })
    }

    pub async fn sync_resources<I>(&self, operations: I) -> Result<SyncReport, Error>
    where
        I: IntoIterator<Item = SyncOperation>,
    {
        let request = SyncRequest {
            operations: operations.into_iter().collect(),
        };
        let token = self.access_token().await?;
        let response = self.send_sync(&request, &token).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return decode_response(response).await;
        }

        self.inner.token.lock().await.take();
        let token = self.access_token().await?;
        decode_response(self.send_sync(&request, &token).await?).await
    }

    async fn send_sync(
        &self,
        request: &SyncRequest,
        access_token: &str,
    ) -> Result<reqwest::Response, Error> {
        for attempt in 0..2 {
            let response = self
                .inner
                .http
                .post(self.inner.resource_sync_url.clone())
                .bearer_auth(access_token)
                .json(request)
                .send()
                .await;
            match response {
                Ok(response) if attempt == 0 && is_transient_status(response.status()) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(response) => return Ok(response),
                Err(error) if attempt == 0 && (error.is_connect() || error.is_timeout()) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(Error::Transport(error)),
            }
        }
        unreachable!("the retry loop always returns on its final attempt")
    }

    async fn access_token(&self) -> Result<String, Error> {
        let mut cached = self.inner.token.lock().await;
        if let Some(token) = cached.as_ref()
            && Instant::now() < token.refresh_at
        {
            return Ok(token.access_token.clone());
        }

        let response = self.request_token().await?;
        let response: TokenResponse = decode_response(response).await?;
        let lifetime = Duration::from_secs(response.expires_in.max(1));
        let refresh_after = lifetime.saturating_sub(TOKEN_REFRESH_MARGIN);
        *cached = Some(CachedToken {
            access_token: response.access_token.clone(),
            refresh_at: Instant::now() + refresh_after,
        });
        Ok(response.access_token)
    }

    async fn request_token(&self) -> Result<reqwest::Response, Error> {
        for attempt in 0..2 {
            let response = self
                .inner
                .http
                .post(self.inner.token_url.clone())
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", self.inner.client_id.as_str()),
                    ("client_secret", self.inner.client_secret.as_str()),
                    ("scope", RESOURCE_SYNC_SCOPE),
                ])
                .send()
                .await;
            match response {
                Ok(response) if attempt == 0 && is_transient_status(response.status()) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(response) => return Ok(response),
                Err(error) if attempt == 0 && (error.is_connect() || error.is_timeout()) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(Error::Transport(error)),
            }
        }
        unreachable!("the retry loop always returns on its final attempt")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SyncedResource {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
    properties: Map<String, Value>,
}

impl SyncedResource {
    pub fn new(resource_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            id: id.into(),
            properties: Map::new(),
        }
    }

    pub fn property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.insert(name.into(), value.into());
        self
    }

    pub fn entity_property(
        mut self,
        name: impl Into<String>,
        entity_type: impl Into<String>,
        entity_id: impl Into<String>,
    ) -> Self {
        self.properties.insert(
            name.into(),
            json!({
                "__entity": {
                    "type": entity_type.into(),
                    "id": entity_id.into(),
                }
            }),
        );
        self
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum SyncOperation {
    Upsert {
        #[serde(flatten)]
        resource: SyncedResource,
    },
    Delete {
        #[serde(rename = "type")]
        resource_type: String,
        id: String,
    },
}

impl SyncOperation {
    pub fn upsert(resource: SyncedResource) -> Self {
        Self::Upsert { resource }
    }

    pub fn delete(resource_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self::Delete {
            resource_type: resource_type.into(),
            id: id.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SyncReport {
    pub request_id: String,
    pub results: Vec<SyncResult>,
}

impl SyncReport {
    pub fn is_success(&self) -> bool {
        self.results.iter().all(SyncResult::is_success)
    }

    pub fn failures(&self) -> impl Iterator<Item = &SyncResult> {
        self.results.iter().filter(|result| !result.is_success())
    }
}

#[derive(Debug, Deserialize)]
pub struct SyncResult {
    pub index: usize,
    pub status: String,
    pub message: Option<String>,
}

impl SyncResult {
    pub fn is_success(&self) -> bool {
        !matches!(self.status.as_str(), "invalid" | "error")
    }
}

#[derive(Serialize)]
struct SyncRequest {
    operations: Vec<SyncOperation>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    message: String,
}

async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, Error> {
    let status = response.status();
    if status.is_success() {
        return response.json().await.map_err(Error::from);
    }
    let body = response.text().await?;
    let message = serde_json::from_str::<ErrorEnvelope>(&body)
        .map(|error| error.error.message)
        .unwrap_or(body);
    Err(Error::Api { status, message })
}

fn is_transient_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_explicit_entity_properties() {
        let operation = SyncOperation::upsert(
            SyncedResource::new("Document", "roadmap")
                .property("title", "Roadmap")
                .entity_property("owner", "User", "alice"),
        );
        assert_eq!(
            serde_json::to_value(operation).unwrap(),
            json!({
                "operation": "upsert",
                "type": "Document",
                "id": "roadmap",
                "properties": {
                    "title": "Roadmap",
                    "owner": {
                        "__entity": { "type": "User", "id": "alice" }
                    }
                }
            })
        );
    }

    #[test]
    fn identifies_partial_failures() {
        let report = SyncReport {
            request_id: "request".into(),
            results: vec![
                SyncResult {
                    index: 0,
                    status: "upserted".into(),
                    message: None,
                },
                SyncResult {
                    index: 1,
                    status: "invalid".into(),
                    message: Some("schema mismatch".into()),
                },
            ],
        };
        assert!(!report.is_success());
        assert_eq!(report.failures().count(), 1);
    }
}
