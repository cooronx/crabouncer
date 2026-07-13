//! Async client for Crabouncer's OAuth client-credentials and AuthZEN APIs.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use protocol::Decision;
pub use protocol::{Action, EvaluationRequest, Resource, Subject};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AuthzenClient {
    http: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    token: Arc<Mutex<Option<CachedToken>>>,
}

struct CachedToken {
    value: String,
    refresh_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization denied ({request_id}): {reason}")]
    Denied { request_id: String, reason: String },
    #[error("service authentication failed")]
    Authentication,
    #[error("Crabouncer returned HTTP {0}")]
    Http(StatusCode),
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl AuthzenClient {
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            token: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn evaluate(&self, request: &EvaluationRequest) -> Result<Decision, Error> {
        let mut attempt = 0;
        loop {
            let token = self.service_token().await?;
            let response = self
                .http
                .post(format!("{}/access/v1/evaluation", self.base_url))
                .bearer_auth(token)
                .header("X-Request-ID", uuid_like_request_id())
                .json(request)
                .send()
                .await?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                *self.token.lock().await = None;
                attempt += 1;
                continue;
            }
            if !response.status().is_success() {
                return Err(Error::Http(response.status()));
            }
            return Ok(response.json().await?);
        }
    }

    pub async fn require_allowed(
        &self,
        subject: Subject,
        action: Action,
        resource: Resource,
    ) -> Result<(), Error> {
        let decision = self
            .evaluate(&EvaluationRequest {
                subject,
                action,
                resource,
                context: Default::default(),
            })
            .await?;
        if decision.decision {
            return Ok(());
        }
        let context = decision.context.unwrap_or(protocol::DecisionContext {
            request_id: "unknown".into(),
            reason: "denied".into(),
        });
        Err(Error::Denied {
            request_id: context.request_id,
            reason: context.reason,
        })
    }

    async fn service_token(&self) -> Result<String, Error> {
        let mut cached = self.token.lock().await;
        if let Some(token) = cached
            .as_ref()
            .filter(|token| token.refresh_at > Instant::now())
        {
            return Ok(token.value.clone());
        }
        let response = self
            .http
            .post(format!("{}/oauth2/token", self.base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", "authzen:evaluate"),
            ])
            .send()
            .await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(Error::Authentication);
        }
        if !response.status().is_success() {
            return Err(Error::Http(response.status()));
        }
        let token: TokenResponse = response.json().await?;
        let safety = token.expires_in.saturating_sub(30);
        *cached = Some(CachedToken {
            value: token.access_token.clone(),
            refresh_at: Instant::now() + Duration::from_secs(safety),
        });
        Ok(token.access_token)
    }
}

fn uuid_like_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "sdk-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}
