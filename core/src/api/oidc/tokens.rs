use std::sync::Arc;

use axum::{Form, Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    db::{AuthorizationCodeExchange, RefreshRotation, ServiceCredential, UserGrant},
    error::{ApiError, Result},
    security::{self, Claims},
};

#[derive(Deserialize)]
pub(super) struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize)]
pub(super) struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

pub(super) async fn token(
    State(state): State<Arc<AppState>>,
    Form(form): Form<TokenForm>,
) -> Result<Json<TokenResponse>> {
    match form.grant_type.as_str() {
        "authorization_code" => authorization_code_token(&state, form).await.map(Json),
        "refresh_token" => refresh_token(&state, form).await.map(Json),
        "client_credentials" => client_credentials(&state, form).await.map(Json),
        _ => Err(ApiError::bad_request("unsupported grant_type")),
    }
}

async fn authorization_code_token(state: &AppState, form: TokenForm) -> Result<TokenResponse> {
    let code = form
        .code
        .ok_or_else(|| ApiError::bad_request("code is required"))?;
    let verifier = form
        .code_verifier
        .ok_or_else(|| ApiError::bad_request("code_verifier is required"))?;
    let redirect = form
        .redirect_uri
        .ok_or_else(|| ApiError::bad_request("redirect_uri is required"))?;
    let refresh = security::random_token();
    let family = Uuid::now_v7();
    let grant: UserGrant = state
        .db
        .exchange_authorization_code(AuthorizationCodeExchange {
            code_hash: security::token_hash(&code),
            redirect_uri: redirect,
            code_challenge: security::pkce_challenge(&verifier),
            refresh_hash: security::token_hash(&refresh),
            refresh_family_id: family,
            refresh_expires_at: OffsetDateTime::now_utc()
                + Duration::seconds(state.config.tokens.refresh_ttl_seconds),
        })
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    user_tokens(
        state,
        grant.user_id,
        grant.organization_id,
        &grant.client_id,
        grant.scope,
        grant.nonce,
        Some(refresh),
    )
}

async fn refresh_token(state: &AppState, form: TokenForm) -> Result<TokenResponse> {
    let old = form
        .refresh_token
        .ok_or_else(|| ApiError::bad_request("refresh_token is required"))?;
    let fresh = security::random_token();
    let grant: UserGrant = match state
        .db
        .rotate_refresh_token(
            security::token_hash(&old),
            security::token_hash(&fresh),
            OffsetDateTime::now_utc() + Duration::seconds(state.config.tokens.refresh_ttl_seconds),
        )
        .await?
    {
        RefreshRotation::Rotated(grant) => grant,
        RefreshRotation::Missing | RefreshRotation::Reused => {
            return Err(ApiError::unauthorized());
        }
    };
    user_tokens(
        state,
        grant.user_id,
        grant.organization_id,
        &grant.client_id,
        grant.scope,
        None,
        Some(fresh),
    )
}

async fn client_credentials(state: &AppState, form: TokenForm) -> Result<TokenResponse> {
    let client_id = form
        .client_id
        .ok_or_else(|| ApiError::bad_request("client_id is required"))?;
    let secret = form
        .client_secret
        .ok_or_else(|| ApiError::bad_request("client_secret is required"))?;
    let candidates: Vec<ServiceCredential> = state.db.service_credentials(&client_id).await?;
    let row = candidates
        .into_iter()
        .find(|row| security::password_matches(&secret, &row.secret_hash))
        .ok_or_else(ApiError::unauthorized)?;
    let available = row
        .scopes
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let requested = form
        .scope
        .as_deref()
        .unwrap_or("authzen:evaluate")
        .split_whitespace()
        .collect::<Vec<_>>();
    if requested.iter().any(|scope| !available.contains(scope)) {
        return Err(ApiError::forbidden());
    }
    let scope = requested.join(" ");
    let claims = claims(
        state,
        row.client_id,
        row.organization_id,
        "authzen".into(),
        Some(row.application_id),
        Some(row.id),
        scope.clone(),
        None,
        state.config.tokens.service_ttl_seconds,
        "access",
    );
    Ok(TokenResponse {
        access_token: state.keys.issue(&state.config.tokens.key_id, &claims)?,
        token_type: "Bearer",
        expires_in: state.config.tokens.service_ttl_seconds,
        scope,
        id_token: None,
        refresh_token: None,
    })
}

fn user_tokens(
    state: &AppState,
    user_id: Uuid,
    organization_id: Uuid,
    audience: &str,
    scope: String,
    nonce: Option<String>,
    refresh: Option<String>,
) -> Result<TokenResponse> {
    let access = claims(
        state,
        user_id.to_string(),
        organization_id,
        audience.into(),
        None,
        None,
        scope.clone(),
        None,
        state.config.tokens.access_ttl_seconds,
        "access",
    );
    let id = claims(
        state,
        user_id.to_string(),
        organization_id,
        audience.into(),
        None,
        None,
        scope.clone(),
        nonce,
        state.config.tokens.access_ttl_seconds,
        "id",
    );
    Ok(TokenResponse {
        access_token: state.keys.issue(&state.config.tokens.key_id, &access)?,
        token_type: "Bearer",
        expires_in: state.config.tokens.access_ttl_seconds,
        scope,
        id_token: Some(state.keys.issue(&state.config.tokens.key_id, &id)?),
        refresh_token: refresh,
    })
}

#[allow(clippy::too_many_arguments)]
fn claims(
    state: &AppState,
    subject: String,
    organization_id: Uuid,
    audience: String,
    application_id: Option<Uuid>,
    service_account_id: Option<Uuid>,
    scope: String,
    nonce: Option<String>,
    ttl: i64,
    token_use: &str,
) -> Claims {
    let now = security::now();
    Claims {
        iss: state.config.tokens.issuer.clone(),
        sub: subject,
        aud: audience,
        exp: (now + ttl) as usize,
        iat: now as usize,
        kind: if service_account_id.is_some() {
            "service".into()
        } else {
            "user".into()
        },
        token_use: token_use.into(),
        organization_id: organization_id.to_string(),
        application_id: application_id.map(|v| v.to_string()),
        service_account_id: service_account_id.map(|v| v.to_string()),
        scope,
        nonce,
    }
}
