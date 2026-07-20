use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::Redirect,
};
use serde::Deserialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::{
    AppState,
    api::management,
    db::{AuthorizationApp, AuthorizationCode},
    error::{ApiError, Result},
    security,
};

#[derive(Deserialize)]
pub(super) struct AuthorizationQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
}

pub(super) async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuthorizationQuery>,
) -> Result<Redirect> {
    let app = state
        .db
        .authorization_app(&query.client_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("unknown client_id"))?;
    validate_authorization(&query, &app)?;
    let current = match management::session_actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(_) => {
            let mut login = Url::parse(&format!(
                "{}/login",
                state.config.server.web_url.trim_end_matches('/')
            ))
            .map_err(|_| ApiError::bad_request("web_url is invalid"))?;
            login
                .query_pairs_mut()
                .append_pair("return_to", &authorization_return_url(&state, &query));
            return Ok(Redirect::to(login.as_str()));
        }
    };
    if current.organization_id != app.organization_id {
        return Err(ApiError::forbidden());
    }
    let code = security::random_token();
    state
        .db
        .store_authorization_code(AuthorizationCode {
            code_hash: security::token_hash(&code),
            application_id: app.id,
            user_id: current.id,
            redirect_uri: query.redirect_uri.clone(),
            scope: query.scope.clone(),
            code_challenge: query.code_challenge.clone(),
            nonce: query.nonce.clone(),
            expires_at: OffsetDateTime::now_utc()
                + Duration::seconds(state.config.tokens.authorization_code_ttl_seconds),
        })
        .await?;
    let mut redirect = Url::parse(&query.redirect_uri)
        .map_err(|_| ApiError::bad_request("redirect_uri is invalid"))?;
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(value) = &query.state {
        redirect.query_pairs_mut().append_pair("state", value);
    }
    Ok(Redirect::to(redirect.as_str()))
}

fn validate_authorization(query: &AuthorizationQuery, app: &AuthorizationApp) -> Result<()> {
    if query.response_type != "code" {
        return Err(ApiError::bad_request(
            "only response_type=code is supported",
        ));
    }
    if query.code_challenge_method != "S256" || query.code_challenge.len() < 43 {
        return Err(ApiError::bad_request("PKCE S256 is required"));
    }
    let redirects = app
        .redirect_uris
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    if !redirects
        .into_iter()
        .any(|value| value == query.redirect_uri)
    {
        return Err(ApiError::bad_request("redirect_uri is not registered"));
    }
    let allowed = app
        .allowed_scopes
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let requested = query.scope.split_whitespace().collect::<Vec<_>>();
    if !requested.contains(&"openid") || requested.iter().any(|scope| !allowed.contains(scope)) {
        return Err(ApiError::bad_request("scope is not allowed"));
    }
    Ok(())
}

fn authorization_return_url(state: &AppState, query: &AuthorizationQuery) -> String {
    let mut url = Url::parse(&format!(
        "{}/oauth2/authorize",
        state.config.server.public_url.trim_end_matches('/')
    ))
    .expect("validated public URL");
    let mut pairs = url.query_pairs_mut();
    pairs
        .append_pair("response_type", &query.response_type)
        .append_pair("client_id", &query.client_id)
        .append_pair("redirect_uri", &query.redirect_uri)
        .append_pair("scope", &query.scope)
        .append_pair("code_challenge", &query.code_challenge)
        .append_pair("code_challenge_method", &query.code_challenge_method);
    if let Some(value) = &query.state {
        pairs.append_pair("state", value);
    }
    if let Some(value) = &query.nonce {
        pairs.append_pair("nonce", value);
    }
    drop(pairs);
    url.into()
}
