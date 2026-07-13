use std::sync::Arc;

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::{Cookie, SameSite};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::{
    AppState,
    error::{ApiError, Result},
    management,
    security::{self, Claims},
};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth2/authorize", get(authorize))
        .route("/oauth2/token", post(token))
        .route("/oauth2/userinfo", get(userinfo))
        .route("/oauth2/logout", post(logout))
}

async fn discovery(State(state): State<Arc<AppState>>) -> Json<Value> {
    let issuer = state.config.tokens.issuer.trim_end_matches('/');
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "end_session_endpoint": format!("{issuer}/oauth2/logout"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"]
    }))
}

async fn jwks(State(state): State<Arc<AppState>>) -> Result<Json<Value>> {
    let pem = std::str::from_utf8(&state.keys.public_pem).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_error",
            "Invalid public key",
        )
    })?;
    let key = RsaPublicKey::from_public_key_pem(pem).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_error",
            "Invalid public key",
        )
    })?;
    Ok(Json(
        json!({ "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": state.config.tokens.key_id, "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()) }] }),
    ))
}

#[derive(Deserialize)]
struct AuthorizationQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(sqlx::FromRow)]
struct AuthorizationApp {
    id: Uuid,
    organization_id: Uuid,
    redirect_uris: Value,
    allowed_scopes: Value,
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuthorizationQuery>,
) -> Result<Redirect> {
    let app = sqlx::query_as::<_, AuthorizationApp>("SELECT id, organization_id, redirect_uris, allowed_scopes FROM applications WHERE client_id = $1 AND enabled")
        .bind(&query.client_id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::bad_request("unknown client_id"))?;
    validate_authorization(&query, &app)?;
    let current = match management::actor(&state, &headers, false).await {
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
    sqlx::query("INSERT INTO oauth_authorization_codes (code_hash, application_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(security::token_hash(&code)).bind(app.id).bind(current.id).bind(&query.redirect_uri).bind(&query.scope).bind(&query.code_challenge).bind(&query.nonce)
        .bind(OffsetDateTime::now_utc() + Duration::seconds(state.config.tokens.authorization_code_ttl_seconds)).execute(&state.pool).await?;
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

#[derive(Deserialize)]
struct TokenForm {
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
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

async fn token(
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

#[derive(sqlx::FromRow)]
struct CodeRow {
    application_id: Uuid,
    user_id: Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    nonce: Option<String>,
    client_id: String,
    organization_id: Uuid,
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
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query_as::<_, CodeRow>("UPDATE oauth_authorization_codes c SET consumed_at = now() FROM applications a WHERE c.application_id = a.id AND c.code_hash = $1 AND c.consumed_at IS NULL AND c.expires_at > now() RETURNING c.application_id, c.user_id, c.redirect_uri, c.scope, c.code_challenge, c.nonce, a.client_id, a.organization_id")
        .bind(security::token_hash(&code)).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::unauthorized)?;
    if row.redirect_uri != redirect || security::pkce_challenge(&verifier) != row.code_challenge {
        return Err(ApiError::unauthorized());
    }
    let refresh = security::random_token();
    let family = Uuid::now_v7();
    sqlx::query("INSERT INTO oauth_refresh_tokens (token_hash, family_id, application_id, user_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6)").bind(security::token_hash(&refresh)).bind(family).bind(row.application_id).bind(row.user_id).bind(&row.scope).bind(OffsetDateTime::now_utc() + Duration::seconds(state.config.tokens.refresh_ttl_seconds)).execute(&mut *tx).await?;
    tx.commit().await?;
    user_tokens(
        state,
        row.user_id,
        row.organization_id,
        &row.client_id,
        row.scope,
        row.nonce,
        Some(refresh),
    )
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    family_id: Uuid,
    application_id: Uuid,
    user_id: Uuid,
    scope: String,
    consumed_at: Option<OffsetDateTime>,
    client_id: String,
    organization_id: Uuid,
}
async fn refresh_token(state: &AppState, form: TokenForm) -> Result<TokenResponse> {
    let old = form
        .refresh_token
        .ok_or_else(|| ApiError::bad_request("refresh_token is required"))?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query_as::<_, RefreshRow>("SELECT r.family_id, r.application_id, r.user_id, r.scope, r.consumed_at, a.client_id, a.organization_id FROM oauth_refresh_tokens r JOIN applications a ON a.id = r.application_id JOIN users u ON u.id = r.user_id JOIN organizations o ON o.id = u.organization_id WHERE r.token_hash = $1 AND r.revoked_at IS NULL AND r.expires_at > now() AND u.status = 'active' AND o.status = 'active' AND a.enabled FOR UPDATE OF r")
        .bind(security::token_hash(&old)).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::unauthorized)?;
    if row.consumed_at.is_some() {
        sqlx::query("UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE family_id = $1")
            .bind(row.family_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(ApiError::unauthorized());
    }
    sqlx::query("UPDATE oauth_refresh_tokens SET consumed_at = now() WHERE token_hash = $1")
        .bind(security::token_hash(&old))
        .execute(&mut *tx)
        .await?;
    let fresh = security::random_token();
    sqlx::query("INSERT INTO oauth_refresh_tokens (token_hash, family_id, application_id, user_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6)").bind(security::token_hash(&fresh)).bind(row.family_id).bind(row.application_id).bind(row.user_id).bind(&row.scope).bind(OffsetDateTime::now_utc() + Duration::seconds(state.config.tokens.refresh_ttl_seconds)).execute(&mut *tx).await?;
    tx.commit().await?;
    user_tokens(
        state,
        row.user_id,
        row.organization_id,
        &row.client_id,
        row.scope,
        None,
        Some(fresh),
    )
}

#[derive(sqlx::FromRow)]
struct ServiceRow {
    id: Uuid,
    application_id: Uuid,
    client_id: String,
    scopes: Value,
    secret_hash: String,
    organization_id: Uuid,
}
async fn client_credentials(state: &AppState, form: TokenForm) -> Result<TokenResponse> {
    let client_id = form
        .client_id
        .ok_or_else(|| ApiError::bad_request("client_id is required"))?;
    let secret = form
        .client_secret
        .ok_or_else(|| ApiError::bad_request("client_secret is required"))?;
    let candidates = sqlx::query_as::<_, ServiceRow>("SELECT s.id, s.application_id, s.client_id, s.scopes, k.secret_hash, a.organization_id FROM service_accounts s JOIN service_account_secrets k ON k.service_account_id = s.id JOIN applications a ON a.id = s.application_id JOIN organizations o ON o.id = a.organization_id WHERE s.client_id = $1 AND s.enabled AND a.enabled AND o.status = 'active' AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())")
        .bind(&client_id).fetch_all(&state.pool).await?;
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

async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<Value>> {
    let token = bearer(&headers)?;
    let claims = state
        .keys
        .verify_issuer(token, &state.config.tokens.issuer)?;
    if claims.kind != "user" || claims.token_use != "access" {
        return Err(ApiError::forbidden());
    }
    let id = Uuid::parse_str(&claims.sub).map_err(|_| ApiError::unauthorized())?;
    let row: (String, String) =
        sqlx::query_as("SELECT email, display_name FROM users WHERE id = $1 AND status = 'active'")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(
        json!({ "sub": claims.sub, "organization_id": claims.organization_id, "email": row.0, "name": row.1 }),
    ))
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(raw) = cookie_value(&headers, "crabouncer_session") {
        let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(security::token_hash(&raw))
            .execute(&state.pool)
            .await;
    }
    let cookie = Cookie::build(("crabouncer_session", ""))
        .path("/")
        .http_only(true)
        .secure(state.config.server.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::ZERO)
        .build();
    (
        [(header::SET_COOKIE, cookie.to_string())],
        StatusCode::NO_CONTENT,
    )
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)
}
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| Cookie::parse(part.trim()).ok())
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.value().to_owned())
}
