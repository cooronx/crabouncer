use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde_json::{Value, json};

use crate::{
    AppState,
    error::{ApiError, Result},
};

pub(super) async fn discovery(State(state): State<Arc<AppState>>) -> Json<Value> {
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

pub(super) async fn jwks(State(state): State<Arc<AppState>>) -> Result<Json<Value>> {
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
