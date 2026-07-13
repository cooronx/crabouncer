use std::sync::Arc;

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::{Config, Tokens, read},
    error::{ApiError, Result},
};

pub(crate) struct SigningKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    pub(crate) public_pem: Arc<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Claims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) exp: usize,
    pub(crate) iat: usize,
    pub(crate) kind: String,
    pub(crate) token_use: String,
    pub(crate) organization_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) service_account_id: Option<String>,
    #[serde(default)]
    pub(crate) scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,
}

impl SigningKeys {
    pub(crate) fn load(config: &Tokens) -> std::result::Result<Self, String> {
        let private = read(&config.private_key_path)?;
        let public = read(&config.public_key_path)?;
        Ok(Self {
            encoding: EncodingKey::from_rsa_pem(&private)
                .map_err(|e| format!("invalid RSA private key: {e}"))?,
            decoding: DecodingKey::from_rsa_pem(&public)
                .map_err(|e| format!("invalid RSA public key: {e}"))?,
            public_pem: Arc::new(public),
        })
    }

    pub(crate) fn issue(&self, kid: &str, claims: &Claims) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(&header, claims, &self.encoding).map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "token_error",
                "Could not issue token",
            )
        })
    }

    pub(crate) fn verify(&self, token: &str, issuer: &str, audience: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| ApiError::unauthorized())
    }

    pub(crate) fn verify_issuer(&self, token: &str, issuer: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.validate_aud = false;
        decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| ApiError::unauthorized())
    }
}

pub(crate) fn password_hash(password: &str) -> std::result::Result<String, String> {
    if !(12..=128).contains(&password.chars().count()) {
        return Err("password must contain 12 to 128 characters".into());
    }
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|v| v.to_string())
        .map_err(|e| e.to_string())
}

pub(crate) fn password_matches(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

pub(crate) fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn token_hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) async fn bootstrap(
    pool: &PgPool,
    config: &Config,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE is_system_admin)")
            .fetch_one(pool)
            .await?;
    if exists {
        return Ok(());
    }
    if config.bootstrap.password.is_empty() {
        return Err(
            "bootstrap password is required on first startup; set CRABOUNCER_BOOTSTRAP_PASSWORD"
                .into(),
        );
    }
    let hash = password_hash(&config.bootstrap.password)?;
    let mut tx = pool.begin().await?;
    let organization_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name, display_name) VALUES ($1, $2, $3)")
        .bind(organization_id)
        .bind(&config.bootstrap.organization)
        .bind(&config.bootstrap.organization)
        .execute(&mut *tx)
        .await?;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, organization_id, email, display_name, role, status, is_system_admin) VALUES ($1, $2, $3, $4, 'owner', 'active', true)")
        .bind(user_id).bind(organization_id).bind(config.bootstrap.email.to_lowercase()).bind(&config.bootstrap.display_name).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(email = %config.bootstrap.email, "created bootstrap administrator");
    Ok(())
}
