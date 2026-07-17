use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Database, Result};

#[derive(sqlx::FromRow)]
pub(crate) struct AuthorizationApp {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) redirect_uris: Value,
    pub(crate) allowed_scopes: Value,
}

pub(crate) struct AuthorizationCode {
    pub(crate) code_hash: Vec<u8>,
    pub(crate) application_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) redirect_uri: String,
    pub(crate) scope: String,
    pub(crate) code_challenge: String,
    pub(crate) nonce: Option<String>,
    pub(crate) expires_at: OffsetDateTime,
}

pub(crate) struct AuthorizationCodeExchange {
    pub(crate) code_hash: Vec<u8>,
    pub(crate) redirect_uri: String,
    pub(crate) code_challenge: String,
    pub(crate) refresh_hash: Vec<u8>,
    pub(crate) refresh_family_id: Uuid,
    pub(crate) refresh_expires_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct AuthorizationCodeRow {
    application_id: Uuid,
    user_id: Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    nonce: Option<String>,
    client_id: String,
    organization_id: Uuid,
}

pub(crate) struct UserGrant {
    pub(crate) user_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) client_id: String,
    pub(crate) scope: String,
    pub(crate) nonce: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    family_id: Uuid,
    application_id: Uuid,
    user_id: Uuid,
    scope: String,
    consumed_at: Option<OffsetDateTime>,
    client_id: String,
    organization_id: Uuid,
}

pub(crate) enum RefreshRotation {
    Missing,
    Reused,
    Rotated(UserGrant),
}

#[derive(sqlx::FromRow)]
pub(crate) struct ServiceCredential {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) client_id: String,
    pub(crate) scopes: Value,
    pub(crate) secret_hash: String,
    pub(crate) organization_id: Uuid,
}

#[derive(sqlx::FromRow)]
pub(crate) struct UserProfile {
    pub(crate) email: String,
    pub(crate) display_name: String,
}

impl Database {
    pub(crate) async fn authorization_app(
        &self,
        client_id: &str,
    ) -> Result<Option<AuthorizationApp>> {
        Ok(sqlx::query_as("SELECT id, organization_id, redirect_uris, allowed_scopes FROM applications WHERE client_id = $1 AND enabled")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn store_authorization_code(&self, code: AuthorizationCode) -> Result<()> {
        sqlx::query("INSERT INTO oauth_authorization_codes (code_hash, application_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
            .bind(code.code_hash)
            .bind(code.application_id)
            .bind(code.user_id)
            .bind(code.redirect_uri)
            .bind(code.scope)
            .bind(code.code_challenge)
            .bind(code.nonce)
            .bind(code.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn exchange_authorization_code(
        &self,
        exchange: AuthorizationCodeExchange,
    ) -> Result<Option<UserGrant>> {
        let mut tx = self.pool.begin().await?;
        let Some(row): Option<AuthorizationCodeRow> = sqlx::query_as("UPDATE oauth_authorization_codes c SET consumed_at = now() FROM applications a WHERE c.application_id = a.id AND c.code_hash = $1 AND c.consumed_at IS NULL AND c.expires_at > now() RETURNING c.application_id, c.user_id, c.redirect_uri, c.scope, c.code_challenge, c.nonce, a.client_id, a.organization_id")
            .bind(exchange.code_hash)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Ok(None);
        };
        if row.redirect_uri != exchange.redirect_uri
            || row.code_challenge != exchange.code_challenge
        {
            return Ok(None);
        }
        sqlx::query("INSERT INTO oauth_refresh_tokens (token_hash, family_id, application_id, user_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(exchange.refresh_hash)
            .bind(exchange.refresh_family_id)
            .bind(row.application_id)
            .bind(row.user_id)
            .bind(&row.scope)
            .bind(exchange.refresh_expires_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(UserGrant {
            user_id: row.user_id,
            organization_id: row.organization_id,
            client_id: row.client_id,
            scope: row.scope,
            nonce: row.nonce,
        }))
    }

    pub(crate) async fn rotate_refresh_token(
        &self,
        old_hash: Vec<u8>,
        fresh_hash: Vec<u8>,
        fresh_expires_at: OffsetDateTime,
    ) -> Result<RefreshRotation> {
        let mut tx = self.pool.begin().await?;
        let Some(row): Option<RefreshTokenRow> = sqlx::query_as("SELECT r.family_id, r.application_id, r.user_id, r.scope, r.consumed_at, a.client_id, a.organization_id FROM oauth_refresh_tokens r JOIN applications a ON a.id = r.application_id JOIN users u ON u.id = r.user_id JOIN organizations o ON o.id = u.organization_id WHERE r.token_hash = $1 AND r.revoked_at IS NULL AND r.expires_at > now() AND u.status = 'active' AND o.status = 'active' AND a.enabled FOR UPDATE OF r")
            .bind(&old_hash)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Ok(RefreshRotation::Missing);
        };
        if row.consumed_at.is_some() {
            sqlx::query("UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE family_id = $1")
                .bind(row.family_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(RefreshRotation::Reused);
        }
        sqlx::query("UPDATE oauth_refresh_tokens SET consumed_at = now() WHERE token_hash = $1")
            .bind(old_hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO oauth_refresh_tokens (token_hash, family_id, application_id, user_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(fresh_hash)
            .bind(row.family_id)
            .bind(row.application_id)
            .bind(row.user_id)
            .bind(&row.scope)
            .bind(fresh_expires_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(RefreshRotation::Rotated(UserGrant {
            user_id: row.user_id,
            organization_id: row.organization_id,
            client_id: row.client_id,
            scope: row.scope,
            nonce: None,
        }))
    }

    pub(crate) async fn service_credentials(
        &self,
        client_id: &str,
    ) -> Result<Vec<ServiceCredential>> {
        Ok(sqlx::query_as("SELECT s.id, s.application_id, s.client_id, s.scopes, k.secret_hash, a.organization_id FROM service_accounts s JOIN service_account_secrets k ON k.service_account_id = s.id JOIN applications a ON a.id = s.application_id JOIN organizations o ON o.id = a.organization_id WHERE s.client_id = $1 AND s.enabled AND a.enabled AND o.status = 'active' AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())")
            .bind(client_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub(crate) async fn active_user_profile(&self, user_id: Uuid) -> Result<Option<UserProfile>> {
        Ok(sqlx::query_as(
            "SELECT email, display_name FROM users WHERE id = $1 AND status = 'active'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub(crate) async fn delete_session(&self, token_hash: Vec<u8>) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
