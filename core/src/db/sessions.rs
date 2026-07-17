use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Database, Result};

#[derive(Clone, Serialize, sqlx::FromRow)]
pub(crate) struct Actor {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) role: String,
    pub(crate) is_system_admin: bool,
    #[serde(skip)]
    pub(crate) csrf_hash: Vec<u8>,
    #[serde(skip)]
    pub(crate) session_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct LoginUser {
    pub(crate) id: Uuid,
    pub(crate) password_hash: String,
}

pub(crate) struct NewSession {
    pub(crate) token_hash: Vec<u8>,
    pub(crate) csrf_hash: Vec<u8>,
    pub(crate) user_id: Uuid,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) ip: Option<String>,
    pub(crate) user_agent: Option<String>,
}

impl Database {
    pub(crate) async fn actor(&self, session_hash: Vec<u8>) -> Result<Option<Actor>> {
        Ok(sqlx::query_as("SELECT u.id, u.organization_id, u.email, u.display_name, u.role::text AS role, u.is_system_admin, s.csrf_hash, s.token_hash AS session_hash FROM sessions s JOIN users u ON u.id = s.user_id JOIN organizations o ON o.id = u.organization_id WHERE s.token_hash = $1 AND s.expires_at > now() AND u.status = 'active' AND o.status = 'active'")
            .bind(session_hash)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn login_user(&self, email: &str) -> Result<Option<LoginUser>> {
        Ok(sqlx::query_as("SELECT u.id, p.password_hash FROM users u JOIN password_credentials p ON p.user_id = u.id JOIN organizations o ON o.id = u.organization_id WHERE u.email = $1 AND u.status = 'active' AND o.status = 'active'")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn create_session(&self, session: NewSession) -> Result<()> {
        sqlx::query("INSERT INTO sessions (token_hash, csrf_hash, user_id, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5::inet, $6)")
            .bind(session.token_hash)
            .bind(session.csrf_hash)
            .bind(session.user_id)
            .bind(session.expires_at)
            .bind(session.ip)
            .bind(session.user_agent)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn delete_session(&self, token_hash: Vec<u8>) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn activate_user(
        &self,
        token_hash: Vec<u8>,
        password_hash: String,
    ) -> Result<Option<Uuid>> {
        let mut tx = self.pool.begin().await?;
        let Some(user_id): Option<Uuid> = sqlx::query_scalar("UPDATE activation_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id")
            .bind(token_hash)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Ok(None);
        };
        sqlx::query("INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = now()")
            .bind(user_id)
            .bind(password_hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE users SET status = 'active', updated_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(user_id))
    }
}
