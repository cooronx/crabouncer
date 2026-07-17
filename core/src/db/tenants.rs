use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AuditEvent, Database, Result, audit};

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct Organization {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) status: String,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct User {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) is_system_admin: bool,
    pub(crate) created_at: OffsetDateTime,
}

pub(crate) struct ActivationToken {
    pub(crate) hash: Vec<u8>,
    pub(crate) expires_at: OffsetDateTime,
}

pub(crate) struct NewOrganization {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) owner_id: Uuid,
    pub(crate) owner_email: String,
    pub(crate) owner_display_name: String,
    pub(crate) activation: ActivationToken,
    pub(crate) audit: AuditEvent,
}

pub(crate) struct UpdateOrganization {
    pub(crate) id: Uuid,
    pub(crate) display_name: Option<String>,
    pub(crate) status: Option<String>,
}

pub(crate) struct NewUser {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) role: String,
    pub(crate) activation: ActivationToken,
    pub(crate) audit: AuditEvent,
}

#[derive(sqlx::FromRow)]
pub(crate) struct UserAccess {
    pub(crate) organization_id: Uuid,
    pub(crate) role: String,
}

pub(crate) struct UpdateUser {
    pub(crate) id: Uuid,
    pub(crate) display_name: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) status: Option<String>,
}

impl Database {
    pub(crate) async fn organizations_for(
        &self,
        organization_id: Uuid,
        system_admin: bool,
    ) -> Result<Vec<Organization>> {
        if system_admin {
            Ok(sqlx::query_as("SELECT id, name, display_name, status::text AS status, created_at, updated_at FROM organizations ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?)
        } else {
            Ok(sqlx::query_as("SELECT id, name, display_name, status::text AS status, created_at, updated_at FROM organizations WHERE id = $1")
                .bind(organization_id)
                .fetch_all(&self.pool)
                .await?)
        }
    }

    pub(crate) async fn organization(&self, id: Uuid) -> Result<Option<Organization>> {
        Ok(sqlx::query_as("SELECT id, name, display_name, status::text AS status, created_at, updated_at FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn create_organization(&self, organization: NewOrganization) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO organizations (id, name, display_name) VALUES ($1, $2, $3)")
            .bind(organization.id)
            .bind(organization.name)
            .bind(organization.display_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO users (id, organization_id, email, display_name, role) VALUES ($1, $2, $3, $4, 'owner')")
            .bind(organization.owner_id)
            .bind(organization.id)
            .bind(organization.owner_email)
            .bind(organization.owner_display_name)
            .execute(&mut *tx)
            .await?;
        insert_activation(&mut tx, organization.owner_id, organization.activation).await?;
        audit::insert(&mut tx, organization.audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn update_organization(&self, organization: UpdateOrganization) -> Result<()> {
        sqlx::query("UPDATE organizations SET display_name = COALESCE($2, display_name), status = COALESCE($3::organization_status, status), updated_at = now() WHERE id = $1")
            .bind(organization.id)
            .bind(organization.display_name)
            .bind(organization.status)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn users(&self, organization_id: Uuid) -> Result<Vec<User>> {
        Ok(sqlx::query_as("SELECT id, organization_id, email, display_name, role::text AS role, status::text AS status, is_system_admin, created_at FROM users WHERE organization_id = $1 ORDER BY created_at")
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub(crate) async fn create_user(&self, user: NewUser) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO users (id, organization_id, email, display_name, role) VALUES ($1, $2, $3, $4, $5::organization_role)")
            .bind(user.id)
            .bind(user.organization_id)
            .bind(user.email)
            .bind(user.display_name)
            .bind(user.role)
            .execute(&mut *tx)
            .await?;
        insert_activation(&mut tx, user.id, user.activation).await?;
        audit::insert(&mut tx, user.audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn user_access(&self, id: Uuid) -> Result<Option<UserAccess>> {
        Ok(
            sqlx::query_as("SELECT organization_id, role::text AS role FROM users WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub(crate) async fn update_user(&self, user: UpdateUser) -> Result<()> {
        sqlx::query("UPDATE users SET display_name = COALESCE($2, display_name), role = COALESCE($3::organization_role, role), status = COALESCE($4::user_status, status), updated_at = now() WHERE id = $1")
            .bind(user.id)
            .bind(user.display_name)
            .bind(user.role)
            .bind(user.status.as_deref())
            .execute(&self.pool)
            .await?;
        if user.status.as_deref() == Some("disabled") {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(user.id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}

async fn insert_activation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    activation: ActivationToken,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO activation_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(activation.hash)
    .bind(user_id)
    .bind(activation.expires_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
