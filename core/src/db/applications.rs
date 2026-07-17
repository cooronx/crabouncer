use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AuditEvent, Database, Result, audit};

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct Application {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) name: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uris: Value,
    pub(crate) allowed_scopes: Value,
    pub(crate) enabled: bool,
    pub(crate) created_at: OffsetDateTime,
}

pub(crate) struct NewApplication {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) name: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uris: Value,
    pub(crate) allowed_scopes: Value,
    pub(crate) audit: AuditEvent,
}

pub(crate) struct UpdateApplication {
    pub(crate) id: Uuid,
    pub(crate) name: Option<String>,
    pub(crate) redirect_uris: Option<Value>,
    pub(crate) allowed_scopes: Option<Value>,
    pub(crate) enabled: Option<bool>,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct ServiceAccount {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) name: String,
    pub(crate) client_id: String,
    pub(crate) scopes: Value,
    pub(crate) enabled: bool,
    pub(crate) created_at: OffsetDateTime,
}

pub(crate) struct NewServiceAccount {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) name: String,
    pub(crate) client_id: String,
    pub(crate) scopes: Value,
    pub(crate) secret_id: Uuid,
    pub(crate) secret_hash: String,
}

pub(crate) struct NewServiceSecret {
    pub(crate) id: Uuid,
    pub(crate) service_account_id: Uuid,
    pub(crate) secret_hash: String,
}

impl Database {
    pub(crate) async fn application(&self, id: Uuid) -> Result<Option<Application>> {
        Ok(sqlx::query_as("SELECT id, organization_id, name, client_id, redirect_uris, allowed_scopes, enabled, created_at FROM applications WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn applications(&self, organization_id: Uuid) -> Result<Vec<Application>> {
        Ok(sqlx::query_as("SELECT id, organization_id, name, client_id, redirect_uris, allowed_scopes, enabled, created_at FROM applications WHERE organization_id = $1 ORDER BY created_at")
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub(crate) async fn create_application(&self, application: NewApplication) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO applications (id, organization_id, name, client_id, redirect_uris, allowed_scopes) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(application.id)
            .bind(application.organization_id)
            .bind(application.name)
            .bind(application.client_id)
            .bind(application.redirect_uris)
            .bind(application.allowed_scopes)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO policy_workspaces (application_id) VALUES ($1)")
            .bind(application.id)
            .execute(&mut *tx)
            .await?;
        audit::insert(&mut tx, application.audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn update_application(&self, application: UpdateApplication) -> Result<()> {
        sqlx::query("UPDATE applications SET name = COALESCE($2, name), redirect_uris = COALESCE($3, redirect_uris), allowed_scopes = COALESCE($4, allowed_scopes), enabled = COALESCE($5, enabled), updated_at = now() WHERE id = $1")
            .bind(application.id)
            .bind(application.name)
            .bind(application.redirect_uris)
            .bind(application.allowed_scopes)
            .bind(application.enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn service_accounts(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<ServiceAccount>> {
        Ok(sqlx::query_as("SELECT id, application_id, name, client_id, scopes, enabled, created_at FROM service_accounts WHERE application_id = $1 ORDER BY created_at")
            .bind(application_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub(crate) async fn create_service_account(&self, account: NewServiceAccount) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO service_accounts (id, application_id, name, client_id, scopes) VALUES ($1, $2, $3, $4, $5)")
            .bind(account.id)
            .bind(account.application_id)
            .bind(account.name)
            .bind(account.client_id)
            .bind(account.scopes)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO service_account_secrets (id, service_account_id, secret_hash) VALUES ($1, $2, $3)")
            .bind(account.secret_id)
            .bind(account.id)
            .bind(account.secret_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn service_account_organization(&self, id: Uuid) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar("SELECT a.organization_id FROM service_accounts s JOIN applications a ON a.id = s.application_id WHERE s.id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn create_service_secret(&self, secret: NewServiceSecret) -> Result<()> {
        sqlx::query("INSERT INTO service_account_secrets (id, service_account_id, secret_hash) VALUES ($1, $2, $3)")
            .bind(secret.id)
            .bind(secret.service_account_id)
            .bind(secret.secret_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn service_secret_organization(&self, id: Uuid) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar("SELECT a.organization_id FROM service_account_secrets k JOIN service_accounts s ON s.id = k.service_account_id JOIN applications a ON a.id = s.application_id WHERE k.id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn revoke_service_secret(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE service_account_secrets SET revoked_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
