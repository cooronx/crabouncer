use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AuditEvent, Database, Result, audit};

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct Workspace {
    pub(crate) application_id: Uuid,
    pub(crate) schema_source: String,
    pub(crate) policies: Value,
    pub(crate) entities: Value,
    pub(crate) updated_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
pub(crate) struct PolicySnapshot {
    pub(crate) schema_source: String,
    pub(crate) policies: Value,
    pub(crate) entities: Value,
}

pub(crate) struct UpdateWorkspace {
    pub(crate) application_id: Uuid,
    pub(crate) schema_source: String,
    pub(crate) policies: Value,
    pub(crate) entities: Value,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct Release {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) version: i64,
    pub(crate) created_by: Uuid,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) active: bool,
}

pub(crate) struct NewPolicyRelease {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) created_by: Uuid,
    pub(crate) snapshot: PolicySnapshot,
    pub(crate) audit: AuditEvent,
}

pub(crate) struct PolicyReleaseResult {
    pub(crate) id: Uuid,
    pub(crate) version: i64,
}

impl Database {
    pub(crate) async fn workspace(&self, application_id: Uuid) -> Result<Workspace> {
        Ok(sqlx::query_as("SELECT application_id, schema_source, policies, entities, updated_at FROM policy_workspaces WHERE application_id = $1")
            .bind(application_id)
            .fetch_one(&self.pool)
            .await?)
    }

    pub(crate) async fn policy_snapshot(&self, application_id: Uuid) -> Result<PolicySnapshot> {
        Ok(sqlx::query_as("SELECT schema_source, policies, entities FROM policy_workspaces WHERE application_id = $1")
            .bind(application_id)
            .fetch_one(&self.pool)
            .await?)
    }

    pub(crate) async fn update_workspace(&self, workspace: UpdateWorkspace) -> Result<()> {
        sqlx::query("UPDATE policy_workspaces SET schema_source = $2, policies = $3, entities = $4, updated_at = now() WHERE application_id = $1")
            .bind(workspace.application_id)
            .bind(workspace.schema_source)
            .bind(workspace.policies)
            .bind(workspace.entities)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn releases(&self, application_id: Uuid) -> Result<Vec<Release>> {
        Ok(sqlx::query_as("SELECT r.id, r.application_id, r.version, r.created_by, r.created_at, ar.release_id IS NOT NULL AS active FROM policy_releases r LEFT JOIN active_policy_releases ar ON ar.release_id = r.id WHERE r.application_id = $1 ORDER BY r.version DESC")
            .bind(application_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub(crate) async fn publish_policy_release(
        &self,
        release: NewPolicyRelease,
    ) -> Result<PolicyReleaseResult> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
            .bind(release.application_id)
            .execute(&mut *tx)
            .await?;
        let version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max(version), 0) + 1 FROM policy_releases WHERE application_id = $1",
        )
        .bind(release.application_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO policy_releases (id, application_id, version, schema_source, policies, entities, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(release.id)
            .bind(release.application_id)
            .bind(version)
            .bind(release.snapshot.schema_source)
            .bind(release.snapshot.policies)
            .bind(release.snapshot.entities)
            .bind(release.created_by)
            .execute(&mut *tx)
            .await?;
        activate_release(
            &mut tx,
            release.application_id,
            release.id,
            release.created_by,
        )
        .await?;
        let mut event = release.audit;
        event.details = json!({ "version": version });
        audit::insert(&mut tx, event).await?;
        tx.commit().await?;
        Ok(PolicyReleaseResult {
            id: release.id,
            version,
        })
    }

    pub(crate) async fn activate_policy_release(
        &self,
        application_id: Uuid,
        release_id: Uuid,
        actor_id: Uuid,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM policy_releases WHERE id = $1 AND application_id = $2)",
        )
        .bind(release_id)
        .bind(application_id)
        .fetch_one(&self.pool)
        .await?;
        if !exists {
            return Ok(false);
        }
        sqlx::query("INSERT INTO active_policy_releases (application_id, release_id, activated_by) VALUES ($1, $2, $3) ON CONFLICT (application_id) DO UPDATE SET release_id = EXCLUDED.release_id, activated_by = EXCLUDED.activated_by, activated_at = now()")
            .bind(application_id)
            .bind(release_id)
            .bind(actor_id)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }
}

async fn activate_release(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    application_id: Uuid,
    release_id: Uuid,
    actor_id: Uuid,
) -> Result<()> {
    sqlx::query("INSERT INTO active_policy_releases (application_id, release_id, activated_by) VALUES ($1, $2, $3) ON CONFLICT (application_id) DO UPDATE SET release_id = EXCLUDED.release_id, activated_by = EXCLUDED.activated_by, activated_at = now()")
        .bind(application_id)
        .bind(release_id)
        .bind(actor_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
