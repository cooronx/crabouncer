use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{Database, Result};

pub(crate) struct AuditEvent {
    pub(crate) organization_id: Option<Uuid>,
    pub(crate) actor_user_id: Uuid,
    pub(crate) action: String,
    pub(crate) target_type: String,
    pub(crate) target_id: Option<String>,
    pub(crate) details: Value,
}

pub(super) async fn insert(tx: &mut Transaction<'_, Postgres>, event: AuditEvent) -> Result<()> {
    sqlx::query("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(Uuid::now_v7())
        .bind(event.organization_id)
        .bind(event.actor_user_id)
        .bind(event.action)
        .bind(event.target_type)
        .bind(event.target_id)
        .bind(event.details)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Database {
    pub(crate) async fn record_audit(&self, event: AuditEvent) -> Result<()> {
        sqlx::query("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(Uuid::now_v7())
            .bind(event.organization_id)
            .bind(event.actor_user_id)
            .bind(event.action)
            .bind(event.target_type)
            .bind(event.target_id)
            .bind(event.details)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn decision_logs(
        &self,
        organization_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT to_jsonb(d) FROM (SELECT id, application_id, service_account_id, request_id, request, decision, reason, diagnostics, duration_us, created_at FROM decision_logs WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2) d")
            .bind(organization_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    pub(crate) async fn audit_logs(&self, organization_id: Uuid, limit: i64) -> Result<Vec<Value>> {
        Ok(sqlx::query_scalar("SELECT to_jsonb(a) FROM (SELECT id, actor_user_id, action, target_type, target_id, details, created_at FROM audit_logs WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2) a")
            .bind(organization_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }
}
