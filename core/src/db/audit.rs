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
}
