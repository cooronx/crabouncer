use serde_json::Value;
use uuid::Uuid;

use super::{Database, Result};

#[derive(Clone, sqlx::FromRow)]
pub(crate) struct AuthzenCaller {
    pub(crate) service_account_id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) organization_id: Uuid,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SubjectAttributes {
    pub(crate) email: String,
    pub(crate) role: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct SearchSubject {
    pub(crate) id: Uuid,
    pub(crate) email: String,
    pub(crate) role: String,
}

#[derive(Clone, sqlx::FromRow)]
pub(crate) struct PolicyRelease {
    pub(crate) id: Uuid,
    pub(crate) schema_source: String,
    pub(crate) policies: Value,
    pub(crate) entities: Value,
}

pub(crate) struct DecisionLog {
    pub(crate) organization_id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) service_account_id: Uuid,
    pub(crate) request_id: String,
    pub(crate) request: Value,
    pub(crate) decision: bool,
    pub(crate) reason: String,
    pub(crate) diagnostics: Value,
    pub(crate) duration_us: i64,
    pub(crate) retention_days: i64,
}

pub(crate) struct SearchLog {
    pub(crate) organization_id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) service_account_id: Uuid,
    pub(crate) request_id: String,
    pub(crate) search_kind: &'static str,
    pub(crate) query: Value,
    pub(crate) release_id: Option<Uuid>,
    pub(crate) evaluated_count: usize,
    pub(crate) result_count: usize,
    pub(crate) result_ids: Value,
    pub(crate) duration_us: i64,
    pub(crate) outcome: &'static str,
    pub(crate) error: Option<String>,
    pub(crate) retention_days: i64,
}

impl Database {
    pub(crate) async fn authzen_caller(
        &self,
        service_account_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<AuthzenCaller>> {
        Ok(sqlx::query_as("SELECT s.id AS service_account_id, a.id AS application_id, a.organization_id FROM service_accounts s JOIN applications a ON a.id = s.application_id JOIN organizations o ON o.id = a.organization_id WHERE s.id = $1 AND a.id = $2 AND s.enabled AND a.enabled AND o.status = 'active'")
            .bind(service_account_id)
            .bind(application_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn active_subject_attributes(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<SubjectAttributes>> {
        Ok(sqlx::query_as("SELECT email, role::text AS role FROM users WHERE id = $1 AND organization_id = $2 AND status = 'active'")
            .bind(user_id)
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn active_subjects_after(
        &self,
        organization_id: Uuid,
        after_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<SearchSubject>> {
        Ok(sqlx::query_as(
            "SELECT id, email, role::text AS role
             FROM users
             WHERE organization_id = $1
               AND status = 'active'
               AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id
             LIMIT $3",
        )
        .bind(organization_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn active_policy_release(
        &self,
        application_id: Uuid,
    ) -> Result<Option<PolicyRelease>> {
        Ok(sqlx::query_as("SELECT r.id, r.schema_source, r.policies, r.entities FROM active_policy_releases ar JOIN policy_releases r ON r.id = ar.release_id WHERE ar.application_id = $1")
            .bind(application_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub(crate) async fn policy_release(
        &self,
        application_id: Uuid,
        release_id: Uuid,
    ) -> Result<Option<PolicyRelease>> {
        Ok(sqlx::query_as(
            "SELECT id, schema_source, policies, entities
             FROM policy_releases
             WHERE application_id = $1 AND id = $2",
        )
        .bind(application_id)
        .bind(release_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub(crate) async fn record_decision(&self, log: DecisionLog) -> Result<()> {
        sqlx::query("INSERT INTO decision_logs (id, organization_id, application_id, service_account_id, request_id, request, decision, reason, diagnostics, duration_us) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
            .bind(Uuid::now_v7())
            .bind(log.organization_id)
            .bind(log.application_id)
            .bind(log.service_account_id)
            .bind(log.request_id)
            .bind(log.request)
            .bind(log.decision)
            .bind(log.reason)
            .bind(log.diagnostics)
            .bind(log.duration_us)
            .execute(&self.pool)
            .await?;
        let _ = sqlx::query(
            "DELETE FROM decision_logs WHERE created_at < now() - make_interval(days => $1)",
        )
        .bind(log.retention_days as i32)
        .execute(&self.pool)
        .await;
        Ok(())
    }

    pub(crate) async fn record_search(&self, log: SearchLog) -> Result<()> {
        sqlx::query(
            "INSERT INTO search_logs (
                id, organization_id, application_id, service_account_id,
                request_id, search_kind, query, release_id, evaluated_count,
                result_count, result_ids, duration_us, outcome, error
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(Uuid::now_v7())
        .bind(log.organization_id)
        .bind(log.application_id)
        .bind(log.service_account_id)
        .bind(log.request_id)
        .bind(log.search_kind)
        .bind(log.query)
        .bind(log.release_id)
        .bind(log.evaluated_count as i32)
        .bind(log.result_count as i32)
        .bind(log.result_ids)
        .bind(log.duration_us)
        .bind(log.outcome)
        .bind(log.error)
        .execute(&self.pool)
        .await?;
        let _ = sqlx::query(
            "DELETE FROM search_logs WHERE created_at < now() - make_interval(days => $1)",
        )
        .bind(log.retention_days as i32)
        .execute(&self.pool)
        .await;
        Ok(())
    }
}
