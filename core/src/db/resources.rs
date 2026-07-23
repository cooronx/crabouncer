use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::{Database, Result};

#[derive(Clone, sqlx::FromRow)]
pub(crate) struct StoredResource {
    pub(crate) resource_type: String,
    pub(crate) resource_id: String,
    pub(crate) properties: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResourceWriteStatus {
    Upserted,
    Unchanged,
}

impl Database {
    pub(crate) async fn upsert_resource(
        &self,
        application_id: Uuid,
        resource_type: &str,
        resource_id: &str,
        properties: &Value,
    ) -> Result<ResourceWriteStatus> {
        let changed: bool = sqlx::query_scalar(
            "WITH existing AS (
                SELECT properties
                FROM application_resources
                WHERE application_id = $1 AND resource_type = $2 AND resource_id = $3
            ),
            written AS (
                INSERT INTO application_resources (
                    application_id, resource_type, resource_id, properties
                )
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (application_id, resource_type, resource_id)
                DO UPDATE SET properties = EXCLUDED.properties, updated_at = now()
                WHERE application_resources.properties IS DISTINCT FROM EXCLUDED.properties
                RETURNING 1
            )
            SELECT EXISTS(SELECT 1 FROM written)
                OR NOT EXISTS(SELECT 1 FROM existing)",
        )
        .bind(application_id)
        .bind(resource_type)
        .bind(resource_id)
        .bind(properties)
        .fetch_one(&self.pool)
        .await?;
        Ok(if changed {
            ResourceWriteStatus::Upserted
        } else {
            ResourceWriteStatus::Unchanged
        })
    }

    pub(crate) async fn delete_resource(
        &self,
        application_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM application_resources
             WHERE application_id = $1 AND resource_type = $2 AND resource_id = $3",
        )
        .bind(application_id)
        .bind(resource_type)
        .bind(resource_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub(crate) async fn all_resources(&self, application_id: Uuid) -> Result<Vec<StoredResource>> {
        Ok(sqlx::query_as(
            "SELECT resource_type, resource_id, properties
             FROM application_resources
             WHERE application_id = $1
             ORDER BY resource_type, resource_id",
        )
        .bind(application_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn resources_after(
        &self,
        application_id: Uuid,
        resource_type: &str,
        after_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredResource>> {
        Ok(sqlx::query_as(
            "SELECT resource_type, resource_id, properties
             FROM application_resources
             WHERE application_id = $1
               AND resource_type = $2
               AND resource_id > $3
             ORDER BY resource_id
             LIMIT $4",
        )
        .bind(application_id)
        .bind(resource_type)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}
