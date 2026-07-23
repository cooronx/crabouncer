use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AuditEvent, Database, Group, Result, audit};

#[derive(Clone, Serialize, sqlx::FromRow)]
pub(crate) struct ApplicationRole {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) key: String,
    pub(crate) display_name: String,
    pub(crate) enabled: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

pub(crate) struct NewApplicationRole {
    pub(crate) id: Uuid,
    pub(crate) application_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) key: String,
    pub(crate) display_name: String,
    pub(crate) actor_user_id: Uuid,
}

pub(crate) struct UpdateApplicationRole {
    pub(crate) id: Uuid,
    pub(crate) display_name: Option<String>,
    pub(crate) enabled: Option<bool>,
    pub(crate) actor_user_id: Uuid,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct ApplicationRoleAssignment {
    pub(crate) target_type: String,
    pub(crate) target_id: Uuid,
    pub(crate) target_key: String,
    pub(crate) target_display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group_kind: Option<String>,
    pub(crate) target_active: bool,
    pub(crate) created_at: OffsetDateTime,
}

#[derive(Serialize)]
pub(crate) struct EffectiveRole {
    pub(crate) id: Uuid,
    pub(crate) key: String,
    pub(crate) display_name: String,
    pub(crate) sources: Vec<EffectiveRoleSource>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct EffectiveRoleSource {
    #[serde(rename = "type")]
    pub(crate) source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group_key: Option<String>,
}

#[derive(sqlx::FromRow)]
struct EffectiveRoleRow {
    id: Uuid,
    key: String,
    display_name: String,
    source_type: String,
    group_id: Option<Uuid>,
    group_key: Option<String>,
}

struct AssignmentRemoval {
    action: &'static str,
    target_type: &'static str,
    target_id: Uuid,
    statement: &'static str,
    details: Value,
}

impl Database {
    pub(crate) async fn application_has_role_assignments(
        &self,
        application_id: Uuid,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1
                FROM application_roles role
                WHERE role.application_id = $1
                  AND (
                    EXISTS (
                        SELECT 1
                        FROM application_role_user_assignments assignment
                        WHERE assignment.role_id = role.id
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM application_role_group_assignments assignment
                        WHERE assignment.role_id = role.id
                    )
                  )
            )",
        )
        .bind(application_id)
        .fetch_one(&self.pool)
        .await?)
    }

    pub(crate) async fn missing_application_role_keys(
        &self,
        application_id: Uuid,
        keys: &[String],
    ) -> Result<Vec<String>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let existing: BTreeSet<String> = sqlx::query_scalar(
            "SELECT key FROM application_roles WHERE application_id = $1 AND key = ANY($2::text[])",
        )
        .bind(application_id)
        .bind(keys)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .collect();
        Ok(keys
            .iter()
            .filter(|key| !existing.contains(*key))
            .cloned()
            .collect())
    }

    pub(crate) async fn application_role(&self, id: Uuid) -> Result<Option<ApplicationRole>> {
        Ok(sqlx::query_as(
            "SELECT id, application_id, organization_id, key, display_name, enabled, created_at, updated_at FROM application_roles WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub(crate) async fn application_roles(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<ApplicationRole>> {
        Ok(sqlx::query_as(
            "SELECT id, application_id, organization_id, key, display_name, enabled, created_at, updated_at FROM application_roles WHERE application_id = $1 ORDER BY key",
        )
        .bind(application_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn create_application_role(
        &self,
        new_role: NewApplicationRole,
    ) -> Result<ApplicationRole> {
        let mut tx = self.pool.begin().await?;
        let role: ApplicationRole = sqlx::query_as(
            "INSERT INTO application_roles (id, application_id, organization_id, key, display_name) VALUES ($1, $2, $3, $4, $5) RETURNING id, application_id, organization_id, key, display_name, enabled, created_at, updated_at",
        )
        .bind(new_role.id)
        .bind(new_role.application_id)
        .bind(new_role.organization_id)
        .bind(new_role.key)
        .bind(new_role.display_name)
        .fetch_one(&mut *tx)
        .await?;
        audit::insert(
            &mut tx,
            role_audit_event(
                &role,
                new_role.actor_user_id,
                "application_role.create",
                json!({}),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(role)
    }

    pub(crate) async fn update_application_role(
        &self,
        update: UpdateApplicationRole,
    ) -> Result<Option<ApplicationRole>> {
        let mut tx = self.pool.begin().await?;
        let Some(current): Option<ApplicationRole> = sqlx::query_as(
            "SELECT id, application_id, organization_id, key, display_name, enabled, created_at, updated_at FROM application_roles WHERE id = $1 FOR UPDATE",
        )
        .bind(update.id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let display_name = update
            .display_name
            .unwrap_or_else(|| current.display_name.clone());
        let enabled = update.enabled.unwrap_or(current.enabled);
        let display_name_changed = display_name != current.display_name;
        let enabled_changed = enabled != current.enabled;
        if !display_name_changed && !enabled_changed {
            tx.commit().await?;
            return Ok(Some(current));
        }

        let role: ApplicationRole = sqlx::query_as(
            "UPDATE application_roles SET display_name = $2, enabled = $3, updated_at = now() WHERE id = $1 RETURNING id, application_id, organization_id, key, display_name, enabled, created_at, updated_at",
        )
        .bind(update.id)
        .bind(display_name)
        .bind(enabled)
        .fetch_one(&mut *tx)
        .await?;
        if display_name_changed {
            audit::insert(
                &mut tx,
                role_audit_event(
                    &role,
                    update.actor_user_id,
                    "application_role.update",
                    json!({
                        "previous_display_name": current.display_name,
                        "display_name": role.display_name,
                    }),
                ),
            )
            .await?;
        }
        if enabled_changed {
            audit::insert(
                &mut tx,
                role_audit_event(
                    &role,
                    update.actor_user_id,
                    if role.enabled {
                        "application_role.enable"
                    } else {
                        "application_role.disable"
                    },
                    json!({ "enabled": role.enabled }),
                ),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(role))
    }

    pub(crate) async fn application_role_assignments(
        &self,
        role_id: Uuid,
    ) -> Result<Vec<ApplicationRoleAssignment>> {
        Ok(sqlx::query_as(
            "SELECT 'user'::text AS target_type, u.id AS target_id, u.email AS target_key, u.display_name AS target_display_name, NULL::text AS group_kind, u.status = 'active' AS target_active, a.created_at
             FROM application_role_user_assignments a
             JOIN users u ON u.id = a.user_id
             WHERE a.role_id = $1
             UNION ALL
             SELECT 'group'::text AS target_type, g.id AS target_id, g.key AS target_key, g.display_name AS target_display_name, g.kind::text AS group_kind, g.enabled AS target_active, a.created_at
             FROM application_role_group_assignments a
             JOIN groups g ON g.id = a.group_id
             WHERE a.role_id = $1
             ORDER BY target_type, target_key",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn assign_role_to_user(
        &self,
        role: &ApplicationRole,
        user_id: Uuid,
        actor_user_id: Uuid,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO application_role_user_assignments (role_id, user_id, organization_id)
             SELECT $1, u.id, $2 FROM users u
             WHERE u.id = $3 AND u.organization_id = $2
             ON CONFLICT (role_id, user_id) DO NOTHING",
        )
        .bind(role.id)
        .bind(role.organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            audit::insert(
                &mut tx,
                assignment_audit_event(
                    role,
                    actor_user_id,
                    "application_role_user.assign",
                    "user",
                    user_id,
                    Value::Null,
                ),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub(crate) async fn unassign_role_from_user(
        &self,
        role: &ApplicationRole,
        user_id: Uuid,
        actor_user_id: Uuid,
    ) -> Result<bool> {
        self.remove_assignment(
            role,
            actor_user_id,
            AssignmentRemoval {
                action: "application_role_user.unassign",
                target_type: "user",
                target_id: user_id,
                statement:
                    "DELETE FROM application_role_user_assignments WHERE role_id = $1 AND user_id = $2",
                details: Value::Null,
            },
        )
        .await
    }

    pub(crate) async fn assign_role_to_group(
        &self,
        role: &ApplicationRole,
        group: &Group,
        actor_user_id: Uuid,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO application_role_group_assignments (role_id, group_id, organization_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (role_id, group_id) DO NOTHING",
        )
        .bind(role.id)
        .bind(group.id)
        .bind(role.organization_id)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            audit::insert(
                &mut tx,
                assignment_audit_event(
                    role,
                    actor_user_id,
                    "application_role_group.assign",
                    "group",
                    group.id,
                    json!({ "group_key": group.key, "group_kind": group.kind }),
                ),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub(crate) async fn unassign_role_from_group(
        &self,
        role: &ApplicationRole,
        group: &Group,
        actor_user_id: Uuid,
    ) -> Result<bool> {
        self.remove_assignment(
            role,
            actor_user_id,
            AssignmentRemoval {
                action: "application_role_group.unassign",
                target_type: "group",
                target_id: group.id,
                statement:
                    "DELETE FROM application_role_group_assignments WHERE role_id = $1 AND group_id = $2",
                details: json!({ "group_key": group.key, "group_kind": group.kind }),
            },
        )
        .await
    }

    pub(crate) async fn effective_roles(
        &self,
        application_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<EffectiveRole>> {
        let rows: Vec<EffectiveRoleRow> = sqlx::query_as(
            "SELECT r.id, r.key, r.display_name, 'direct'::text AS source_type, NULL::uuid AS group_id, NULL::text AS group_key
             FROM application_role_user_assignments a
             JOIN application_roles r ON r.id = a.role_id
             JOIN users u ON u.id = a.user_id
             WHERE r.application_id = $1 AND u.id = $2 AND u.status = 'active' AND r.enabled
             UNION ALL
             SELECT r.id, r.key, r.display_name, (g.kind::text || '_group') AS source_type, g.id AS group_id, g.key AS group_key
             FROM group_memberships m
             JOIN groups g ON g.id = m.group_id
             JOIN application_role_group_assignments a ON a.group_id = g.id
             JOIN application_roles r ON r.id = a.role_id
             JOIN users u ON u.id = m.user_id
             WHERE r.application_id = $1 AND u.id = $2 AND u.status = 'active' AND g.enabled AND r.enabled
             ORDER BY key, source_type, group_key",
        )
        .bind(application_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(aggregate_effective_roles(rows))
    }

    async fn remove_assignment(
        &self,
        role: &ApplicationRole,
        actor_user_id: Uuid,
        removal: AssignmentRemoval,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(removal.statement)
            .bind(role.id)
            .bind(removal.target_id)
            .execute(&mut *tx)
            .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            audit::insert(
                &mut tx,
                assignment_audit_event(
                    role,
                    actor_user_id,
                    removal.action,
                    removal.target_type,
                    removal.target_id,
                    removal.details,
                ),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }
}

fn aggregate_effective_roles(rows: Vec<EffectiveRoleRow>) -> Vec<EffectiveRole> {
    let mut roles = BTreeMap::<String, EffectiveRole>::new();
    for row in rows {
        let role = roles
            .entry(row.key.clone())
            .or_insert_with(|| EffectiveRole {
                id: row.id,
                key: row.key,
                display_name: row.display_name,
                sources: Vec::new(),
            });
        role.sources.push(EffectiveRoleSource {
            source_type: row.source_type,
            group_id: row.group_id,
            group_key: row.group_key,
        });
    }
    for role in roles.values_mut() {
        role.sources.sort();
        role.sources.dedup();
    }
    roles.into_values().collect()
}

fn role_audit_event(
    role: &ApplicationRole,
    actor_user_id: Uuid,
    action: &str,
    changes: Value,
) -> AuditEvent {
    AuditEvent {
        organization_id: Some(role.organization_id),
        actor_user_id,
        action: action.into(),
        target_type: "application_role".into(),
        target_id: Some(role.id.to_string()),
        details: json!({
            "organization_id": role.organization_id,
            "application_id": role.application_id,
            "role_id": role.id,
            "role_key": role.key,
            "changes": changes,
        }),
    }
}

fn assignment_audit_event(
    role: &ApplicationRole,
    actor_user_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: Uuid,
    target_details: Value,
) -> AuditEvent {
    AuditEvent {
        organization_id: Some(role.organization_id),
        actor_user_id,
        action: action.into(),
        target_type: "application_role_assignment".into(),
        target_id: Some(format!("{}:{target_type}:{target_id}", role.id)),
        details: json!({
            "organization_id": role.organization_id,
            "application_id": role.application_id,
            "role_id": role.id,
            "role_key": role.key,
            "target_type": target_type,
            "target_id": target_id,
            "target": target_details,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_roles_are_deduplicated_with_stable_sources() {
        let role_id = Uuid::now_v7();
        let group_id = Uuid::now_v7();
        let rows = vec![
            EffectiveRoleRow {
                id: role_id,
                key: "reader".into(),
                display_name: "Reader".into(),
                source_type: "virtual_group".into(),
                group_id: Some(group_id),
                group_key: Some("research".into()),
            },
            EffectiveRoleRow {
                id: role_id,
                key: "reader".into(),
                display_name: "Reader".into(),
                source_type: "direct".into(),
                group_id: None,
                group_key: None,
            },
        ];
        let roles = aggregate_effective_roles(rows);
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].sources.len(), 2);
        assert_eq!(roles[0].sources[0].source_type, "direct");
    }
}
