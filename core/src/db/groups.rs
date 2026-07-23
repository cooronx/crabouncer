use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AuditEvent, Database, Result, audit};

#[derive(Clone, Serialize, sqlx::FromRow)]
pub(crate) struct Group {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) key: String,
    pub(crate) display_name: String,
    pub(crate) kind: String,
    pub(crate) enabled: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct GroupMember {
    pub(crate) user_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) membership_created_at: OffsetDateTime,
}

pub(crate) struct NewGroup {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) key: String,
    pub(crate) display_name: String,
    pub(crate) kind: String,
    pub(crate) actor_user_id: Uuid,
}

pub(crate) struct UpdateGroup {
    pub(crate) id: Uuid,
    pub(crate) display_name: Option<String>,
    pub(crate) enabled: Option<bool>,
    pub(crate) actor_user_id: Uuid,
}

impl Database {
    pub(crate) async fn group(&self, id: Uuid) -> Result<Option<Group>> {
        Ok(sqlx::query_as(
            "SELECT id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at FROM groups WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub(crate) async fn groups(&self, organization_id: Uuid) -> Result<Vec<Group>> {
        Ok(sqlx::query_as(
            "SELECT id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at FROM groups WHERE organization_id = $1 ORDER BY key",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn create_group(&self, new_group: NewGroup) -> Result<Group> {
        let mut tx = self.pool.begin().await?;
        let group: Group = sqlx::query_as(
            "INSERT INTO groups (id, organization_id, key, display_name, kind) VALUES ($1, $2, $3, $4, $5::group_kind) RETURNING id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at",
        )
        .bind(new_group.id)
        .bind(new_group.organization_id)
        .bind(new_group.key)
        .bind(new_group.display_name)
        .bind(new_group.kind)
        .fetch_one(&mut *tx)
        .await?;
        audit::insert(
            &mut tx,
            AuditEvent {
                organization_id: Some(group.organization_id),
                actor_user_id: new_group.actor_user_id,
                action: "group.create".into(),
                target_type: "group".into(),
                target_id: Some(group.id.to_string()),
                details: json!({
                    "organization_id": group.organization_id,
                    "group_id": group.id,
                    "group_key": group.key,
                    "kind": group.kind,
                }),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(group)
    }

    pub(crate) async fn update_group(&self, update: UpdateGroup) -> Result<Option<Group>> {
        let mut tx = self.pool.begin().await?;
        let Some(current): Option<Group> = sqlx::query_as(
            "SELECT id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at FROM groups WHERE id = $1 FOR UPDATE",
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

        let group: Group = sqlx::query_as(
            "UPDATE groups SET display_name = $2, enabled = $3, updated_at = now() WHERE id = $1 RETURNING id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at",
        )
        .bind(update.id)
        .bind(display_name)
        .bind(enabled)
        .fetch_one(&mut *tx)
        .await?;

        if display_name_changed {
            audit::insert(
                &mut tx,
                group_audit_event(
                    &group,
                    update.actor_user_id,
                    "group.update",
                    json!({
                        "previous_display_name": current.display_name,
                        "display_name": group.display_name,
                    }),
                ),
            )
            .await?;
        }
        if enabled_changed {
            let action = if group.enabled {
                "group.enable"
            } else {
                "group.disable"
            };
            audit::insert(
                &mut tx,
                group_audit_event(
                    &group,
                    update.actor_user_id,
                    action,
                    json!({ "enabled": group.enabled }),
                ),
            )
            .await?;
        }

        tx.commit().await?;
        Ok(Some(group))
    }

    pub(crate) async fn group_members(&self, group_id: Uuid) -> Result<Vec<GroupMember>> {
        Ok(sqlx::query_as(
            "SELECT u.id AS user_id, u.email, u.display_name, u.role::text AS role, u.status::text AS status, m.created_at AS membership_created_at FROM group_memberships m JOIN users u ON u.id = m.user_id WHERE m.group_id = $1 ORDER BY u.email",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn user_groups(&self, user_id: Uuid) -> Result<Vec<Group>> {
        Ok(sqlx::query_as(
            "SELECT g.id, g.organization_id, g.key, g.display_name, g.kind::text AS kind, g.enabled, g.created_at, g.updated_at FROM group_memberships m JOIN groups g ON g.id = m.group_id WHERE m.user_id = $1 ORDER BY g.kind, g.key",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub(crate) async fn physical_group_for_user(&self, user_id: Uuid) -> Result<Option<Group>> {
        Ok(sqlx::query_as(
            "SELECT g.id, g.organization_id, g.key, g.display_name, g.kind::text AS kind, g.enabled, g.created_at, g.updated_at FROM group_memberships m JOIN groups g ON g.id = m.group_id WHERE m.user_id = $1 AND m.group_kind = 'physical'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub(crate) async fn add_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        actor_user_id: Uuid,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let Some(group): Option<Group> = sqlx::query_as(
            "SELECT id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at FROM groups WHERE id = $1 FOR SHARE",
        )
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(false);
        };

        let result = sqlx::query(
            "INSERT INTO group_memberships (organization_id, group_id, user_id, group_kind) SELECT g.organization_id, g.id, u.id, g.kind FROM groups g JOIN users u ON u.organization_id = g.organization_id WHERE g.id = $1 AND u.id = $2 ON CONFLICT (group_id, user_id) DO NOTHING",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        let added = result.rows_affected() == 1;

        if added {
            audit::insert(
                &mut tx,
                group_member_audit_event(&group, user_id, actor_user_id, "group_member.add"),
            )
            .await?;
        }

        tx.commit().await?;
        Ok(added)
    }

    pub(crate) async fn remove_group_member(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        actor_user_id: Uuid,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let Some(group): Option<Group> = sqlx::query_as(
            "SELECT id, organization_id, key, display_name, kind::text AS kind, enabled, created_at, updated_at FROM groups WHERE id = $1 FOR SHARE",
        )
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(false);
        };

        let result =
            sqlx::query("DELETE FROM group_memberships WHERE group_id = $1 AND user_id = $2")
                .bind(group_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        let removed = result.rows_affected() == 1;

        if removed {
            audit::insert(
                &mut tx,
                group_member_audit_event(&group, user_id, actor_user_id, "group_member.remove"),
            )
            .await?;
        }

        tx.commit().await?;
        Ok(removed)
    }
}

fn group_audit_event(
    group: &Group,
    actor_user_id: Uuid,
    action: &str,
    changes: serde_json::Value,
) -> AuditEvent {
    AuditEvent {
        organization_id: Some(group.organization_id),
        actor_user_id,
        action: action.into(),
        target_type: "group".into(),
        target_id: Some(group.id.to_string()),
        details: json!({
            "organization_id": group.organization_id,
            "group_id": group.id,
            "group_key": group.key,
            "kind": group.kind,
            "changes": changes,
        }),
    }
}

fn group_member_audit_event(
    group: &Group,
    user_id: Uuid,
    actor_user_id: Uuid,
    action: &str,
) -> AuditEvent {
    AuditEvent {
        organization_id: Some(group.organization_id),
        actor_user_id,
        action: action.into(),
        target_type: "group_member".into(),
        target_id: Some(format!("{}:{user_id}", group.id)),
        details: json!({
            "organization_id": group.organization_id,
            "group_id": group.id,
            "group_key": group.key,
            "group_kind": group.kind,
            "user_id": user_id,
        }),
    }
}
