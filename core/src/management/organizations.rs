use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, patch},
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    db::{
        ActivationToken, Actor, AuditEvent, NewOrganization, NewUser, Organization,
        UpdateOrganization as DatabaseUpdateOrganization, UpdateUser as DatabaseUpdateUser, User,
        UserAccess,
    },
    error::{ApiError, Result},
    security,
};

use super::{
    access::{audit_event, can_manage, can_view, owner_or_system},
    validation,
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/organizations",
            get(list_organizations).post(create_organization),
        )
        .route(
            "/api/v1/organizations/{id}",
            get(get_organization).patch(update_organization),
        )
        .route(
            "/api/v1/organizations/{id}/users",
            get(list_users).post(create_user),
        )
        .route("/api/v1/users/{id}", patch(update_user))
}

async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
) -> Result<Json<Vec<Organization>>> {
    let rows = state
        .db
        .organizations_for(current.organization_id, current.is_system_admin)
        .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct CreateOrganization {
    name: String,
    display_name: String,
    owner_email: String,
    owner_display_name: String,
}

async fn create_organization(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Json(body): Json<CreateOrganization>,
) -> Result<(StatusCode, Json<Value>)> {
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    validation::name(&body.name, "name")?;
    validation::name(&body.display_name, "display_name")?;
    validation::email(&body.owner_email)?;
    let organization_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let token = security::random_token();
    state
        .db
        .create_organization(NewOrganization {
            id: organization_id,
            name: body.name.trim().into(),
            display_name: body.display_name.trim().into(),
            owner_id: user_id,
            owner_email: body.owner_email.trim().to_lowercase(),
            owner_display_name: body.owner_display_name.trim().into(),
            activation: ActivationToken {
                hash: security::token_hash(&token),
                expires_at: OffsetDateTime::now_utc()
                    + Duration::seconds(state.config.tokens.activation_ttl_seconds),
            },
            audit: AuditEvent {
                organization_id: Some(organization_id),
                actor_user_id: current.id,
                action: "organization.create".into(),
                target_type: "organization".into(),
                target_id: Some(organization_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "organization_id": organization_id,
            "owner_id": user_id,
            "activation_url": activation_url(&state, &token),
        })),
    ))
}

async fn get_organization(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Organization>> {
    can_view(&current, id)?;
    Ok(Json(
        state
            .db
            .organization(id)
            .await?
            .ok_or_else(|| ApiError::not_found("Organization"))?,
    ))
}

#[derive(Deserialize)]
struct UpdateOrganization {
    display_name: Option<String>,
    status: Option<String>,
}

async fn update_organization(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateOrganization>,
) -> Result<Json<Organization>> {
    owner_or_system(&current, id)?;
    if body
        .status
        .as_deref()
        .is_some_and(|value| !matches!(value, "active" | "disabled"))
    {
        return Err(ApiError::bad_request("status must be active or disabled"));
    }
    state
        .db
        .update_organization(DatabaseUpdateOrganization {
            id,
            display_name: body.display_name.map(|value| value.trim().into()),
            status: body.status,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(id),
        "organization.update",
        "organization",
        id,
    )
    .await?;
    get_organization(State(state), Extension(current), Path(id)).await
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<User>>> {
    can_view(&current, id)?;
    Ok(Json(state.db.users(id).await?))
}

#[derive(Deserialize)]
struct CreateUser {
    email: String,
    display_name: String,
    role: String,
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<Value>)> {
    can_manage(&current, id)?;
    validation::email(&body.email)?;
    validation::role(&body.role)?;
    if body.role == "owner" {
        owner_or_system(&current, id)?;
    }
    let user_id = Uuid::now_v7();
    let token = security::random_token();
    state
        .db
        .create_user(NewUser {
            id: user_id,
            organization_id: id,
            email: body.email.trim().to_lowercase(),
            display_name: body.display_name.trim().into(),
            role: body.role,
            activation: ActivationToken {
                hash: security::token_hash(&token),
                expires_at: OffsetDateTime::now_utc()
                    + Duration::seconds(state.config.tokens.activation_ttl_seconds),
            },
            audit: AuditEvent {
                organization_id: Some(id),
                actor_user_id: current.id,
                action: "user.create".into(),
                target_type: "user".into(),
                target_id: Some(user_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "user_id": user_id,
            "activation_url": activation_url(&state, &token),
        })),
    ))
}

#[derive(Deserialize)]
struct UpdateUser {
    display_name: Option<String>,
    role: Option<String>,
    status: Option<String>,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUser>,
) -> Result<StatusCode> {
    let access: UserAccess = state
        .db
        .user_access(id)
        .await?
        .ok_or_else(|| ApiError::not_found("User"))?;
    can_manage(&current, access.organization_id)?;
    if access.role == "owner" {
        owner_or_system(&current, access.organization_id)?;
    }
    if let Some(role) = &body.role {
        validation::role(role)?;
        if role == "owner" {
            owner_or_system(&current, access.organization_id)?;
        }
    }
    if body
        .status
        .as_deref()
        .is_some_and(|value| !matches!(value, "active" | "disabled"))
    {
        return Err(ApiError::bad_request("status must be active or disabled"));
    }
    state
        .db
        .update_user(DatabaseUpdateUser {
            id,
            display_name: body.display_name.map(|value| value.trim().into()),
            role: body.role,
            status: body.status,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(access.organization_id),
        "user.update",
        "user",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn activation_url(state: &AppState, token: &str) -> String {
    format!(
        "{}/activate/{}",
        state.config.server.web_url.trim_end_matches('/'),
        token
    )
}
