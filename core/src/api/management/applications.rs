use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    db::{
        Actor, Application, NewApplication, NewServiceAccount, NewServiceSecret, ServiceAccount,
        UpdateApplication as DatabaseUpdateApplication,
    },
    error::{ApiError, Result},
    security,
};

use super::{
    access::{audit_event, can_manage, can_view},
    validation,
};

pub(super) async fn load_application(state: &AppState, id: Uuid) -> Result<Application> {
    state
        .db
        .application(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Application"))
}

pub(super) async fn view_application(
    state: &AppState,
    current: &Actor,
    id: Uuid,
) -> Result<Application> {
    let application = load_application(state, id).await?;
    can_view(current, application.organization_id)?;
    Ok(application)
}

pub(super) async fn manage_application(
    state: &AppState,
    current: &Actor,
    id: Uuid,
) -> Result<Application> {
    let application = load_application(state, id).await?;
    can_manage(current, application.organization_id)?;
    Ok(application)
}

pub(super) async fn list_applications(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Application>>> {
    can_view(&current, id)?;
    Ok(Json(state.db.applications(id).await?))
}

#[derive(Deserialize)]
pub(super) struct ApplicationInput {
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
}

pub(super) async fn create_application(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApplicationInput>,
) -> Result<(StatusCode, Json<Application>)> {
    can_manage(&current, id)?;
    validate_application(&body)?;
    let application_id = Uuid::now_v7();
    let client_id = format!("app_{}", security::random_token());
    state
        .db
        .create_application(NewApplication {
            id: application_id,
            organization_id: id,
            name: body.name.trim().into(),
            client_id,
            redirect_uris: json!(body.redirect_uris),
            allowed_scopes: json!(body.allowed_scopes),
            audit: crate::db::AuditEvent {
                organization_id: Some(id),
                actor_user_id: current.id,
                action: "application.create".into(),
                target_type: "application".into(),
                target_id: Some(application_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(load_application(&state, application_id).await?),
    ))
}

pub(super) async fn get_application(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Application>> {
    let application = load_application(&state, id).await?;
    can_view(&current, application.organization_id)?;
    Ok(Json(application))
}

#[derive(Deserialize)]
pub(super) struct UpdateApplication {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    enabled: Option<bool>,
}

pub(super) async fn update_application(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateApplication>,
) -> Result<StatusCode> {
    let application = load_application(&state, id).await?;
    can_manage(&current, application.organization_id)?;
    if let Some(scopes) = &body.allowed_scopes {
        validation::oidc_scopes(scopes)?;
    }
    if let Some(redirect_uris) = &body.redirect_uris {
        validation::redirects(redirect_uris)?;
    }
    state
        .db
        .update_application(DatabaseUpdateApplication {
            id,
            name: body.name.map(|value| value.trim().into()),
            redirect_uris: body.redirect_uris.map(|value| json!(value)),
            allowed_scopes: body.allowed_scopes.map(|value| json!(value)),
            enabled: body.enabled,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(application.organization_id),
        "application.update",
        "application",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn list_service_accounts(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ServiceAccount>>> {
    let application = load_application(&state, id).await?;
    can_view(&current, application.organization_id)?;
    Ok(Json(state.db.service_accounts(id).await?))
}

#[derive(Deserialize)]
pub(super) struct CreateServiceAccount {
    name: String,
    scopes: Vec<String>,
}

pub(super) async fn create_service_account(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateServiceAccount>,
) -> Result<(StatusCode, Json<Value>)> {
    let application = load_application(&state, id).await?;
    can_manage(&current, application.organization_id)?;
    validation::service_scopes(&body.scopes)?;
    let account_id = Uuid::now_v7();
    let client_id = format!("svc_{}", security::random_token());
    let secret = security::random_token();
    let secret_id = Uuid::now_v7();
    let hash = security::password_hash(&secret).map_err(ApiError::bad_request)?;
    state
        .db
        .create_service_account(NewServiceAccount {
            id: account_id,
            application_id: id,
            name: body.name.trim().into(),
            client_id: client_id.clone(),
            scopes: json!(body.scopes),
            secret_id,
            secret_hash: hash,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(application.organization_id),
        "service_account.create",
        "service_account",
        account_id,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": account_id,
            "client_id": client_id,
            "client_secret": secret,
            "secret_id": secret_id,
        })),
    ))
}

async fn service_account_organization(state: &AppState, id: Uuid) -> Result<Uuid> {
    state
        .db
        .service_account_organization(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Service account"))
}

pub(super) async fn create_service_secret(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>)> {
    let organization_id = service_account_organization(&state, id).await?;
    can_manage(&current, organization_id)?;
    let secret = security::random_token();
    let secret_id = Uuid::now_v7();
    let hash = security::password_hash(&secret).map_err(ApiError::bad_request)?;
    state
        .db
        .create_service_secret(NewServiceSecret {
            id: secret_id,
            service_account_id: id,
            secret_hash: hash,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(organization_id),
        "service_secret.create",
        "service_account",
        id,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "secret_id": secret_id, "client_secret": secret })),
    ))
}

pub(super) async fn revoke_service_secret(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let organization_id = state
        .db
        .service_secret_organization(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Secret"))?;
    can_manage(&current, organization_id)?;
    state.db.revoke_service_secret(id).await?;
    audit_event(
        &state,
        &current,
        Some(organization_id),
        "service_secret.revoke",
        "service_secret",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_application(body: &ApplicationInput) -> Result<()> {
    validation::name(&body.name, "name")?;
    validation::redirects(&body.redirect_uris)?;
    validation::oidc_scopes(&body.allowed_scopes)
}
