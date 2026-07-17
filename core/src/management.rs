use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use cookie::{Cookie, SameSite};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    db::{
        ActivationToken, Actor, Application, AuditEvent, LoginUser, NewApplication,
        NewOrganization, NewPolicyRelease, NewServiceAccount, NewServiceSecret, NewSession,
        NewUser, Organization, PolicyReleaseResult, PolicySnapshot, Release, ServiceAccount,
        UpdateApplication as DatabaseUpdateApplication,
        UpdateOrganization as DatabaseUpdateOrganization, UpdateUser as DatabaseUpdateUser,
        UpdateWorkspace as DatabaseUpdateWorkspace, User, UserAccess, Workspace,
    },
    error::{ApiError, Result},
    policy, security,
};

const SESSION_COOKIE: &str = "crabouncer_session";

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/session", post(login).delete(logout))
        .route("/api/v1/session/me", get(me))
        .route("/api/v1/activations/{token}", post(activate))
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
        .route("/api/v1/users/{id}", axum::routing::patch(update_user))
        .route(
            "/api/v1/organizations/{id}/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/api/v1/applications/{id}",
            get(get_application).patch(update_application),
        )
        .route(
            "/api/v1/applications/{id}/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route(
            "/api/v1/service-accounts/{id}/secrets",
            post(create_service_secret),
        )
        .route(
            "/api/v1/service-secrets/{id}",
            axum::routing::delete(revoke_service_secret),
        )
        .route(
            "/api/v1/applications/{id}/workspace",
            get(get_workspace).put(update_workspace),
        )
        .route(
            "/api/v1/applications/{id}/workspace/validate",
            post(validate_workspace),
        )
        .route(
            "/api/v1/applications/{id}/workspace/simulate",
            post(simulate_workspace),
        )
        .route(
            "/api/v1/applications/{id}/releases",
            get(list_releases).post(publish_release),
        )
        .route(
            "/api/v1/applications/{id}/releases/{release_id}/activate",
            post(activate_release),
        )
        .route(
            "/api/v1/organizations/{id}/decision-logs",
            get(list_decision_logs),
        )
        .route(
            "/api/v1/organizations/{id}/audit-logs",
            get(list_audit_logs),
        )
}

pub(crate) async fn actor(state: &AppState, headers: &HeaderMap, mutation: bool) -> Result<Actor> {
    let token = cookie_value(headers, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
    let session_hash = security::token_hash(&token);
    let current = state
        .db
        .actor(session_hash)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if mutation {
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::forbidden)?;
        if security::token_hash(csrf) != current.csrf_hash {
            return Err(ApiError::forbidden());
        }
    }
    Ok(current)
}

pub(crate) fn can_manage(current: &Actor, organization_id: Uuid) -> Result<()> {
    if current.is_system_admin
        || (current.organization_id == organization_id
            && matches!(current.role.as_str(), "owner" | "admin"))
    {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

fn can_view(current: &Actor, organization_id: Uuid) -> Result<()> {
    if current.is_system_admin || current.organization_id == organization_id {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

fn owner_or_system(current: &Actor, organization_id: Uuid) -> Result<()> {
    if current.is_system_admin
        || (current.organization_id == organization_id && current.role == "owner")
    {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> Result<impl axum::response::IntoResponse> {
    let email = body.email.trim().to_lowercase();
    let user: Option<LoginUser> = state.db.login_user(&email).await?;
    let Some(user) = user else {
        return Err(ApiError::unauthorized());
    };
    if !security::password_matches(&body.password, &user.password_hash) {
        return Err(ApiError::unauthorized());
    }
    let session = security::random_token();
    let csrf = security::random_token();
    let expires =
        OffsetDateTime::now_utc() + Duration::seconds(state.config.tokens.session_ttl_seconds);
    state
        .db
        .create_session(NewSession {
            token_hash: security::token_hash(&session),
            csrf_hash: security::token_hash(&csrf),
            user_id: user.id,
            expires_at: expires,
            ip: client_ip(&headers).map(str::to_owned),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        })
        .await?;
    let cookie = Cookie::build((SESSION_COOKIE, session))
        .path("/")
        .http_only(true)
        .secure(state.config.server.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(
            state.config.tokens.session_ttl_seconds,
        ))
        .build();
    Ok((
        [(header::SET_COOKIE, cookie.to_string())],
        Json(json!({ "csrf_token": csrf })),
    ))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl axum::response::IntoResponse> {
    let current = actor(&state, &headers, true).await?;
    state.db.delete_session(current.session_hash).await?;
    let cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .secure(state.config.server.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::ZERO)
        .build();
    Ok((
        [(header::SET_COOKIE, cookie.to_string())],
        StatusCode::NO_CONTENT,
    ))
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<Actor>> {
    Ok(Json(actor(&state, &headers, false).await?))
}

#[derive(Deserialize)]
struct Activate {
    password: String,
}
async fn activate(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    Json(body): Json<Activate>,
) -> Result<StatusCode> {
    let hash = security::password_hash(&body.password).map_err(ApiError::bad_request)?;
    state
        .db
        .activate_user(security::token_hash(&token), hash)
        .await?
        .ok_or_else(|| ApiError::bad_request("activation token is invalid or expired"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_organizations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Organization>>> {
    let current = actor(&state, &headers, false).await?;
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
    headers: HeaderMap,
    Json(body): Json<CreateOrganization>,
) -> Result<(StatusCode, Json<Value>)> {
    let current = actor(&state, &headers, true).await?;
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    validate_name(&body.name, "name")?;
    validate_name(&body.display_name, "display_name")?;
    validate_email(&body.owner_email)?;
    let org_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let token = security::random_token();
    state
        .db
        .create_organization(NewOrganization {
            id: org_id,
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
                organization_id: Some(org_id),
                actor_user_id: current.id,
                action: "organization.create".into(),
                target_type: "organization".into(),
                target_id: Some(org_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "organization_id": org_id, "owner_id": user_id, "activation_url": activation_url(&state, &token) }),
        ),
    ))
}
async fn get_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Organization>> {
    can_view(&actor(&state, &headers, false).await?, id)?;
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
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateOrganization>,
) -> Result<Json<Organization>> {
    let current = actor(&state, &headers, true).await?;
    owner_or_system(&current, id)?;
    if body
        .status
        .as_deref()
        .is_some_and(|v| !matches!(v, "active" | "disabled"))
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
    get_organization(State(state), headers, Path(id)).await
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<User>>> {
    can_view(&actor(&state, &headers, false).await?, id)?;
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
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<Value>)> {
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, id)?;
    validate_email(&body.email)?;
    validate_role(&body.role)?;
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
        Json(json!({ "user_id": user_id, "activation_url": activation_url(&state, &token) })),
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
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUser>,
) -> Result<StatusCode> {
    let access: UserAccess = state
        .db
        .user_access(id)
        .await?
        .ok_or_else(|| ApiError::not_found("User"))?;
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, access.organization_id)?;
    if access.role == "owner" {
        owner_or_system(&current, access.organization_id)?;
    }
    if let Some(role) = &body.role {
        validate_role(role)?;
        if role == "owner" {
            owner_or_system(&current, access.organization_id)?;
        }
    }
    if body
        .status
        .as_deref()
        .is_some_and(|v| !matches!(v, "active" | "disabled"))
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

pub(crate) async fn load_application(state: &AppState, id: Uuid) -> Result<Application> {
    state
        .db
        .application(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Application"))
}
async fn list_applications(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Application>>> {
    can_view(&actor(&state, &headers, false).await?, id)?;
    Ok(Json(state.db.applications(id).await?))
}
#[derive(Deserialize)]
struct ApplicationInput {
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
}
async fn create_application(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ApplicationInput>,
) -> Result<(StatusCode, Json<Application>)> {
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, id)?;
    validate_application(&body)?;
    let app_id = Uuid::now_v7();
    let client_id = format!("app_{}", security::random_token());
    state
        .db
        .create_application(NewApplication {
            id: app_id,
            organization_id: id,
            name: body.name.trim().into(),
            client_id,
            redirect_uris: json!(body.redirect_uris),
            allowed_scopes: json!(body.allowed_scopes),
            audit: AuditEvent {
                organization_id: Some(id),
                actor_user_id: current.id,
                action: "application.create".into(),
                target_type: "application".into(),
                target_id: Some(app_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(load_application(&state, app_id).await?),
    ))
}
async fn get_application(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Application>> {
    let app = load_application(&state, id).await?;
    can_view(&actor(&state, &headers, false).await?, app.organization_id)?;
    Ok(Json(app))
}
#[derive(Deserialize)]
struct UpdateApplication {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    enabled: Option<bool>,
}
async fn update_application(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateApplication>,
) -> Result<StatusCode> {
    let app = load_application(&state, id).await?;
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, app.organization_id)?;
    if let Some(scopes) = &body.allowed_scopes {
        validate_scopes(scopes)?;
    }
    if let Some(uris) = &body.redirect_uris {
        validate_redirects(uris)?;
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
        Some(app.organization_id),
        "application.update",
        "application",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_service_accounts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ServiceAccount>>> {
    let app = load_application(&state, id).await?;
    can_view(&actor(&state, &headers, false).await?, app.organization_id)?;
    Ok(Json(state.db.service_accounts(id).await?))
}
#[derive(Deserialize)]
struct CreateServiceAccount {
    name: String,
    scopes: Vec<String>,
}
async fn create_service_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateServiceAccount>,
) -> Result<(StatusCode, Json<Value>)> {
    let app = load_application(&state, id).await?;
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, app.organization_id)?;
    validate_service_scopes(&body.scopes)?;
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
        Some(app.organization_id),
        "service_account.create",
        "service_account",
        account_id,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": account_id, "client_id": client_id, "client_secret": secret, "secret_id": secret_id }),
        ),
    ))
}
async fn service_account_org(state: &AppState, id: Uuid) -> Result<Uuid> {
    state
        .db
        .service_account_organization(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Service account"))
}
async fn create_service_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>)> {
    let org = service_account_org(&state, id).await?;
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, org)?;
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
        Some(org),
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
async fn revoke_service_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let org = state
        .db
        .service_secret_organization(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Secret"))?;
    let current = actor(&state, &headers, true).await?;
    can_manage(&current, org)?;
    state.db.revoke_service_secret(id).await?;
    audit_event(
        &state,
        &current,
        Some(org),
        "service_secret.revoke",
        "service_secret",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize_app(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    mutation: bool,
) -> Result<(Actor, Application)> {
    let app = load_application(state, id).await?;
    let current = actor(state, headers, mutation).await?;
    if mutation {
        can_manage(&current, app.organization_id)?;
    } else {
        can_view(&current, app.organization_id)?;
    }
    Ok((current, app))
}
async fn get_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Workspace>> {
    authorize_app(&state, &headers, id, false).await?;
    Ok(Json(state.db.workspace(id).await?))
}
#[derive(Deserialize)]
struct WorkspaceInput {
    schema_source: String,
    policies: Value,
    entities: Value,
}
async fn update_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<WorkspaceInput>,
) -> Result<StatusCode> {
    let (current, app) = authorize_app(&state, &headers, id, true).await?;
    if !body.policies.is_array() || !body.entities.is_array() {
        return Err(ApiError::bad_request(
            "policies and entities must be arrays",
        ));
    }
    state
        .db
        .update_workspace(DatabaseUpdateWorkspace {
            application_id: id,
            schema_source: body.schema_source,
            policies: body.policies,
            entities: body.entities,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(app.organization_id),
        "policy_workspace.update",
        "application",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn validate_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    authorize_app(&state, &headers, id, false).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    policy::validate_workspace(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
    )?;
    Ok(Json(json!({ "valid": true })))
}
async fn simulate_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<authzen_rs::EvaluationRequest>,
) -> Result<Json<Value>> {
    let (_, app) = authorize_app(&state, &headers, id, false).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    Ok(Json(policy::evaluate(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
        &request,
        app.organization_id,
        None,
    )?))
}
async fn list_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Release>>> {
    authorize_app(&state, &headers, id, false).await?;
    Ok(Json(state.db.releases(id).await?))
}
async fn publish_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>)> {
    let (current, app) = authorize_app(&state, &headers, id, true).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    policy::validate_workspace(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
    )?;
    let release_id = Uuid::now_v7();
    let release: PolicyReleaseResult = state
        .db
        .publish_policy_release(NewPolicyRelease {
            id: release_id,
            application_id: id,
            created_by: current.id,
            snapshot,
            audit: AuditEvent {
                organization_id: Some(app.organization_id),
                actor_user_id: current.id,
                action: "policy_release.publish".into(),
                target_type: "policy_release".into(),
                target_id: Some(release_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": release.id, "version": release.version, "active": true })),
    ))
}
async fn activate_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, release_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let (current, app) = authorize_app(&state, &headers, id, true).await?;
    if !state
        .db
        .activate_policy_release(id, release_id, current.id)
        .await?
    {
        return Err(ApiError::not_found("Release"));
    }
    audit_event(
        &state,
        &current,
        Some(app.organization_id),
        "policy_release.activate",
        "policy_release",
        release_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct LogQuery {
    limit: Option<i64>,
}
async fn list_decision_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<Value>>> {
    can_view(&actor(&state, &headers, false).await?, id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let rows = state.db.decision_logs(id, limit).await?;
    Ok(Json(rows))
}
async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<Value>>> {
    can_view(&actor(&state, &headers, false).await?, id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let rows = state.db.audit_logs(id, limit).await?;
    Ok(Json(rows))
}

async fn audit_event(
    state: &AppState,
    current: &Actor,
    organization_id: Option<Uuid>,
    action: &str,
    target_type: &str,
    target_id: Uuid,
) -> Result<()> {
    state
        .db
        .record_audit(AuditEvent {
            organization_id,
            actor_user_id: current.id,
            action: action.into(),
            target_type: target_type.into(),
            target_id: Some(target_id.to_string()),
            details: json!({}),
        })
        .await?;
    Ok(())
}
fn activation_url(state: &AppState, token: &str) -> String {
    format!(
        "{}/activate/{}",
        state.config.server.web_url.trim_end_matches('/'),
        token
    )
}
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| Cookie::parse(part.trim()).ok())
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.value().to_owned())
}
fn client_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
}
fn validate_name(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(ApiError::bad_request(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}
fn validate_email(value: &str) -> Result<()> {
    let value = value.trim();
    if value.contains('@') && !value.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err(ApiError::bad_request("email is invalid"))
    }
}
fn validate_role(value: &str) -> Result<()> {
    if matches!(value, "owner" | "admin" | "member") {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "role must be owner, admin, or member",
        ))
    }
}
fn validate_redirects(values: &[String]) -> Result<()> {
    for value in values {
        let url = url::Url::parse(value)
            .map_err(|_| ApiError::bad_request("redirect URI must be absolute"))?;
        if url.fragment().is_some() {
            return Err(ApiError::bad_request(
                "redirect URI must not contain a fragment",
            ));
        }
    }
    Ok(())
}
fn validate_scopes(values: &[String]) -> Result<()> {
    if values.iter().all(|v| {
        matches!(
            v.as_str(),
            "openid" | "profile" | "email" | "offline_access"
        )
    }) {
        Ok(())
    } else {
        Err(ApiError::bad_request("unsupported OIDC scope"))
    }
}
fn validate_service_scopes(values: &[String]) -> Result<()> {
    if values.iter().all(|v| v == "authzen:evaluate")
        && values.iter().any(|v| v == "authzen:evaluate")
    {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "service account requires authzen:evaluate scope",
        ))
    }
}
fn validate_application(body: &ApplicationInput) -> Result<()> {
    validate_name(&body.name, "name")?;
    validate_redirects(&body.redirect_uris)?;
    validate_scopes(&body.allowed_scopes)
}
