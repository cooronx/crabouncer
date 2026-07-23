mod access;
mod applications;
mod groups;
mod logs;
mod organizations;
mod policies;
mod roles;
mod sessions;
mod validation;

use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post, put},
};

use crate::AppState;

pub(super) use access::session_actor;

pub(super) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let protected = Router::new()
        .route("/api/v1/session", delete(sessions::logout))
        .route("/api/v1/session/me", get(sessions::me))
        .route(
            "/api/v1/organizations",
            get(organizations::list_organizations).post(organizations::create_organization),
        )
        .route(
            "/api/v1/organizations/{id}",
            get(organizations::get_organization).patch(organizations::update_organization),
        )
        .route(
            "/api/v1/organizations/{id}/users",
            get(organizations::list_users).post(organizations::create_user),
        )
        .route("/api/v1/users/{id}", patch(organizations::update_user))
        .route(
            "/api/v1/organizations/{id}/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/api/v1/groups/{id}",
            get(groups::get_group).patch(groups::update_group),
        )
        .route(
            "/api/v1/groups/{id}/members",
            get(groups::list_group_members),
        )
        .route(
            "/api/v1/groups/{id}/members/{user_id}",
            put(groups::add_group_member).delete(groups::remove_group_member),
        )
        .route("/api/v1/users/{id}/groups", get(groups::list_user_groups))
        .route(
            "/api/v1/organizations/{id}/applications",
            get(applications::list_applications).post(applications::create_application),
        )
        .route(
            "/api/v1/applications/{id}",
            get(applications::get_application).patch(applications::update_application),
        )
        .route(
            "/api/v1/applications/{id}/roles",
            get(roles::list_roles).post(roles::create_role),
        )
        .route(
            "/api/v1/application-roles/{id}",
            get(roles::get_role).patch(roles::update_role),
        )
        .route(
            "/api/v1/application-roles/{id}/assignments",
            get(roles::list_assignments),
        )
        .route(
            "/api/v1/application-roles/{id}/users/{user_id}",
            put(roles::assign_user).delete(roles::unassign_user),
        )
        .route(
            "/api/v1/application-roles/{id}/groups/{group_id}",
            put(roles::assign_group).delete(roles::unassign_group),
        )
        .route(
            "/api/v1/applications/{id}/users/{user_id}/effective-roles",
            get(roles::effective_roles),
        )
        .route(
            "/api/v1/applications/{id}/service-accounts",
            get(applications::list_service_accounts).post(applications::create_service_account),
        )
        .route(
            "/api/v1/service-accounts/{id}/secrets",
            post(applications::create_service_secret),
        )
        .route(
            "/api/v1/service-secrets/{id}",
            delete(applications::revoke_service_secret),
        )
        .route(
            "/api/v1/applications/{id}/workspace",
            get(policies::get_workspace).put(policies::update_workspace),
        )
        .route(
            "/api/v1/applications/{id}/workspace/validate",
            post(policies::validate_workspace),
        )
        .route(
            "/api/v1/applications/{id}/workspace/simulate",
            post(policies::simulate_workspace),
        )
        .route(
            "/api/v1/applications/{id}/releases",
            get(policies::list_releases).post(policies::publish_release),
        )
        .route(
            "/api/v1/applications/{id}/releases/{release_id}/activate",
            post(policies::activate_release),
        )
        .route(
            "/api/v1/organizations/{id}/decision-logs",
            get(logs::list_decision_logs),
        )
        .route(
            "/api/v1/organizations/{id}/audit-logs",
            get(logs::list_audit_logs),
        )
        .route_layer(middleware::from_fn_with_state(state, access::authenticate));

    Router::new()
        .route("/api/v1/session", post(sessions::login))
        .route("/api/v1/activations/{token}", post(sessions::activate))
        .merge(protected)
}
