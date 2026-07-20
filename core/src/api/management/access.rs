use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, header},
    middleware::Next,
    response::Response,
};
use cookie::Cookie;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState,
    db::{Actor, AuditEvent},
    error::{ApiError, Result},
    security,
};

pub(super) const SESSION_COOKIE: &str = "crabouncer_session";

pub(in crate::api) async fn session_actor(state: &AppState, headers: &HeaderMap) -> Result<Actor> {
    let token = cookie_value(headers, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
    let session_hash = security::token_hash(&token);
    state
        .db
        .actor(session_hash)
        .await?
        .ok_or_else(ApiError::unauthorized)
}

pub(super) async fn authenticate(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    let current = session_actor(&state, request.headers()).await?;
    if requires_csrf(request.method()) {
        validate_csrf(request.headers(), &current)?;
    }
    request.extensions_mut().insert(current);
    Ok(next.run(request).await)
}

pub(super) fn can_manage(current: &Actor, organization_id: Uuid) -> Result<()> {
    if current.is_system_admin
        || (current.organization_id == organization_id
            && matches!(current.role.as_str(), "owner" | "admin"))
    {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub(super) fn can_view(current: &Actor, organization_id: Uuid) -> Result<()> {
    if current.is_system_admin || current.organization_id == organization_id {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub(super) fn owner_or_system(current: &Actor, organization_id: Uuid) -> Result<()> {
    if current.is_system_admin
        || (current.organization_id == organization_id && current.role == "owner")
    {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub(super) async fn audit_event(
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

fn requires_csrf(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn validate_csrf(headers: &HeaderMap, current: &Actor) -> Result<()> {
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::forbidden)?;
    if security::token_hash(csrf) == current.csrf_hash {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Method};
    use uuid::Uuid;

    use crate::{db::Actor, security};

    #[test]
    fn csrf_is_required_for_unsafe_methods() {
        for method in [
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::CONNECT,
        ] {
            assert!(super::requires_csrf(&method));
        }
    }

    #[test]
    fn csrf_is_not_required_for_safe_methods() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!super::requires_csrf(&method));
        }
    }

    #[test]
    fn csrf_header_must_match_the_session() {
        let token = "csrf-token";
        let current = Actor {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            email: String::new(),
            display_name: String::new(),
            role: String::new(),
            is_system_admin: false,
            csrf_hash: security::token_hash(token),
            session_hash: Vec::new(),
        };
        let mut headers = HeaderMap::new();

        assert!(super::validate_csrf(&headers, &current).is_err());
        headers.insert("x-csrf-token", HeaderValue::from_static("wrong-token"));
        assert!(super::validate_csrf(&headers, &current).is_err());
        headers.insert("x-csrf-token", HeaderValue::from_static(token));
        assert!(super::validate_csrf(&headers, &current).is_ok());
    }
}
