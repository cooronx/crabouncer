use std::fmt;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::db;

pub(crate) type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    details: Value,
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: Value::Null,
        }
    }
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
    pub(crate) fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication is required",
        )
    }
    pub(crate) fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "Permission denied")
    }
    pub(crate) fn not_found(name: &'static str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{name} was not found"),
        )
    }
    pub(crate) fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    pub(crate) fn validation(message: impl Into<String>, details: Value) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "validation_failed",
            message: message.into(),
            details,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": { "code": self.code, "message": self.message, "details": self.details } }))).into_response()
    }
}

impl From<db::Error> for ApiError {
    fn from(error: db::Error) -> Self {
        match error {
            db::Error::Conflict => Self::conflict(
                "already_exists",
                "A resource with the same unique value already exists",
            ),
            db::Error::PolicyStateChanged => Self::conflict(
                "policy_state_changed",
                "The active policy release changed; retry the request",
            ),
            db::Error::SchemaNotRoleReady => Self::conflict(
                "schema_not_role_ready",
                "The active policy release does not satisfy the User, Group, and Role schema contract",
            ),
            db::Error::Internal(error) => {
                tracing::error!(%error, "database error");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                )
            }
            db::Error::Migration(error) => {
                tracing::error!(%error, "database migration error");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                )
            }
        }
    }
}
