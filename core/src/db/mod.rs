mod audit;
mod authzen;
mod oidc;
mod sessions;
mod tenants;

use std::fmt;

use sqlx::PgPool;

pub(crate) use audit::AuditEvent;
pub(crate) use authzen::{AuthzenCaller, DecisionLog, PolicyRelease, SubjectAttributes};
pub(crate) use oidc::{
    AuthorizationApp, AuthorizationCode, AuthorizationCodeExchange, RefreshRotation,
    ServiceCredential, UserGrant, UserProfile,
};
pub(crate) use sessions::{Actor, LoginUser, NewSession};
pub(crate) use tenants::{
    ActivationToken, NewOrganization, NewUser, Organization, UpdateOrganization, UpdateUser, User,
    UserAccess,
};

#[derive(Clone)]
pub(crate) struct Database {
    pool: PgPool,
}

impl Database {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    Conflict,
    Internal(sqlx::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("database conflict"),
            Self::Internal(_) => formatter.write_str("database operation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conflict => None,
            Self::Internal(error) => Some(error),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            Self::Conflict
        } else {
            Self::Internal(error)
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
