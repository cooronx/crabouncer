mod applications;
mod audit;
mod authzen;
mod bootstrap;
mod oidc;
mod policies;
mod resources;
mod sessions;
mod tenants;

use std::fmt;

use sqlx::{PgPool, postgres::PgPoolOptions};

pub(crate) use applications::{
    Application, NewApplication, NewServiceAccount, NewServiceSecret, ServiceAccount,
    UpdateApplication,
};
pub(crate) use audit::{AuditEvent, ServiceAuditEvent};
pub(crate) use authzen::{AuthzenCaller, DecisionLog, PolicyRelease, SubjectAttributes};
pub(crate) use bootstrap::BootstrapAdmin;
pub(crate) use oidc::{
    AuthorizationApp, AuthorizationCode, AuthorizationCodeExchange, RefreshRotation,
    ServiceCredential, UserGrant, UserProfile,
};
pub(crate) use policies::{
    NewPolicyRelease, PolicyReleaseResult, PolicySnapshot, Release, UpdateWorkspace, Workspace,
};
pub(crate) use resources::ResourceWriteStatus;
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
    pub(crate) async fn connect(url: &str, max_connections: u32) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub(crate) async fn migrate(&self) -> Result<()> {
        sqlx::migrate!().run(&self.pool).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    Conflict,
    Internal(sqlx::Error),
    Migration(sqlx::migrate::MigrateError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("database conflict"),
            Self::Internal(_) => formatter.write_str("database operation failed"),
            Self::Migration(_) => formatter.write_str("database migration failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conflict => None,
            Self::Internal(error) => Some(error),
            Self::Migration(error) => Some(error),
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

impl From<sqlx::migrate::MigrateError> for Error {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(error)
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
