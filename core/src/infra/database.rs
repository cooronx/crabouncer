use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::identity::password;

pub(crate) async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}

pub(crate) async fn bootstrap(pool: &PgPool, initial_password: &str) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let organization_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO organizations (id, name, display_name, status, is_system) \
         VALUES ($1, 'system', 'Crabouncer System', 'active', true) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    let organization_id: Uuid =
        sqlx::query_scalar("SELECT id FROM organizations WHERE name = 'system'")
            .fetch_one(&mut *transaction)
            .await?;

    let user_id = Uuid::now_v7();
    let hash = password::hash(initial_password).map_err(sqlx::Error::Protocol)?;
    sqlx::query(
        "INSERT INTO users (id, username, display_name, status, is_system_admin, must_change_password) \
         VALUES ($1, 'crabouncer', 'Crabouncer Administrator', 'active', true, true) \
         ON CONFLICT (username) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'crabouncer'")
        .fetch_one(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(hash)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO organization_memberships (organization_id, user_id, role) \
         VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}
