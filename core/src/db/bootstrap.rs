use uuid::Uuid;

use super::{Database, Result};

pub(crate) struct BootstrapAdmin {
    pub(crate) organization_id: Uuid,
    pub(crate) organization_name: String,
    pub(crate) user_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) password_hash: String,
}

impl Database {
    pub(crate) async fn has_system_admin(&self) -> Result<bool> {
        Ok(
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE is_system_admin)")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub(crate) async fn create_bootstrap_admin(&self, admin: BootstrapAdmin) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO organizations (id, name, display_name) VALUES ($1, $2, $3)")
            .bind(admin.organization_id)
            .bind(&admin.organization_name)
            .bind(&admin.organization_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO users (id, organization_id, email, display_name, role, status, is_system_admin) VALUES ($1, $2, $3, $4, 'owner', 'active', true)")
            .bind(admin.user_id)
            .bind(admin.organization_id)
            .bind(admin.email)
            .bind(admin.display_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)")
            .bind(admin.user_id)
            .bind(admin.password_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
