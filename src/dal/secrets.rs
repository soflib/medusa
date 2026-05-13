use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::models::enums::SecretKind;
use crate::domain::models::secrets::{CreateTenantSecret, TenantSecret, UpdateTenantSecret};
use crate::errors::db_errors::DbError;

pub type DbResult<T> = Result<T, DbError>;

pub struct TenantSecretsRepository {
    pool: PgPool,
}

impl TenantSecretsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_tenant_and_kind(
        &self,
        tenant_id: Uuid,
        kind:      SecretKind,
    ) -> DbResult<TenantSecret> {
        sqlx::query_as!(
            TenantSecret,
            r#"
            SELECT id, tenant_id,
                   kind      AS "kind: SecretKind",
                   encrypted_value,
                   created_at, updated_at, deleted_at
            FROM auth.tenant_secrets
            WHERE tenant_id = $1
              AND kind       = $2
              AND deleted_at IS NULL
            "#,
            tenant_id,
            kind as SecretKind,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError::from)?
        .ok_or(DbError::NotFound)
    }

    pub async fn create(&self, dto: CreateTenantSecret) -> DbResult<TenantSecret> {
        sqlx::query_as!(
            TenantSecret,
            r#"
            INSERT INTO auth.tenant_secrets (tenant_id, kind, encrypted_value)
            VALUES ($1, $2, $3)
            RETURNING id, tenant_id,
                      kind      AS "kind: SecretKind",
                      encrypted_value,
                      created_at, updated_at, deleted_at
            "#,
            dto.tenant_id,
            dto.kind as SecretKind,
            dto.encrypted_value,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DbError::from)
    }

    pub async fn update(&self, id: Uuid, dto: UpdateTenantSecret) -> DbResult<TenantSecret> {
        sqlx::query_as!(
            TenantSecret,
            r#"
            UPDATE auth.tenant_secrets
            SET encrypted_value = $2
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING id, tenant_id,
                      kind      AS "kind: SecretKind",
                      encrypted_value,
                      created_at, updated_at, deleted_at
            "#,
            id,
            dto.encrypted_value,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DbError::from)
    }

    pub async fn soft_delete(&self, id: Uuid) -> DbResult<()> {
        let rows = sqlx::query!(
            "UPDATE auth.tenant_secrets SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(DbError::from)?
        .rows_affected();

        if rows == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }
}
