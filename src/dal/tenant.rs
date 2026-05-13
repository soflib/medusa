use sqlx::PgPool;
use uuid::Uuid;
use crate::errors::db_errors::{DbError, DbResult};
use crate::domain::models::tenant::{CreateTenant, Tenant};
use crate::domain::models::enums::UserStatus;

#[derive(Clone)]
pub struct TenantRepository {
    pool: PgPool,
}

impl TenantRepository {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    // ------------------------------------------------------------------ CREATE
    pub async fn create(&self, dto: CreateTenant) -> DbResult<Tenant> {
        sqlx::query_as!(
            Tenant,
            r#"
            INSERT INTO auth.tenants (name, privat_db, payment_id)
            VALUES ($1, $2, $3)
            RETURNING
                id, name,
                status AS "status: _",
                privat_db, payment_id,
                created_at, updated_at, deleted_at
            "#,
            dto.name,
            dto.privat_db,
            dto.payment_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.constraint() == Some("tenants_name_key") =>
                DbError::Conflict(e.to_string()),
            _ => DbError::Sqlx(e),
        })
    }

    // ------------------------------------------------------------------ FIND
    pub async fn find_by_id(&self, id: Uuid) -> DbResult<Tenant> {
        sqlx::query_as!(
            Tenant,
            r#"
            SELECT id, name,
                   status AS "status: _",
                   privat_db, payment_id,
                   created_at, updated_at, deleted_at
            FROM auth.tenants
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    pub async fn find_by_name(&self, name: &str) -> DbResult<Tenant> {
        sqlx::query_as!(
            Tenant,
            r#"
            SELECT id, name,
                   status AS "status: _",
                   privat_db, payment_id,
                   created_at, updated_at, deleted_at
            FROM auth.tenants
            WHERE name = $1 AND deleted_at IS NULL
            "#,
            name
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    pub async fn list_active(&self, limit: i64, offset: i64) -> DbResult<Vec<Tenant>> {
        Ok(sqlx::query_as!(
            Tenant,
            r#"
            SELECT id, name,
                   status AS "status: _",
                   privat_db, payment_id,
                   created_at, updated_at, deleted_at
            FROM auth.tenants
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit, offset
        )
        .fetch_all(&self.pool)
        .await?)
    }

    // ------------------------------------------------------------------ UPDATE
    pub async fn update(&self, id: Uuid, name: Option<String>, status: Option<UserStatus>) -> DbResult<Tenant> {
        sqlx::query_as!(
            Tenant,
            r#"
            UPDATE auth.tenants SET
                name   = COALESCE($2, name),
                status = COALESCE($3, status)
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING
                id, name,
                status AS "status: _",
                privat_db, payment_id,
                created_at, updated_at, deleted_at
            "#,
            id,
            name,
            status as Option<UserStatus>,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    // ------------------------------------------------------------------ DELETE (soft)
    pub async fn soft_delete(&self, id: Uuid) -> DbResult<()> {
        let rows = sqlx::query!(
            "UPDATE auth.tenants SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
            id
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows == 0 { Err(DbError::NotFound) } else { Ok(()) }
    }
}