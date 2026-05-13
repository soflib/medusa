use sqlx::PgPool;
use uuid::Uuid;
use crate::errors::db_errors::{DbError, DbResult};
use crate::domain::models::user::{CreateUser, UpdateUser, User};
use crate::domain::models::enums::UserStatus;

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    // ------------------------------------------------------------------ CREATE
    pub async fn create(&self, dto: CreateUser) -> DbResult<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO auth.users (tenant_id, email, username, password_hash, role, status, full_name, phone)
            VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
            RETURNING
                id, tenant_id,
                email, username, password_hash,
                role    AS "role: _",
                status  AS "status: _",
                full_name, phone,
                failed_attempts, locked_until,
                last_login_at, last_login_ip AS "last_login_ip: _",
                created_at, updated_at, deleted_at
            "#,
            dto.tenant_id,
            dto.email,
            dto.username,
            dto.password_hash,
            dto.role as _,
            dto.full_name,
            dto.phone,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.constraint() == Some("users_email_unique") =>
                DbError::Conflict("email already taken".into()),
            sqlx::Error::Database(d) if d.constraint() == Some("users_username_unique") =>
                DbError::Conflict("username already taken".into()),
            _ => DbError::Sqlx(e),
        })?;

        Ok(user)
    }

    // ------------------------------------------------------------------ FIND
    pub async fn find_by_id(&self, id: Uuid) -> DbResult<User> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id, tenant_id,
                   email, username, password_hash,
                   role   AS "role: _",
                   status AS "status: _",
                   full_name, phone, failed_attempts, locked_until,
                   last_login_at, last_login_ip AS "last_login_ip: _",
                   created_at, updated_at, deleted_at
            FROM auth.users
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    pub async fn find_by_email(&self, email: &str) -> DbResult<User> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id, tenant_id,
                   email, username, password_hash,
                   role   AS "role: _",
                   status AS "status: _",
                   full_name, phone, failed_attempts, locked_until,
                   last_login_at, last_login_ip AS "last_login_ip: _",
                   created_at, updated_at, deleted_at
            FROM auth.users
            WHERE email = $1 AND deleted_at IS NULL
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    pub async fn list_active(&self, limit: i64, offset: i64) -> DbResult<Vec<User>> {
        Ok(sqlx::query_as!(
            User,
            r#"
            SELECT id, tenant_id,
                   email, username, password_hash,
                   role   AS "role: _",
                   status AS "status: _",
                   full_name, phone, failed_attempts, locked_until,
                   last_login_at, last_login_ip AS "last_login_ip: _",
                   created_at, updated_at, deleted_at
            FROM auth.users
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit, offset
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_by_tenant(&self, tenant_id: Uuid, limit: i64, offset: i64) -> DbResult<Vec<User>> {
        Ok(sqlx::query_as!(
            User,
            r#"
            SELECT id, tenant_id,
                   email, username, password_hash,
                   role   AS "role: _",
                   status AS "status: _",
                   full_name, phone, failed_attempts, locked_until,
                   last_login_at, last_login_ip AS "last_login_ip: _",
                   created_at, updated_at, deleted_at
            FROM auth.users
            WHERE tenant_id = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            tenant_id, limit, offset
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn find_by_username(&self, username: &str) -> DbResult<User> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id, tenant_id,
                   email, username, password_hash,
                   role   AS "role: _",
                   status AS "status: _",
                   full_name, phone, failed_attempts, locked_until,
                   last_login_at, last_login_ip AS "last_login_ip: _",
                   created_at, updated_at, deleted_at
            FROM auth.users
            WHERE username = $1 AND deleted_at IS NULL
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    // ------------------------------------------------------------------ UPDATE
    pub async fn update(&self, id: Uuid, dto: UpdateUser) -> DbResult<User> {
        sqlx::query_as!(
            User,
            r#"
            UPDATE auth.users SET
                full_name = COALESCE($2, full_name),
                phone     = COALESCE($3, phone),
                status    = COALESCE($4, status),
                role      = COALESCE($5, role)
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING
                id, tenant_id,
                email, username, password_hash,
                role   AS "role: _",
                status AS "status: _",
                full_name, phone, failed_attempts, locked_until,
                last_login_at, last_login_ip AS "last_login_ip: _",
                created_at, updated_at, deleted_at
            "#,
            id,
            dto.full_name,
            dto.phone,
            dto.status as Option<UserStatus>,
            dto.role   as Option<_>,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    // ------------------------------------------------------------------ DELETE (soft)
    pub async fn soft_delete(&self, id: Uuid) -> DbResult<()> {
        let rows = sqlx::query!(
            "UPDATE auth.users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
            id
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows == 0 { Err(DbError::NotFound) } else { Ok(()) }
    }

    pub async fn unlock_account(&self, id: Uuid) -> DbResult<()> {
        sqlx::query!(
            "UPDATE auth.users SET locked_until = NULL, failed_attempts = 0 WHERE id = $1 AND deleted_at IS NULL",
            id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ------------------------------------------------------------------ AUTH helpers
    pub async fn increment_failed_attempts(&self, id: Uuid) -> DbResult<i16> {
        let row = sqlx::query!(
            "UPDATE auth.users SET failed_attempts = failed_attempts + 1
             WHERE id = $1
             RETURNING failed_attempts",
            id
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.failed_attempts)
    }

    pub async fn reset_failed_attempts(&self, id: Uuid) -> DbResult<()> {
        sqlx::query!(
            "UPDATE auth.users SET failed_attempts = 0, locked_until = NULL WHERE id = $1",
            id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_password(&self, id: Uuid, new_hash: &str) -> DbResult<()> {
        let rows = sqlx::query!(
            "UPDATE auth.users SET password_hash = $2, updated_at = NOW()
             WHERE id = $1 AND deleted_at IS NULL",
            id,
            new_hash,
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows == 0 { Err(DbError::NotFound) } else { Ok(()) }
    }

    pub async fn lock_account(
        &self,
        id:    Uuid,
        until: chrono::DateTime<chrono::Utc>,
    ) -> DbResult<()> {
        sqlx::query!(
            "UPDATE auth.users SET locked_until = $2 WHERE id = $1 AND deleted_at IS NULL",
            id,
            until,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}