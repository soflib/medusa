// src/dal/refresh_token.rs

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::db_errors::{DbError, DbResult};
use crate::domain::models::refresh_token::{CreateRefreshToken, RefreshToken};

#[derive(Clone)]
pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ------------------------------------------------------------------ CREATE

    pub async fn create(&self, dto: CreateRefreshToken) -> DbResult<RefreshToken> {
        sqlx::query_as!(
            RefreshToken,
            r#"
            INSERT INTO auth.refresh_tokens (jti, user_id, expires_at, device_hint)
            VALUES ($1, $2, $3, $4)
            RETURNING
                id,
                jti,
                user_id,
                status      AS "status: _",
                issued_at,
                expires_at,
                revoked_at,
                device_hint
            "#,
            dto.jti,
            dto.user_id,
            dto.expires_at,
            dto.device_hint,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DbError::Sqlx)
    }

    // ------------------------------------------------------------------ FIND

    pub async fn find_by_jti(&self, jti: Uuid) -> DbResult<RefreshToken> {
        sqlx::query_as!(
            RefreshToken,
            r#"
            SELECT
                id, jti, user_id,
                status      AS "status: _",
                issued_at, expires_at, revoked_at, device_hint
            FROM auth.refresh_tokens
            WHERE jti = $1
            "#,
            jti
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    /// Todos los tokens activos de un usuario — útil para "cerrar todas las sesiones"
    pub async fn list_active_by_user(&self, user_id: Uuid) -> DbResult<Vec<RefreshToken>> {
        Ok(sqlx::query_as!(
            RefreshToken,
            r#"
            SELECT
                id, jti, user_id,
                status      AS "status: _",
                issued_at, expires_at, revoked_at, device_hint
            FROM auth.refresh_tokens
            WHERE user_id = $1
              AND status = 'active'
              AND expires_at > NOW()
            ORDER BY issued_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    // ------------------------------------------------------------------ REVOKE

    /// Revoca un token por su jti — logout normal
    pub async fn revoke_by_jti(&self, jti: Uuid) -> DbResult<()> {
        let rows = sqlx::query!(
            r#"
            UPDATE auth.refresh_tokens
            SET status     = 'revoked',
                revoked_at = NOW()
            WHERE jti    = $1
              AND status = 'active'
            "#,
            jti
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows == 0 {
            Err(DbError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Revoca todos los tokens activos de un usuario — "cerrar sesión en todos los dispositivos"
    pub async fn revoke_all_by_user(&self, user_id: Uuid) -> DbResult<u64> {
        let rows = sqlx::query!(
            r#"
            UPDATE auth.refresh_tokens
            SET status     = 'revoked',
                revoked_at = NOW()
            WHERE user_id = $1
              AND status  = 'active'
            "#,
            user_id
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(rows)
    }

    // ------------------------------------------------------------------ ROTATE

    /// Invalida el token viejo y crea uno nuevo en una sola transacción — token rotation
    pub async fn rotate(
        &self,
        old_jti: Uuid,
        new: CreateRefreshToken,
    ) -> DbResult<RefreshToken> {
        let mut tx = self.pool.begin().await.map_err(DbError::Sqlx)?;

        // 1. Revoca el viejo
        let rows = sqlx::query!(
            r#"
            UPDATE auth.refresh_tokens
            SET status     = 'revoked',
                revoked_at = NOW()
            WHERE jti    = $1
              AND status = 'active'
            "#,
            old_jti
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if rows == 0 {
            tx.rollback().await.map_err(DbError::Sqlx)?;
            return Err(DbError::InvalidState(
                "token ya fue usado o no existe".into(),
            ));
        }

        // 2. Inserta el nuevo
        let token = sqlx::query_as!(
            RefreshToken,
            r#"
            INSERT INTO auth.refresh_tokens (jti, user_id, expires_at, device_hint)
            VALUES ($1, $2, $3, $4)
            RETURNING
                id, jti, user_id,
                status      AS "status: _",
                issued_at, expires_at, revoked_at, device_hint
            "#,
            new.jti,
            new.user_id,
            new.expires_at,
            new.device_hint,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(DbError::Sqlx)?;

        tx.commit().await.map_err(DbError::Sqlx)?;
        Ok(token)
    }

    // ------------------------------------------------------------------ CLEANUP

    /// Marca como expirados los tokens que ya pasaron su expires_at
    /// Llamar desde un job periódico, no en cada request
    pub async fn expire_stale(&self) -> DbResult<u64> {
        let rows = sqlx::query!(
            r#"
            UPDATE auth.refresh_tokens
            SET status = 'expired'
            WHERE status     = 'active'
              AND expires_at < NOW()
            "#
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(rows)
    }
}