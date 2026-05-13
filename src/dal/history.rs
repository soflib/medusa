//! Repository for `history` — append-only audit log.
//!
//! This table is NEVER updated or deleted; only INSERTs and SELECTs.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::db_errors::{DbError, DbResult};
use crate::domain::models::enums::HistoryAction;
use crate::domain::models::history::{CreateHistory, History};

#[derive(Clone)]
pub struct HistoryRepository {
    pool: PgPool,
}

impl HistoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ------------------------------------------------------------------ WRITE

    /// Appends one audit event.  Use `CreateHistory::new(action)` builder.
    ///
    /// # Example
    /// ```no_run
    /// repo.append(
    ///     CreateHistory::new(HistoryAction::UserLogin)
    ///         .actor(user.id, &user.email)
    ///         .ip(client_ip)
    /// ).await?;
    /// ```
    pub async fn append(&self, dto: CreateHistory) -> DbResult<History> {
        let action = dto
            .action
            .ok_or_else(|| DbError::InvalidState("HistoryAction must be set".into()))?;

        sqlx::query_as!(
            History,
            r#"
            INSERT INTO auth.history (
                actor_id, actor_email, action,
                target_user_id, sign_doc_id, token_id, key_id,
                ip_address, user_agent, metadata,
                success, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING
                id,
                actor_id,
                actor_email,
                action          AS "action: _",
                target_user_id,
                sign_doc_id,
                token_id,
                key_id,
                ip_address      AS "ip_address: _",
                user_agent,
                metadata        AS "metadata: _",
                success,
                error_message,
                created_at
            "#,
            dto.actor_id,
            dto.actor_email,
            action as _,
            dto.target_user_id,
            dto.sign_doc_id,
            dto.token_id,
            dto.key_id,
            dto.ip_address as _,
            dto.user_agent,
            dto.metadata as _,
            dto.success,
            dto.error_message,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DbError::Sqlx)
    }

    // ------------------------------------------------------------------ READ

    pub async fn find_by_id(&self, id: i64) -> DbResult<History> {
        sqlx::query_as!(
            History,
            r#"
            SELECT
                id, actor_id, actor_email,
                action         AS "action: _",
                target_user_id, sign_doc_id, token_id, key_id,
                ip_address     AS "ip_address: _",
                user_agent,
                metadata       AS "metadata: _",
                success, error_message, created_at
            FROM auth.history
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }

    /// All events for a given actor (user), newest first, with pagination.
    pub async fn list_for_actor(
        &self,
        actor_id: Uuid,
        limit: i64,
        offset: i64,
        tenant_id: String,
    ) -> DbResult<Vec<History>> {
        Ok(sqlx::query_as!(
            History,
            r#"
            SELECT
                id, actor_id, actor_email,
                action         AS "action: _",
                target_user_id, sign_doc_id, token_id, key_id,
                ip_address     AS "ip_address: _",
                user_agent,
                metadata       AS "metadata: _",
                success, error_message, created_at
            FROM auth.history
            WHERE actor_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            actor_id,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// All events tied to a specific signing document, newest first.
    pub async fn list_for_sign_doc(&self, sign_doc_id: Uuid) -> DbResult<Vec<History>> {
        Ok(sqlx::query_as!(
            History,
            r#"
            SELECT
                id, actor_id, actor_email,
                action         AS "action: _",
                target_user_id, sign_doc_id, token_id, key_id,
                ip_address     AS "ip_address: _",
                user_agent,
                metadata       AS "metadata: _",
                success, error_message, created_at
            FROM auth.history
            WHERE sign_doc_id = $1
            ORDER BY created_at ASC
            "#,
            sign_doc_id,
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Failed events only — useful for security dashboards / alerting.
    pub async fn list_failures(
        &self,
        action: Option<HistoryAction>,
        limit: i64,
    ) -> DbResult<Vec<History>> {
        // Two queries to avoid dynamic SQL with optional filter
        if let Some(act) = action {
            Ok(sqlx::query_as!(
                History,
                r#"
                SELECT
                    id, actor_id, actor_email,
                    action         AS "action: _",
                    target_user_id, sign_doc_id, token_id, key_id,
                    ip_address     AS "ip_address: _",
                    user_agent,
                    metadata       AS "metadata: _",
                    success, error_message, created_at
                FROM auth.history
                WHERE success = FALSE
                  AND action  = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
                act as _,
                limit,
            )
            .fetch_all(&self.pool)
            .await?)
        } else {
            Ok(sqlx::query_as!(
                History,
                r#"
                SELECT
                    id, actor_id, actor_email,
                    action         AS "action: _",
                    target_user_id, sign_doc_id, token_id, key_id,
                    ip_address     AS "ip_address: _",
                    user_agent,
                    metadata       AS "metadata: _",
                    success, error_message, created_at
                FROM auth.history
                WHERE success = FALSE
                ORDER BY created_at DESC
                LIMIT $1
                "#,
                limit,
            )
            .fetch_all(&self.pool)
            .await?)
        }
    }
}