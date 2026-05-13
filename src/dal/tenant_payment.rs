use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::db_errors::{DbError, DbResult};
use crate::domain::models::tenant_payment::{CreateTenantPayment, TenantPayment};

#[derive(Clone)]
pub struct TenantPaymentRepository {
    pool: PgPool,
}

impl TenantPaymentRepository {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    pub async fn create(&self, dto: CreateTenantPayment) -> DbResult<TenantPayment> {
        sqlx::query_as!(
            TenantPayment,
            r#"
            INSERT INTO auth.tenant_payments
                (tenant_id, payment_id, payment_method, payment_plan, payment_plan_end)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id, tenant_id, payment_id, payment_method,
                payment_plan, payment_plan_end,
                created_at, updated_at
            "#,
            dto.tenant_id,
            dto.payment_id,
            dto.payment_method,
            dto.payment_plan,
            dto.payment_plan_end,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DbError::Sqlx)
    }

    pub async fn find_by_tenant(&self, tenant_id: Uuid) -> DbResult<TenantPayment> {
        sqlx::query_as!(
            TenantPayment,
            r#"
            SELECT id, tenant_id, payment_id, payment_method,
                   payment_plan, payment_plan_end,
                   created_at, updated_at
            FROM auth.tenant_payments
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)
    }
}
