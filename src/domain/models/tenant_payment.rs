use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TenantPayment {
    pub id:               Uuid,
    pub tenant_id:        Uuid,
    pub payment_id:       String,
    pub payment_method:   String,
    pub payment_plan:     String,
    pub payment_plan_end: Option<DateTime<Utc>>,
    pub created_at:       DateTime<Utc>,
    pub updated_at:       DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTenantPayment {
    pub tenant_id:        Uuid,
    pub payment_id:       String,
    pub payment_method:   String,
    pub payment_plan:     String,
    pub payment_plan_end: Option<DateTime<Utc>>,
}
