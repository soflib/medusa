use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::domain::models::enums::{
    PaymentMethodType,
    PaymentProvider,
};

// ── Model ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentMethod {
    pub id:             Uuid,
    pub tenant_id:      Uuid,
    pub r#type:         PaymentMethodType,
    pub provider:       PaymentProvider,
    pub provider_token: String,
    pub last_four:      Option<String>,
    pub is_default:     bool,
    pub expires_at:     Option<DateTime<Utc>>,
    pub created_at:     DateTime<Utc>,
}

// ── Create ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePaymentMethod {
    pub tenant_id:      Uuid,
    pub r#type:         PaymentMethodType,
    pub provider:       PaymentProvider,
    pub provider_token: String,
    pub last_four:      Option<String>,
    pub is_default:     bool,
    pub expires_at:     Option<DateTime<Utc>>,
}