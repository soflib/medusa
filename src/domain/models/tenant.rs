use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use super::enums::UserStatus;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id:         Uuid,
    pub name:       String,
    pub status:     UserStatus,
    pub privat_db:  bool,
    pub payment_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTenant {
    pub name:       String,
    pub privat_db:  bool,
    pub payment_id: Option<String>,
}