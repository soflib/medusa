// src/infrastructure/data/models/audit_log.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use std::net::IpAddr;
use crate::domain::models::enums::HistoryAction;

/// Registro inmutable — nunca se actualiza, solo se inserta
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id:         Uuid,
    pub user_id:    Option<Uuid>,   // Option porque login fallido puede no tener user_id válido
    pub action:     HistoryAction,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub success:    bool,
    pub detail:     Option<String>, // mensaje libre: "cuenta bloqueada tras 5 intentos"
    pub created_at: DateTime<Utc>,
}

/// Para insertar — id y created_at los genera la DB
#[derive(Debug, Clone)]
pub struct CreateAuditLog {
    pub user_id:    Option<Uuid>,
    pub action:     HistoryAction,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub success:    bool,
    pub detail:     Option<String>,
}