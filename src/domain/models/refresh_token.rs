// src/infrastructure/data/models/refresh_token.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use super::enums::TokenStatus;

/// Fila en DB — fuente de verdad de todos los refresh tokens emitidos
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id:         Uuid,           // PK
    pub jti:        Uuid,           // claim jti del token — lo que va a Redis blacklist
    pub user_id:    Uuid,           // FK → users.id
    pub status:     TokenStatus,
    pub issued_at:  DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub device_hint: Option<String>, // "Chrome / macOS" — útil para "cerrar sesión en dispositivo X"
}

/// Para insertar un refresh token nuevo
#[derive(Debug, Clone)]
pub struct CreateRefreshToken {
    pub jti:        Uuid,
    pub user_id:    Uuid,
    pub expires_at: DateTime<Utc>,
    pub device_hint: Option<String>,
}