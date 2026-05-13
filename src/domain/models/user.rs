// src/domain/models/user.rs
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use super::enums::{UserRole, UserStatus};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id:              Uuid,
    pub tenant_id:       Option<Uuid>,  // ← add
    pub email:           String,
    pub username:        String,
    pub password_hash:   String,
    pub role:            UserRole,
    pub status:          UserStatus,
    pub full_name:       Option<String>,
    pub phone:           Option<String>,
    pub failed_attempts: i16,
    pub locked_until:    Option<DateTime<Utc>>,
    pub last_login_at:   Option<DateTime<Utc>>,
    pub last_login_ip:   Option<IpAddr>,
    pub created_at:      DateTime<Utc>,
    pub updated_at:      DateTime<Utc>,
    pub deleted_at:      Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUser {
    pub email:         String,
    pub username:      String,
    pub password_hash: String,
    pub role:          UserRole,
    pub tenant_id:     Option<Uuid>,
    pub full_name:     Option<String>,
    pub phone:         Option<String>,
}

#[derive(Default, Deserialize)]
pub struct UpdateUser {
    pub full_name: Option<String>,
    pub phone:     Option<String>,
    pub status:    Option<UserStatus>,
    pub role:      Option<UserRole>,
}