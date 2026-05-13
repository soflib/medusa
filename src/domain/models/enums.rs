// src/domain/models/enums.rs
use std::fmt;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;



#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    User,
    Moderator,
    Arquitecto,
    Finanzas,
    Reportes,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Inactive,
    Banned,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "token_status", rename_all = "snake_case")]
pub enum TokenStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "history_action", rename_all = "snake_case")]
pub enum HistoryAction {
    Login,
    Logout,
    LoginFailed,
    TokenRefreshed,
    TokenRevoked,
    PasswordChanged,
    AccountLocked,
    AccountUnlocked,
    Register,
    PasswordResetRequested,
    PasswordResetCompleted,
    RoleChanged,
    UserDeleted,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserRole::Admin       => write!(f, "admin"),
            UserRole::User        => write!(f, "user"),
            UserRole::Moderator   => write!(f, "moderator"),
            UserRole::Arquitecto  => write!(f, "arquitecto"),
            UserRole::Finanzas    => write!(f, "finanzas"),
            UserRole::Reportes    => write!(f, "reportes"),
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserStatus::Active   => write!(f, "active"),
            UserStatus::Inactive => write!(f, "inactive"),
            UserStatus::Banned   => write!(f, "banned"),
            UserStatus::Pending  => write!(f, "pending"),
        }
    }
}

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "secret_kind", rename_all = "snake_case")]
pub enum SecretKind {
    DatabaseConnection,
    TenantSchema,
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SecretKind::DatabaseConnection => write!(f, "database_connection"),
            SecretKind::TenantSchema       => write!(f, "tenant_schema"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "payment_method_type", rename_all = "snake_case")]
pub enum PaymentMethodType {
    CreditCard,
    DebitCard,
    BankTransfer,
    Wallet,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "payment_provider", rename_all = "snake_case")]
pub enum PaymentProvider {
    Stripe,
    Paypal,
    Mercadopago,
    Manual,
}