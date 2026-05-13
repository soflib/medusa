use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::enums::SecretKind;

// ─── DB row ───────────────────────────────────────────────────────────────────

/// One secret entry per tenant.
///
/// `encrypted_value` is the raw output of `security::encryption::encrypt()` —
/// a 12-byte nonce followed by ChaCha20-Poly1305 ciphertext stored as `BYTEA`.
/// Decrypt it with `security::encryption::decrypt()` using `TENANT_SECRETS_KEY`.
///
/// Never expose `encrypted_value` over the wire — always decrypt in the service
/// layer and return only what the caller needs.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TenantSecret {
    pub id:              Uuid,
    pub tenant_id:       Uuid,
    pub kind:            SecretKind,
    pub encrypted_value: Vec<u8>,          // BYTEA — nonce || ciphertext
    pub created_at:      DateTime<Utc>,
    pub updated_at:      DateTime<Utc>,
    pub deleted_at:      Option<DateTime<Utc>>,
}

// ─── DTOs ─────────────────────────────────────────────────────────────────────

/// Pass to the DAL when inserting a new secret.
/// The service layer encrypts `value` before building this struct.
#[derive(Debug, Clone)]
pub struct CreateTenantSecret {
    pub tenant_id:       Uuid,
    pub kind:            SecretKind,
    pub encrypted_value: Vec<u8>,
}

/// Pass to the DAL when rotating a secret.
/// The service layer re-encrypts the new plaintext before building this.
#[derive(Debug, Clone)]
pub struct UpdateTenantSecret {
    pub encrypted_value: Vec<u8>,
}
