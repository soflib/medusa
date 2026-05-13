use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::dal::secrets::TenantSecretsRepository;
use crate::domain::models::enums::SecretKind;
use crate::domain::models::secrets::CreateTenantSecret;
use crate::errors::db_errors::DbError;
use crate::security::encryption::{decrypt, encrypt, EncryptionError};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("secret not found for tenant")]
    NotFound,

    #[error("encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("database error: {0}")]
    Db(#[from] DbError),

    #[error("invalid UTF-8 in decrypted secret")]
    Utf8,
}

// ─── Service ──────────────────────────────────────────────────────────────────

pub struct TenantSecretsService {
    repo: Arc<TenantSecretsRepository>,
    key:  [u8; 32],
}

impl TenantSecretsService {
    /// Load the 32-byte `TENANT_SECRETS_KEY` from the environment (hex-encoded).
    pub fn from_env(repo: Arc<TenantSecretsRepository>) -> Result<Self, String> {
        let hex = std::env::var("TENANT_SECRETS_KEY")
            .map_err(|_| "TENANT_SECRETS_KEY env var missing".to_string())?;
        let bytes = hex::decode(&hex)
            .map_err(|e| format!("TENANT_SECRETS_KEY is not valid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "TENANT_SECRETS_KEY must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        info!("tenant secrets key loaded");
        Ok(Self { repo, key })
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Return the tenant schema name (e.g. `t_<uuid>`).
    pub async fn get_schema_name(&self, tenant_id: Uuid) -> Result<String, SecretsError> {
        self.get_secret(tenant_id, SecretKind::TenantSchema).await
    }

    /// Persist the tenant schema name encrypted.
    pub async fn set_schema_name(&self, tenant_id: Uuid, schema: &str) -> Result<(), SecretsError> {
        self.set_secret(tenant_id, SecretKind::TenantSchema, schema).await
    }

    /// Decrypt and return the database connection URL for a tenant.
    /// Returns `SecretsError::NotFound` if no active secret exists.
    pub async fn get_db_url(&self, tenant_id: Uuid) -> Result<String, SecretsError> {
        self.get_secret(tenant_id, SecretKind::DatabaseConnection).await
    }

    /// Encrypt `url` and upsert it as the tenant's `DatabaseConnection` secret.
    /// The URL itself is never logged — it contains credentials.
    pub async fn set_db_url(&self, tenant_id: Uuid, url: &str) -> Result<(), SecretsError> {
        self.set_secret(tenant_id, SecretKind::DatabaseConnection, url).await
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn get_secret(&self, tenant_id: Uuid, kind: SecretKind) -> Result<String, SecretsError> {
        debug!(tenant_id = %tenant_id, kind = %kind, "fetching secret");

        let record = self.repo
            .find_by_tenant_and_kind(tenant_id, kind.clone())
            .await
            .map_err(|e| match e {
                DbError::NotFound => {
                    warn!(tenant_id = %tenant_id, kind = %kind, "no secret found");
                    SecretsError::NotFound
                }
                e => {
                    error!(tenant_id = %tenant_id, error = %e, "db error fetching secret");
                    SecretsError::Db(e)
                }
            })?;

        let plaintext = decrypt(&self.key, &record.encrypted_value).map_err(|e| {
            error!(tenant_id = %tenant_id, "decryption failed: {e}");
            SecretsError::Encryption(e)
        })?;
        String::from_utf8(plaintext).map_err(|_| {
            error!(tenant_id = %tenant_id, "decrypted secret is not valid UTF-8");
            SecretsError::Utf8
        })
    }

    async fn set_secret(&self, tenant_id: Uuid, kind: SecretKind, value: &str) -> Result<(), SecretsError> {
        debug!(tenant_id = %tenant_id, kind = %kind, "storing secret");

        let encrypted = encrypt(&self.key, value.as_bytes()).map_err(|e| {
            error!(tenant_id = %tenant_id, "encryption failed: {e}");
            SecretsError::Encryption(e)
        })?;

        match self.repo.find_by_tenant_and_kind(tenant_id, kind.clone()).await {
            Ok(existing) => {
                self.repo.update(
                    existing.id,
                    crate::domain::models::secrets::UpdateTenantSecret { encrypted_value: encrypted },
                ).await?;
                info!(tenant_id = %tenant_id, kind = %kind, "secret rotated");
            }
            Err(DbError::NotFound) => {
                self.repo.create(CreateTenantSecret {
                    tenant_id,
                    kind,
                    encrypted_value: encrypted,
                }).await?;
                info!(tenant_id = %tenant_id, "secret created");
            }
            Err(e) => {
                error!(tenant_id = %tenant_id, error = %e, "db error upserting secret");
                return Err(SecretsError::Db(e));
            }
        }

        Ok(())
    }
}
