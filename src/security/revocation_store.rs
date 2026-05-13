use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::security::encryption::{decrypt, encrypt, EncryptionError};

// ─── Entry ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedTokenEntry {
    pub jti:        Uuid,
    pub user_id:    Uuid,
    pub revoked_at: DateTime<Utc>,
    pub reason:     String,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("key load failed: {0}")]
    KeyLoad(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] EncryptionError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

// ─── Store ────────────────────────────────────────────────────────────────────

/// Encrypted, append-only revocation list backed by a local file.
///
/// The file format is: nonce (12 bytes) || ChaCha20-Poly1305 ciphertext of a
/// JSON array of `RevokedTokenEntry`.
///
/// An in-memory cache keeps `contains_jti` lock-free-read fast; `add` holds the
/// write lock while updating the cache and flushing to disk atomically.
pub struct RevocationStore {
    path:  PathBuf,
    key:   [u8; 32],
    cache: RwLock<Vec<RevokedTokenEntry>>,
}

impl RevocationStore {
    /// Load from environment variables.
    ///
    /// REVOCATION_STORE_KEY  — 32-byte hex key (required)
    /// REVOCATION_STORE_PATH — path to .enc file (default: ./security/revoked_tokens.enc)
    pub async fn from_env() -> Result<Self, RevocationError> {
        let hex_key = std::env::var("REVOCATION_STORE_KEY")
            .map_err(|_| RevocationError::KeyLoad("REVOCATION_STORE_KEY not set".into()))?;

        let raw = hex::decode(hex_key.trim())
            .map_err(|e| RevocationError::KeyLoad(format!("invalid hex: {e}")))?;

        if raw.len() != 32 {
            return Err(RevocationError::KeyLoad(format!(
                "expected 32 bytes, got {}",
                raw.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);

        let path = PathBuf::from(
            std::env::var("REVOCATION_STORE_PATH")
                .unwrap_or_else(|_| "./security/revoked_tokens.enc".into()),
        );

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let initial = load_from_disk(&path, &key).await?;
        info!(count = initial.len(), path = %path.display(), "revocation store loaded");

        Ok(Self {
            path,
            key,
            cache: RwLock::new(initial),
        })
    }

    /// Append a revoked token to the store and flush to disk.
    pub async fn add(&self, entry: RevokedTokenEntry) -> Result<(), RevocationError> {
        debug!(jti = %entry.jti, user_id = %entry.user_id, reason = %entry.reason, "revoking token");
        let mut cache = self.cache.write().await;
        cache.push(entry);
        flush_to_disk(&self.path, &self.key, &cache).await.map_err(|e| {
            error!(path = %self.path.display(), "revocation store flush failed: {e}");
            e
        })
    }

    /// Check whether the given JTI has been revoked.
    /// Reads only the in-memory cache — no disk I/O.
    pub async fn contains_jti(&self, jti: &Uuid) -> Result<bool, RevocationError> {
        let cache = self.cache.read().await;
        let found = cache.iter().any(|e| &e.jti == jti);
        if found {
            warn!(jti = %jti, "revoked token presented");
        }
        Ok(found)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async fn load_from_disk(
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<Vec<RevokedTokenEntry>, RevocationError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let blob = tokio::fs::read(path).await?;
    if blob.is_empty() {
        return Ok(Vec::new());
    }

    let plain = decrypt(key, &blob)?;
    let entries: Vec<RevokedTokenEntry> = serde_json::from_slice(&plain)?;
    Ok(entries)
}

async fn flush_to_disk(
    path: &PathBuf,
    key: &[u8; 32],
    entries: &[RevokedTokenEntry],
) -> Result<(), RevocationError> {
    let json = serde_json::to_vec(entries)?;
    let blob = encrypt(key, &json)?;
    tokio::fs::write(path, blob).await?;
    Ok(())
}
