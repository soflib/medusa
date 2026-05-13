use argon2::password_hash::rand_core::{OsRng, RngCore};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed — wrong key or corrupted data")]
    Decrypt,

    #[error("ciphertext too short to contain nonce")]
    TooShort,
}

/// Encrypt `plaintext` and return `nonce (12 bytes) || ciphertext`.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptionError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| EncryptionError::Encrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt`. Expects `nonce (12 bytes) || ciphertext`.
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if blob.len() < NONCE_LEN {
        return Err(EncryptionError::TooShort);
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptionError::Decrypt)?;
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::Decrypt)
}
