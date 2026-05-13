use chrono::{DateTime, Duration, Utc};
use tracing::{debug, error, warn};
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate, SymmetricKey},
    local, public,
    token::UntrustedToken,
    version4::V4,
    Local, Public,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::models::enums::UserRole;

const ISSUER: &str = "arch-pilot-auth";
const ACCESS_SECS: i64 = 15 * 60;
const REFRESH_SECS: i64 = 7 * 24 * 3600;

// ─── Input ────────────────────────────────────────────────────────────────────

/// Minimal user data needed to mint a token — no secrets here.
#[derive(Debug, Clone)]
pub struct TokenSubject {
    pub user_id:     Uuid,
    pub email:       String,
    pub username:    String,
    pub role:        UserRole,
    pub tenant_id:   Option<Uuid>,
    pub device_hint: Option<String>,
}

// ─── Decoded payload ──────────────────────────────────────────────────────────

/// Verified claims returned from both verify_access and verify_refresh.
/// This struct is the canonical shape — add/remove fields here to control
/// what travels inside every token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub:         Uuid,
    pub email:       String,
    pub username:    String,
    pub role:        UserRole,
    pub tenant_id:   Option<Uuid>,
    pub jti:         Uuid,
    pub iss:         String,
    pub iat:         DateTime<Utc>,
    pub exp:         DateTime<Utc>,
    pub device_hint: Option<String>,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("failed to build claims: {0}")]
    ClaimsBuild(String),

    #[error("failed to issue token: {0}")]
    IssueFailed(String),

    #[error("token is invalid or expired")]
    Invalid,

    #[error("missing or malformed claim '{0}'")]
    MissingClaim(String),

    #[error("key load failed: {0}")]
    KeyLoad(String),
}

// ─── Service ──────────────────────────────────────────────────────────────────

pub struct TokenService {
    /// v4.local  — symmetric AEAD; used for refresh tokens (opaque to callers).
    local_key:  SymmetricKey<V4>,
    /// v4.public — Ed25519 signing key; used to mint access tokens.
    secret_key: AsymmetricSecretKey<V4>,
    /// v4.public — Ed25519 verification key; distributable to other services.
    public_key: AsymmetricPublicKey<V4>,
}

impl TokenService {
    /// Load all three keys from env vars (hex-encoded).
    ///
    /// PASETO_LOCAL_KEY  — 32-byte symmetric key (hex)
    /// PASETO_SECRET_KEY — 64-byte Ed25519 secret key (hex)
    /// PASETO_PUBLIC_KEY — 32-byte Ed25519 public key (hex)
    ///
    /// Run `TokenService::generate_keys()` once to produce these values.
    pub fn from_env() -> Result<Self, TokenError> {
        let svc = Self {
            local_key:  Self::load_symmetric("PASETO_LOCAL_KEY")?,
            secret_key: Self::load_secret("PASETO_SECRET_KEY")?,
            public_key: Self::load_public("PASETO_PUBLIC_KEY")?,
        };
        tracing::info!("PASETO keys loaded");
        Ok(svc)
    }

    /// One-shot key generation — run once and paste the hex values into .env.
    /// Returns (local_hex, secret_hex, public_hex).
    ///   PASETO_LOCAL_KEY  = <32-byte hex>
    ///   PASETO_SECRET_KEY = <64-byte hex>  (Ed25519 seed || public_key)
    ///   PASETO_PUBLIC_KEY = <32-byte hex>
    pub fn generate_keys() -> Result<(String, String, String), TokenError> {
        let sym = SymmetricKey::<V4>::generate()
            .map_err(|e| TokenError::KeyLoad(e.to_string()))?;
        let kp = AsymmetricKeyPair::<V4>::generate()
            .map_err(|e| TokenError::KeyLoad(e.to_string()))?;
        Ok((
            hex::encode(sym.as_bytes()),
            hex::encode(kp.secret.as_bytes()),
            hex::encode(kp.public.as_bytes()),
        ))
    }

    // ─── Issue ────────────────────────────────────────────────────────────────

    /// Mint a short-lived v4.public access token (Ed25519 signed).
    /// Any service that has the public key can verify this without calling us.
    pub fn issue_access(
        &self,
        subject: &TokenSubject,
    ) -> Result<(String, TokenClaims), TokenError> {
        let (now, exp, jti) = Self::timing(ACCESS_SECS);
        let paseto = Self::build_paseto_claims(subject, &jti, now, exp)?;
        let token = public::sign(&self.secret_key, &paseto, None, None)
            .map_err(|e| {
                error!(user_id = %subject.user_id, "access token signing failed: {e}");
                TokenError::IssueFailed(e.to_string())
            })?;
        debug!(user_id = %subject.user_id, jti = %jti, "access token issued");
        Ok((token, Self::to_token_claims(subject, jti, now, exp)))
    }

    /// Mint a long-lived v4.local refresh token (symmetric AEAD, auth-service only).
    pub fn issue_refresh(
        &self,
        subject: &TokenSubject,
    ) -> Result<(String, TokenClaims), TokenError> {
        let (now, exp, jti) = Self::timing(REFRESH_SECS);
        let paseto = Self::build_paseto_claims(subject, &jti, now, exp)?;
        let token = local::encrypt(&self.local_key, &paseto, None, None)
            .map_err(|e| {
                error!(user_id = %subject.user_id, "refresh token encryption failed: {e}");
                TokenError::IssueFailed(e.to_string())
            })?;
        debug!(user_id = %subject.user_id, jti = %jti, "refresh token issued");
        Ok((token, Self::to_token_claims(subject, jti, now, exp)))
    }

    // ─── Verify ───────────────────────────────────────────────────────────────

    /// Verify a v4.public access token and return decoded claims.
    /// Fails if the signature is wrong, exp is in the past, or iss is not ours.
    pub fn verify_access(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let rules = Self::validation_rules();
        let untrusted = UntrustedToken::<Public, V4>::try_from(token)
            .map_err(|_| { warn!("access token rejected: malformed"); TokenError::Invalid })?;
        let trusted = public::verify(&self.public_key, &untrusted, &rules, None, None)
            .map_err(|_| { warn!("access token rejected: invalid signature or expired"); TokenError::Invalid })?;
        let claims = trusted.payload_claims().ok_or(TokenError::Invalid)?;
        let result = Self::decode_paseto_claims(claims);
        if let Ok(ref c) = result {
            debug!(jti = %c.jti, user_id = %c.sub, "access token verified");
        }
        result
    }

    /// Verify a v4.local refresh token and return decoded claims.
    pub fn verify_refresh(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let rules = Self::validation_rules();
        let untrusted = UntrustedToken::<Local, V4>::try_from(token)
            .map_err(|_| { warn!("refresh token rejected: malformed"); TokenError::Invalid })?;
        let trusted = local::decrypt(&self.local_key, &untrusted, &rules, None, None)
            .map_err(|_| { warn!("refresh token rejected: decryption or expiry failed"); TokenError::Invalid })?;
        let claims = trusted.payload_claims().ok_or(TokenError::Invalid)?;
        let result = Self::decode_paseto_claims(claims);
        if let Ok(ref c) = result {
            debug!(jti = %c.jti, user_id = %c.sub, "refresh token verified");
        }
        result
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    fn timing(lifetime_secs: i64) -> (DateTime<Utc>, DateTime<Utc>, Uuid) {
        let now = Utc::now();
        (now, now + Duration::seconds(lifetime_secs), Uuid::new_v4())
    }

    fn validation_rules() -> ClaimsValidationRules {
        let mut r = ClaimsValidationRules::new();
        r.validate_issuer_with(ISSUER);
        r
    }

    fn build_paseto_claims(
        subject: &TokenSubject,
        jti: &Uuid,
        now: DateTime<Utc>,
        exp: DateTime<Utc>,
    ) -> Result<Claims, TokenError> {
        macro_rules! set {
            ($expr:expr) => {
                $expr.map_err(|e| TokenError::ClaimsBuild(e.to_string()))?
            };
        }

        let mut c = Claims::new()
            .map_err(|e| TokenError::ClaimsBuild(e.to_string()))?;

        set!(c.issuer(ISSUER));
        set!(c.subject(&subject.user_id.to_string()));
        set!(c.token_identifier(&jti.to_string()));
        set!(c.issued_at(&now.to_rfc3339()));
        set!(c.expiration(&exp.to_rfc3339()));
        set!(c.add_additional("email",    serde_json::json!(&subject.email)));
        set!(c.add_additional("username", serde_json::json!(&subject.username)));
        set!(c.add_additional("role",     serde_json::json!(subject.role.to_string())));

        if let Some(tid) = subject.tenant_id {
            set!(c.add_additional("tenant_id", serde_json::json!(tid.to_string())));
        }
        if let Some(ref hint) = subject.device_hint {
            set!(c.add_additional("device_hint", serde_json::json!(hint)));
        }

        Ok(c)
    }

    fn to_token_claims(
        subject: &TokenSubject,
        jti: Uuid,
        iat: DateTime<Utc>,
        exp: DateTime<Utc>,
    ) -> TokenClaims {
        TokenClaims {
            sub:         subject.user_id,
            email:       subject.email.clone(),
            username:    subject.username.clone(),
            role:        subject.role.clone(),
            tenant_id:   subject.tenant_id,
            jti,
            iss:         ISSUER.to_string(),
            iat,
            exp,
            device_hint: subject.device_hint.clone(),
        }
    }

    fn decode_paseto_claims(claims: &Claims) -> Result<TokenClaims, TokenError> {
        macro_rules! str_req {
            ($key:expr) => {
                claims
                    .get_claim($key)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| TokenError::MissingClaim($key.into()))?
            };
        }

        let sub = Uuid::parse_str(str_req!("sub"))
            .map_err(|_| TokenError::MissingClaim("sub".into()))?;
        let jti = Uuid::parse_str(str_req!("jti"))
            .map_err(|_| TokenError::MissingClaim("jti".into()))?;

        Ok(TokenClaims {
            sub,
            jti,
            iss:         str_req!("iss").to_string(),
            email:       str_req!("email").to_string(),
            username:    str_req!("username").to_string(),
            role:        role_from_str(str_req!("role"))?,
            iat:         parse_dt(str_req!("iat"), "iat")?,
            exp:         parse_dt(str_req!("exp"), "exp")?,
            tenant_id:   claims.get_claim("tenant_id")
                             .and_then(|v| v.as_str())
                             .and_then(|s| Uuid::parse_str(s).ok()),
            device_hint: claims.get_claim("device_hint")
                             .and_then(|v| v.as_str())
                             .map(str::to_string),
        })
    }

    fn load_symmetric(var: &str) -> Result<SymmetricKey<V4>, TokenError> {
        let bytes = load_hex_env(var)?;
        SymmetricKey::<V4>::from(&bytes)
            .map_err(|e| TokenError::KeyLoad(format!("{var}: {e}")))
    }

    fn load_secret(var: &str) -> Result<AsymmetricSecretKey<V4>, TokenError> {
        let bytes = load_hex_env(var)?;
        AsymmetricSecretKey::<V4>::from(&bytes)
            .map_err(|e| TokenError::KeyLoad(format!("{var}: {e}")))
    }

    fn load_public(var: &str) -> Result<AsymmetricPublicKey<V4>, TokenError> {
        let bytes = load_hex_env(var)?;
        AsymmetricPublicKey::<V4>::from(&bytes)
            .map_err(|e| TokenError::KeyLoad(format!("{var}: {e}")))
    }
}

// ─── Module-level helpers ─────────────────────────────────────────────────────

fn load_hex_env(var: &str) -> Result<Vec<u8>, TokenError> {
    let raw = std::env::var(var)
        .map_err(|_| TokenError::KeyLoad(format!("{var} is not set")))?;
    hex::decode(raw.trim())
        .map_err(|e| TokenError::KeyLoad(format!("{var} is not valid hex: {e}")))
}

fn role_from_str(s: &str) -> Result<UserRole, TokenError> {
    match s {
        "admin"      => Ok(UserRole::Admin),
        "user"       => Ok(UserRole::User),
        "moderator"  => Ok(UserRole::Moderator),
        "arquitecto" => Ok(UserRole::Arquitecto),
        "finanzas"   => Ok(UserRole::Finanzas),
        "reportes"   => Ok(UserRole::Reportes),
        other => Err(TokenError::MissingClaim(format!("unknown role '{other}'"))),
    }
}

fn parse_dt(s: &str, field: &str) -> Result<DateTime<Utc>, TokenError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| TokenError::MissingClaim(format!("{field} is not valid RFC3339")))
}
