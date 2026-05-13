use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};
use chrono::{Duration, Utc};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::dal::history::HistoryRepository;
use crate::dal::token::RefreshTokenRepository;
use crate::dal::user::UserRepository;
use crate::domain::models::enums::{HistoryAction, TokenStatus, UserStatus};
use crate::domain::models::history::CreateHistory;
use crate::domain::models::refresh_token::CreateRefreshToken;
use crate::errors::db_errors::DbError;
use crate::security::revocation_store::{RevocationError, RevokedTokenEntry, RevocationStore};
use crate::service::secrets::TenantSecretsService;
use crate::service::token::{TokenClaims, TokenError, TokenService, TokenSubject};

const MAX_FAILED_ATTEMPTS: i16  = 5;
const LOCKOUT_MINUTES: i64      = 15;
const ACCESS_LIFETIME_SECS: u32 = 15 * 60;
const REFRESH_LIFETIME_DAYS: i64 = 7;

// ─── Result types ─────────────────────────────────────────────────────────────

pub struct LoginResult {
    pub access_token:      String,
    pub access_claims:     TokenClaims,
    pub user_status:       UserStatus,
    pub refresh_jti:       Uuid,
    pub expires_in:        u32,
    pub db_connection_url: Option<String>,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("account locked until {0}")]
    AccountLocked(String),

    #[error("account is not active")]
    AccountInactive,

    #[error("token is invalid or expired")]
    InvalidToken,

    #[error("token has been revoked")]
    TokenRevoked,

    #[error("session not found or already expired")]
    SessionNotFound,

    #[error("invalid id: {0}")]
    BadUuid(String),

    #[error("database error: {0}")]
    Db(#[from] DbError),

    #[error("token error: {0}")]
    Token(#[from] TokenError),

    #[error("revocation error: {0}")]
    Revocation(#[from] RevocationError),
}

// ─── Service ──────────────────────────────────────────────────────────────────

pub struct AuthService {
    user_repo:    Arc<UserRepository>,
    token_repo:   Arc<RefreshTokenRepository>,
    history_repo: Arc<HistoryRepository>,
    token_svc:    Arc<TokenService>,
    revoc_store:  Arc<RevocationStore>,
    secrets_svc:  Arc<TenantSecretsService>,
}

impl AuthService {
    pub fn new(
        user_repo:    Arc<UserRepository>,
        token_repo:   Arc<RefreshTokenRepository>,
        history_repo: Arc<HistoryRepository>,
        token_svc:    Arc<TokenService>,
        revoc_store:  Arc<RevocationStore>,
        secrets_svc:  Arc<TenantSecretsService>,
    ) -> Self {
        Self { user_repo, token_repo, history_repo, token_svc, revoc_store, secrets_svc }
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    pub async fn login(
        &self,
        email:       &str,
        password:    &str,
        device_hint: Option<String>,
        ip:          Option<IpAddr>,
        user_agent:  Option<String>,
    ) -> Result<LoginResult, AuthError> {
        // 1. Look up user — return generic error so callers can't enumerate accounts.
        let user = self.user_repo.find_by_email(email).await.map_err(|e| match e {
            DbError::NotFound => AuthError::InvalidCredentials,
            e                 => AuthError::Db(e),
        })?;

        // 2. Reject locked accounts.
        if let Some(until) = user.locked_until {
            if until > Utc::now() {
                warn!(user_id = %user.id, locked_until = %until, "login rejected: account locked");
                let mut h = CreateHistory::new(HistoryAction::LoginFailed)
                    .actor(user.id, &user.email)
                    .failed(format!("account locked until {until}"));
                if let Some(ip)  = ip          { h = h.ip(ip); }
                if let Some(ua)  = &user_agent { h = h.user_agent(ua.as_str()); }
                self.record(h).await;
                return Err(AuthError::AccountLocked(until.to_rfc3339()));
            }
        }

        // 3. Reject non-active accounts.
        if !matches!(user.status, UserStatus::Active) {
            warn!(user_id = %user.id, status = %user.status, "login rejected: account not active");
            return Err(AuthError::AccountInactive);
        }

        // 4. Verify password.
        let hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        if Argon2::default().verify_password(password.as_bytes(), &hash).is_err() {
            let attempts = self.user_repo.increment_failed_attempts(user.id).await?;
            warn!(user_id = %user.id, attempts, "login failed: wrong password");

            if attempts >= MAX_FAILED_ATTEMPTS {
                let lock_until = Utc::now() + Duration::minutes(LOCKOUT_MINUTES);
                warn!(user_id = %user.id, lock_until = %lock_until, "account locked after repeated failures");
                if let Err(e) = self.user_repo.lock_account(user.id, lock_until).await {
                    warn!(user_id = %user.id, error = %e, "lock_account failed");
                }
            }

            let mut h = CreateHistory::new(HistoryAction::LoginFailed)
                .actor(user.id, &user.email)
                .failed("invalid password");
            if let Some(ip) = ip          { h = h.ip(ip); }
            if let Some(ua) = &user_agent { h = h.user_agent(ua.as_str()); }
            self.record(h).await;

            return Err(AuthError::InvalidCredentials);
        }

        // 5. Reset failure counter on success.
        if let Err(e) = self.user_repo.reset_failed_attempts(user.id).await {
            warn!(user_id = %user.id, error = %e, "reset_failed_attempts failed");
        }

        // 6. Mint access token (v4.public, 15 min).
        let subject = TokenSubject {
            user_id:     user.id,
            email:       user.email.clone(),
            username:    user.username.clone(),
            role:        user.role.clone(),
            tenant_id:   user.tenant_id,
            device_hint: device_hint.clone(),
        };
        let (access_token, access_claims) = self.token_svc.issue_access(&subject)?;

        // 7. Persist refresh token record in DB.
        let refresh_jti = Uuid::new_v4();
        self.token_repo.create(CreateRefreshToken {
            jti:         refresh_jti,
            user_id:     user.id,
            expires_at:  Utc::now() + Duration::days(REFRESH_LIFETIME_DAYS),
            device_hint: device_hint.clone(),
        }).await?;

        // 8. Audit.
        let mut h = CreateHistory::new(HistoryAction::Login)
            .actor(user.id, &user.email)
            .token(refresh_jti);
        if let Some(ip) = ip          { h = h.ip(ip); }
        if let Some(ua) = &user_agent { h = h.user_agent(ua.as_str()); }
        self.record(h).await;

        // 9. Fetch tenant schema name, falling back to db url (best-effort).
        let db_connection_url = match user.tenant_id {
            Some(tid) => match self.secrets_svc.get_schema_name(tid).await {
                Ok(s)  => Some(s),
                Err(_) => self.secrets_svc.get_db_url(tid).await.ok(),
            },
            None => None,
        };

        info!(user_id = %user.id, email = %user.email, "login successful");
        Ok(LoginResult {
            access_token,
            access_claims,
            user_status: user.status,
            refresh_jti,
            expires_in: ACCESS_LIFETIME_SECS,
            db_connection_url,
        })
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    pub async fn logout(
        &self,
        refresh_jti_str: &str,
        access_token:    Option<&str>,
    ) -> Result<(), AuthError> {
        let refresh_jti = parse_uuid(refresh_jti_str)?;

        let record = self.token_repo.find_by_jti(refresh_jti).await.map_err(|e| match e {
            DbError::NotFound => AuthError::SessionNotFound,
            e                 => AuthError::Db(e),
        })?;

        self.token_repo.revoke_by_jti(refresh_jti).await.map_err(|e| match e {
            DbError::NotFound => AuthError::SessionNotFound,
            e                 => AuthError::Db(e),
        })?;

        // Immediately invalidate the access token in the revocation store.
        // Best-effort: if verification fails the token is likely expired already.
        if let Some(token_str) = access_token {
            if !token_str.is_empty() {
                if let Ok(claims) = self.token_svc.verify_access(token_str) {
                    let entry = RevokedTokenEntry {
                        jti:        claims.jti,
                        user_id:    claims.sub,
                        revoked_at: Utc::now(),
                        reason:     "logout".into(),
                    };
                    if let Err(e) = self.revoc_store.add(entry).await {
                        warn!(error = %e, "revocation store add failed during logout");
                    }
                }
            }
        }

        self.record(
            CreateHistory::new(HistoryAction::Logout)
                .actor(record.user_id, "")
                .token(refresh_jti),
        ).await;

        info!(user_id = %record.user_id, refresh_jti = %refresh_jti, "logout successful");
        Ok(())
    }

    // ── Refresh token ─────────────────────────────────────────────────────────

    pub async fn refresh_token(
        &self,
        refresh_jti_str: &str,
        new_device_hint: Option<String>,
    ) -> Result<LoginResult, AuthError> {
        let old_jti = parse_uuid(refresh_jti_str)?;

        let record = self.token_repo.find_by_jti(old_jti).await.map_err(|e| match e {
            DbError::NotFound => AuthError::SessionNotFound,
            e                 => AuthError::Db(e),
        })?;

        if !matches!(record.status, TokenStatus::Active) {
            return Err(AuthError::TokenRevoked);
        }
        if record.expires_at < Utc::now() {
            return Err(AuthError::InvalidToken);
        }

        let user = self.user_repo.find_by_id(record.user_id).await?;
        if !matches!(user.status, UserStatus::Active) {
            return Err(AuthError::AccountInactive);
        }

        // Atomic rotate: revoke old JTI, create new one.
        let new_jti        = Uuid::new_v4();
        let device_hint    = new_device_hint.or(record.device_hint);
        self.token_repo.rotate(old_jti, CreateRefreshToken {
            jti:         new_jti,
            user_id:     user.id,
            expires_at:  Utc::now() + Duration::days(REFRESH_LIFETIME_DAYS),
            device_hint: device_hint.clone(),
        }).await?;

        let subject = TokenSubject {
            user_id:     user.id,
            email:       user.email.clone(),
            username:    user.username.clone(),
            role:        user.role.clone(),
            tenant_id:   user.tenant_id,
            device_hint: device_hint.clone(),
        };
        let (access_token, access_claims) = self.token_svc.issue_access(&subject)?;

        self.record(
            CreateHistory::new(HistoryAction::TokenRefreshed)
                .actor(user.id, &user.email)
                .token(new_jti),
        ).await;

        let db_connection_url = match user.tenant_id {
            Some(tid) => match self.secrets_svc.get_schema_name(tid).await {
                Ok(s)  => Some(s),
                Err(_) => self.secrets_svc.get_db_url(tid).await.ok(),
            },
            None => None,
        };

        info!(user_id = %user.id, "token refreshed");
        Ok(LoginResult {
            access_token,
            access_claims,
            user_status: user.status,
            refresh_jti: new_jti,
            expires_in:  ACCESS_LIFETIME_SECS,
            db_connection_url,
        })
    }

    // ── Validate token ────────────────────────────────────────────────────────

    pub async fn validate_token(&self, access_token: &str) -> Result<TokenClaims, AuthError> {
        let claims = self.token_svc.verify_access(access_token)?;

        if self.revoc_store.contains_jti(&claims.jti).await? {
            return Err(AuthError::TokenRevoked);
        }

        Ok(claims)
    }

    // ── Revoke all sessions ───────────────────────────────────────────────────

    pub async fn revoke_sessions(&self, user_id: Uuid) -> Result<u64, AuthError> {
        let count = self.token_repo.revoke_all_by_user(user_id).await?;

        self.record(
            CreateHistory::new(HistoryAction::TokenRevoked)
                .actor(user_id, "")
                .target_user(user_id),
        ).await;

        info!(user_id = %user_id, sessions_revoked = count, "all sessions revoked");
        Ok(count)
    }

    // ── Change password ───────────────────────────────────────────────────────

    /// Verifies `current_password`, replaces the hash, and optionally revokes
    /// all active sessions. Returns the number of sessions revoked (0 when the
    /// flag is false).
    pub async fn change_password(
        &self,
        user_id:          Uuid,
        current_password: &str,
        new_password:     &str,
        revoke_sessions:  bool,
    ) -> Result<u64, AuthError> {
        let user = self.user_repo.find_by_id(user_id).await?;

        let hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;
        if Argon2::default().verify_password(current_password.as_bytes(), &hash).is_err() {
            return Err(AuthError::InvalidCredentials);
        }

        let salt     = SaltString::generate(&mut OsRng);
        let new_hash = Argon2::default()
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|_| AuthError::InvalidCredentials)?
            .to_string();

        self.user_repo.update_password(user_id, &new_hash).await?;

        let sessions_revoked = if revoke_sessions {
            self.revoke_sessions(user_id).await?
        } else {
            0
        };

        self.record(
            CreateHistory::new(HistoryAction::PasswordChanged)
                .actor(user_id, &user.email),
        ).await;

        info!(user_id = %user_id, sessions_revoked, "password changed");
        Ok(sessions_revoked)
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    async fn record(&self, entry: CreateHistory) {
        if let Err(e) = self.history_repo.append(entry).await {
            warn!(error = %e, "history append failed");
        }
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, AuthError> {
    Uuid::parse_str(s).map_err(|e| AuthError::BadUuid(e.to_string()))
}
