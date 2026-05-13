use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use std::sync::Arc;

use chrono::{Duration, Utc};
use crate::dal::user::UserRepository;
use crate::errors::db_errors::DbError;
use crate::domain::models::user::{UpdateUser, User};

// ─── Input from the handler (plain-text password) ────────────────────────────

/// Lo que llega del HTTP body — password en texto plano.
/// Nunca sale de esta capa sin ser hasheado.
#[derive(Debug, serde::Deserialize)]
pub struct RegisterUserRequest {
    pub email:     String,
    pub username:  String,
    pub password:  String,          // ← plain text, solo existe aquí
    pub full_name: Option<String>,
    pub phone:     Option<String>,
    pub role:      crate::domain::models::enums::UserRole,
    pub tenant_id: Option<uuid::Uuid>,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum UserServiceError {
    #[error("failed to hash password")]
    HashFailed,

    #[error(transparent)]
    Db(#[from] DbError),
}

// ─── Service ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct UserService {
    repo: Arc<UserRepository>,
}

impl UserService {
    pub fn new(repo: Arc<UserRepository>) -> Self {
        Self { repo }
    }

    /// Registra un usuario nuevo:
    ///   1. hashea el password  ← única responsabilidad extra vs el repo
    ///   2. delega persistencia al repositorio
    pub async fn register(
        &self,
        req: RegisterUserRequest,
    ) -> Result<User, UserServiceError> {
        // ── 1. Hash ──────────────────────────────────────────────────────────
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|_| UserServiceError::HashFailed)?
            .to_string();

        // ── 2. Construye el DTO que ya no contiene el password en claro ──────
        let create = crate::domain::models::user::CreateUser {
            email:         req.email,
            username:      req.username,
            password_hash: hash,       // ← repo solo recibe esto
            role:          req.role,
            tenant_id:     req.tenant_id,
            full_name:     req.full_name,
            phone:         req.phone,
        };

        // ── 3. Persiste ───────────────────────────────────────────────────────
        let user = self.repo.create(create).await?;
        Ok(user)
    }

    pub async fn list_all(&self, limit: i64, offset: i64, tenant_id: Option<uuid::Uuid>) -> Result<Vec<User>, UserServiceError> {
        let users = match tenant_id {
            Some(tid) => self.repo.list_by_tenant(tid, limit, offset).await?,
            None      => self.repo.list_active(limit, offset).await?,
        };
        Ok(users)
    }

    pub async fn get_user(&self, user_id: uuid::Uuid) -> Result<User, UserServiceError> {
        Ok(self.repo.find_by_id(user_id).await?)
    }

    pub async fn delete_user(&self, user_id: uuid::Uuid) -> Result<(), UserServiceError> {
        Ok(self.repo.soft_delete(user_id).await?)
    }

    pub async fn update_user(&self, user_id: uuid::Uuid, dto: UpdateUser) -> Result<User, UserServiceError> {
        Ok(self.repo.update(user_id, dto).await?)
    }

    pub async fn lock_user(
        &self,
        user_id: uuid::Uuid,
        lock: bool,
        minutes: i32,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, UserServiceError> {
        if lock {
            let until = if minutes <= 0 {
                Utc::now() + Duration::days(36500)
            } else {
                Utc::now() + Duration::minutes(minutes as i64)
            };
            self.repo.lock_account(user_id, until).await?;
            Ok(Some(until))
        } else {
            self.repo.unlock_account(user_id).await?;
            Ok(None)
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, UserServiceError> {
        Ok(self.repo.find_by_username(username).await?)
    }

    pub async fn check_username(&self, username: &str) -> Result<bool, UserServiceError> {
        match self.repo.find_by_username(username).await {
            Ok(_)                  => Ok(false),
            Err(DbError::NotFound) => Ok(true),
            Err(e)                 => Err(UserServiceError::Db(e)),
        }
    }
}