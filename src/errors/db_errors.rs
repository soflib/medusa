use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Record not found")]
    NotFound,
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub type DbResult<T> = Result<T, DbError>;