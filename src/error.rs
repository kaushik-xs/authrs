//! Application error types and HTTP mapping.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt::Display;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    Locked(String),
    AccessExpired(String),
    TooManyRequests(String),
    Internal(String),
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(s) => write!(f, "Bad request: {}", s),
            AppError::Unauthorized(s) => write!(f, "Unauthorized: {}", s),
            AppError::Forbidden(s) => write!(f, "Forbidden: {}", s),
            AppError::NotFound(s) => write!(f, "Not found: {}", s),
            AppError::Conflict(s) => write!(f, "Conflict: {}", s),
            AppError::Locked(s) => write!(f, "Account locked: {}", s),
            AppError::AccessExpired(s) => write!(f, "Access expired: {}", s),
            AppError::TooManyRequests(s) => write!(f, "Rate limit: {}", s),
            AppError::Internal(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl std::error::Error for AppError {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    error: String,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::Locked(_) => (StatusCode::LOCKED, "account_locked"),
            AppError::AccessExpired(_) => (StatusCode::FORBIDDEN, "access_expired"),
            AppError::TooManyRequests(_) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (
            status,
            Json(ErrorBody {
                error: code.to_string(),
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        use sqlx::Error;
        match &e {
            Error::RowNotFound => AppError::NotFound("Resource not found".to_string()),
            Error::Database(db) if db.is_unique_violation() => {
                AppError::Conflict("Resource already exists".to_string())
            }
            _ => AppError::Internal(e.to_string()),
        }
    }
}

impl From<redis::RedisError> for AppError {
    fn from(e: redis::RedisError) -> Self {
        AppError::Internal(e.to_string())
    }
}
