use axum::{http::StatusCode, Json};
use serde_json::{error, json, Value};
use std::io;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Redis SET error!")]
    RedisSetError,
    #[error("Configuration secret missing!")]
    ConfigurationSecretMissing,
    #[error("NotImplementedError")]
    NotImplementedError,
}

pub type ApiError = (StatusCode, Json<Value>);
pub type ApiResult<T> = std::result::Result<T, ApiError>;
