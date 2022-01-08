use axum::{http::StatusCode, Json};
use serde_json::{error, json, Value};
use std::io;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    ConfigurationSecretMissing,
    NotImplementedError,
}

pub type ApiError = (StatusCode, Json<Value>);
pub type ApiResult<T> = std::result::Result<T, ApiError>;
