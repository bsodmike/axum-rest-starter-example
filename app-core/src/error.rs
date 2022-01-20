use async_session;
use axum::{
    body::{boxed, Full},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{error, json, Value};
use std::error::Error as StdError;
use std::fmt;
use std::io;
use thiserror::Error;

type Cause = Box<dyn StdError + Send + Sync>;

pub struct Error {
    inner: Box<ErrorImpl>,
}

pub fn new(kind: Kind) -> Error {
    let err = Error {
        inner: Box::new(ErrorImpl { kind, cause: None }),
    };

    err
}

impl Error {
    pub fn set_cause(&mut self, error: Box<dyn StdError + Send + Sync>) {
        self.inner.cause = Some(error)
    }
}

struct ErrorImpl {
    kind: Kind,
    cause: Option<Cause>,
}

#[derive(Debug)]
pub enum Kind {
    Hyper(Hyper),
    ApiError(ApiError),
    AuthError(AuthError),
    UriError(UriError),
    RedisError(RedisError),
    ExtensionMissing,
    ConfigurationSecretMissing,
    ConfigurationSecretEmpty,
    NotImplementedError,
}

impl IntoResponse for Kind {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Kind::ExtensionMissing => (StatusCode::INTERNAL_SERVER_ERROR, "Extension missing!"),
            Kind::ConfigurationSecretMissing => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration secret missing!",
            ),
            Kind::ConfigurationSecretEmpty => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration secret is blank!",
            ),
            Kind::NotImplementedError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error: Not implemented, well, yet!",
            ),
            Kind::Hyper(hyper) => (StatusCode::INTERNAL_SERVER_ERROR, "Hyper related error!"),
            Kind::ApiError(api_error) => (StatusCode::BAD_REQUEST, "Unknown API error!"),
            Kind::AuthError(auth_error) => (StatusCode::BAD_REQUEST, "Unknown Auth error!"),
            Kind::UriError(uri_error) => (StatusCode::INTERNAL_SERVER_ERROR, "Unknown Uri error!"),
            Kind::RedisError(redis_error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unknown Redis error!")
            }
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug)]
pub enum UriError {
    RegexpMatchError,
}

impl IntoResponse for UriError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            UriError::RegexpMatchError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "RegExp match error!")
            }
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl From<UriError> for AuthError {
    fn from(error: UriError) -> Self {
        AuthError::GenericAuthError
    }
}

#[derive(Debug)]
pub enum Hyper {
    ParseError,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest,
}

#[derive(Debug)]
pub enum RedisError {
    ConnectionError,
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    GenericAuthError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials!"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials!"),
            AuthError::TokenCreation => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error!")
            }
            AuthError::GenericAuthError => (StatusCode::INTERNAL_SERVER_ERROR, "Auth error!"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token!"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("hyper::Error");
        f.field(&self.inner.kind);
        if let Some(ref cause) = self.inner.cause {
            f.field(cause);
        }
        f.finish()
    }
}

#[allow(clippy::to_string_in_display)]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref cause) = self.inner.cause {
            write!(f, "{}: {}", self, cause)
        } else {
            f.write_str(&self.to_string())
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner
            .cause
            .as_ref()
            .map(|cause| &**cause as &(dyn StdError + 'static))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut res = Response::new(boxed(Full::from(self.to_string())));
        *res.status_mut() = StatusCode::BAD_REQUEST;
        res
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Error {
        new(Kind::Hyper(Hyper::ParseError))
    }
}
