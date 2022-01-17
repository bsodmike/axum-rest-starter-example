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

pub type CustomError = Error;

pub fn new(kind: Kind) -> Error {
    Error {
        inner: Box::new(ErrorImpl { kind, cause: None }),
    }
}

struct ErrorImpl {
    kind: Kind,
    cause: Option<Cause>,
}

#[derive(Debug)]
pub enum Kind {
    Hyper(Hyper),
    ConfigurationSecretMissing,
    NotImplementedError,
}

#[derive(Debug)]
pub enum Hyper {
    ParseError,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref cause) = self.inner.cause {
            write!(f, "{}: {}", self.to_string(), cause)
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

impl IntoResponse for CustomError {
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
