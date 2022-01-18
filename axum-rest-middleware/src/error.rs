//! Error and Result module.
use crate::BoxError;
use async_session;
use axum::{
    body::{boxed, Full},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{error, json, Value};
use std::io;
use std::{error::Error as StdError, fmt};

type Cause = BoxError;

/// Errors that can happen when using `axum-rest-middleware`
pub struct Error {
    inner: Box<ErrorImpl>,
}

pub(crate) fn new(kind: Kind) -> Error {
    Error {
        inner: Box::new(ErrorImpl { kind, cause: None }),
    }
}

pub(crate) struct ErrorImpl {
    kind: Kind,
    cause: Option<Cause>,
}

#[derive(Debug)]
pub(crate) enum Kind {
    Hyper(Hyper),
    BaseError(BaseError),
    EnvironmentVariableMissing,
    SessionError,
    NotImplementedError,
}

#[derive(Debug)]
pub(super) enum BaseError {
    NotImplementedError,
}

#[derive(Debug)]
pub(crate) enum Hyper {
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

impl From<async_session::Error> for Error {
    fn from(err: async_session::Error) -> Error {
        new(Kind::SessionError)
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Error {
        new(Kind::Hyper(Hyper::ParseError))
    }
}

#[doc(hidden)]
trait AssertSendSync: Send + Sync + 'static {}
#[doc(hidden)]
impl AssertSendSync for Error {}
