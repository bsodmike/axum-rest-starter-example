use crate::{extractors::user_extractor, AppState, User};
use app_core::{error, error::Error};
use async_redis_session::RedisSessionStore;
use async_session::{MemoryStore, Session, SessionStore as _};
use axum::{
    async_trait,
    body::{Body, BoxBody, HttpBody},
    extract::{
        extractor_middleware, rejection::TypedHeaderRejection,
        rejection::TypedHeaderRejectionReason, Extension, Form, FromRequest, Path, RequestParts,
        TypedHeader,
    },
    headers::{Cookie, HeaderMap, HeaderMapExt},
    http::{self, header::HeaderName, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::middleware::{self, Next};
use axum_rest_middleware::middleware::{self as RestMiddleware};
use futures::future::TryFutureExt;
use rand::RngCore;
use redis::AsyncCommands;
use redis::Client;
use serde::{de, Deserialize, Serialize};
use std::{fmt::format, str::FromStr};
use uuid::Uuid;

#[derive(Deserialize, Debug, Clone)]
pub struct UserExtractor(pub User);

#[async_trait]
impl<B> FromRequest<B> for UserExtractor
where
    B: Send, // required by `async_trait`
{
    type Rejection = http::StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<RedisSessionStore>::from_request(req)
            .await
            .expect("`RedisSessionStore` extension missing!");

        let cookie = Option::<TypedHeader<Cookie>>::from_request(req)
            .await
            .unwrap();

        tracing::debug!("cookie: {:?}", cookie);

        let session_cookie = cookie
            .as_ref()
            .and_then(|cookie| cookie.get(RestMiddleware::AXUM_SESSION_COOKIE_NAME));

        tracing::debug!(
            "session_uuid_middleware: got session cookie from user agent, {:?}={:?}",
            RestMiddleware::AXUM_SESSION_COOKIE_NAME,
            &session_cookie.unwrap()
        );

        // continue to decode the session cookie
        let session: Session = match store
            .load_session(session_cookie.unwrap().to_string())
            .await
        {
            Ok(value) => match value {
                Some(session_value) => session_value,
                None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            },
            Err(err) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };

        let fetched_user = match session.get::<User>("user") {
            Some(val) => val,
            None => {
                crate::utils::tracing_error(
                    std::panic::Location::caller(),
                    format!("Unable to fetch user from session!"),
                )
                .await
                .into_response();

                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        Ok(Self(fetched_user))
    }
}
