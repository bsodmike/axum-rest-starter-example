use askama::Template;
use async_redis_session::RedisSessionStore;
use async_session::{log::kv::ToValue, MemoryStore, Session as AsyncSession, SessionStore as _};
use axum::{
    async_trait,
    body::{self, Body, BoxBody, Bytes, Full, HttpBody},
    extract::{
        extractor_middleware, rejection::*, Extension, Form, FromRequest, Path, RequestParts,
        TypedHeader,
    },
    handler::Handler,
    headers::{Cookie, Header, HeaderMapExt},
    http::{
        self, header::HeaderName, header::LOCATION, HeaderMap, HeaderValue, Method, Request,
        StatusCode, Uri,
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    AddExtensionLayer, Json,
};
use hyper::body::Buf;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{errors::CustomError, session::Session};
use std::fmt::{self, Display};

pub async fn privacy_policy_handler() {}

// Templates
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    uuid: uuid::Uuid,
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body::boxed(Full::from(format!(
                    "Failed to render template. Error: {}",
                    err
                ))))
                .unwrap(),
        }
    }
}

pub async fn show_form(session: crate::session::Session) -> impl IntoResponse {
    dbg!(session);
    let uuid = session.uuid;
    let template = IndexTemplate { uuid };
    HtmlTemplate(template)
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct FormFields {
    name: String,
    email: String,
}

impl fmt::Display for FormFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}, {}}}", self.name, self.email)
    }
}

pub async fn handle_form(req: Request<Body>) -> impl IntoResponse {
    let mut req_parts = RequestParts::new(req);
    let body_taken = req_parts.take_body();
    let store = &mut req_parts
        .extensions()
        .unwrap()
        .get::<RedisSessionStore>()
        .expect("`RedisSessionStore` extension missing!");

    //let cookie = Option::<TypedHeader<Cookie>>::from_request(&mut req_parts)
    //    .await
    //    .unwrap();

    let headers = if let Some(value) = req_parts.headers() {
        value
    } else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap();
    };

    let cookie_result = match headers.typed_try_get::<Cookie>() {
        Ok(Some(value)) => TypedHeader(value),
        _ => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };

    let session_cookie = &cookie_result
        .get(crate::session::AXUM_SESSION_COOKIE_NAME)
        .expect("Unable to fetch session cookie!");

    //let bytes = Bytes::from_request(&mut req_parts).await.unwrap();
    let body = if let Some(value) = body_taken {
        value
    } else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap();
    };

    let body_bytes = hyper::body::to_bytes(body).await.unwrap();
    let body_value = match serde_urlencoded::from_bytes::<FormFields>(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            crate::utils::tracing_error(
                std::panic::Location::caller(),
                format!("Error: Unable to deserialize request body {:?}", err),
            )
            .await;

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };

    crate::utils::tracing_debug(
        std::panic::Location::caller(),
        format!("handle_form: Body {:?}", body_value),
    )
    .await;

    crate::utils::tracing_debug(
        std::panic::Location::caller(),
        format!(
            "handle_form: got session cookie from user agent, {:?}={:?}",
            crate::session::AXUM_SESSION_COOKIE_NAME,
            &session_cookie
        ),
    )
    .await;

    // Use `session_cookie` to load the session
    let mut session: AsyncSession = match store.load_session(session_cookie.to_string()).await {
        Ok(value) => match value {
            Some(session_value) => session_value,
            None => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            }
        },
        Err(err) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        }
    };

    session.set_cookie_value(session_cookie.to_string());
    let user_id = crate::session::UserId::new();
    let new_uuid = user_id.0.to_hyphenated().to_string();

    match session.insert(
        "user",
        crate::session::User {
            uuid: new_uuid,
            name: body_value.name,
            email: "".to_string(),
        },
    ) {
        Ok(value) => value,
        Err(err) => {
            crate::utils::tracing_error(
                std::panic::Location::caller(),
                format!("Error: Unable to update session with user {:?}", err),
            )
            .await;

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };

    let _: String = match store.store_session(session).await {
        Ok(value) => match value {
            Some(cookie_value) => {
                crate::utils::tracing_debug(
                    std::panic::Location::caller(),
                    format!(
                        "Store updated OK / Cookie value returned {:?}",
                        cookie_value
                    ),
                )
                .await;

                cookie_value
            }
            None => {
                crate::utils::tracing_debug(
                    std::panic::Location::caller(),
                    format!("Store updated OK / No cookie value returned"),
                )
                .await;

                String::from("")
            }
        },
        Err(err) => {
            crate::utils::tracing_error(
                std::panic::Location::caller(),
                format!("Error whilst attempting to update store {:?}", err),
            )
            .await;

            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };

    // Redirect::to("/".parse().unwrap())
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .body(Body::empty())
        .unwrap();

    let headers = response.headers_mut();
    headers.insert(LOCATION, "/".parse().unwrap());

    response
}

pub async fn handler_404(_method: Method, _uri: Uri) -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
