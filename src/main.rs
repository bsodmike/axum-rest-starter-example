#![allow(unused_imports)]
use askama::Template;
use async_session::{MemoryStore, Session, SessionStore as _};
use axum::headers::HeaderMapExt;
use axum::{
    async_trait,
    body::{self, Body, BoxBody, Bytes, Full},
    extract::{
        extractor_middleware, rejection::TypedHeaderRejection,
        rejection::TypedHeaderRejectionReason, Extension, Form, FromRequest, Path, RequestParts,
        TypedHeader,
    },
    handler::Handler,
    headers::Cookie,
    http::{self, header::LOCATION, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, Router},
    AddExtensionLayer, Json,
};
use axum_extra::middleware::{self as axum_middleware, Next};
use config::*;
use glob::glob;
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::json;
use session::session_uuid_middleware;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use tower::{
    filter::AsyncFilterLayer, limit::ConcurrencyLimitLayer, util::AndThenLayer, BoxError,
    ServiceBuilder,
};
use tower_http::trace::TraceLayer;

pub mod configure;
pub mod errors;
pub mod middleware;
pub mod session;
pub mod wrappers;

use crate::errors::{ApiResult, Error};

pub static CONFIG: Lazy<config::Config> = Lazy::new(|| {
    let mut glob_path = "conf/development/*";
    let mut settings = Config::default();

    let run_mode = match std::env::var("RUST_ENV") {
        Ok(value) => value,
        Err(_) => String::new(),
    };

    if run_mode.eq("production") {
        glob_path = "conf/production/*";
        println!("RUST_ENV={}", run_mode);
    }

    settings
        .merge(
            glob(glob_path)
                .unwrap()
                .map(|path| File::from(path.unwrap()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    settings
});

#[derive(Clone)]
struct AppState {
    redis_client: redis::Client,
}

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "register_otp=debug,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    // `MemoryStore` just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(AppState {
            redis_client: crate::wrappers::redis_wrapper::connect().await,
        }))
        .layer(axum_extra::middleware::from_fn(
            crate::middleware::debugging::print_request_info_middleware,
        ))
        .layer(AddExtensionLayer::new(store))
        .layer(axum_extra::middleware::from_fn(
            session::session_uuid_middleware,
        ));

    // build our application with some routes
    let app = Router::new()
        .route("/", get(show_form).post(accept_form))
        .route("/privacy-policy", get(privacy_policy_handler))
        .layer(middleware_stack);

    // add a fallback service for handling routes to unknown paths
    let app = app.fallback(handler_404.into_service());

    // run it with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn privacy_policy_handler() {}

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

// Frontend logic
async fn show_form(session_user: UserFromSession) -> impl IntoResponse {
    let uuid = session_user.uuid;
    let template = IndexTemplate { uuid };
    HtmlTemplate(template)
}

struct UserFromSession {
    uuid: uuid::Uuid,
}

#[async_trait]
impl<B> FromRequest<B> for UserFromSession
where
    B: Send, // required by `async_trait`
{
    type Rejection = http::StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<MemoryStore>::from_request(req)
            .await
            .expect("`MemoryStore` extension missing");

        let cookie = Option::<TypedHeader<Cookie>>::from_request(req)
            .await
            .unwrap();

        tracing::debug!("cookie: {:?}", cookie);

        let session_cookie = cookie
            .as_ref()
            .and_then(|cookie| cookie.get(crate::session::AXUM_SESSION_COOKIE_NAME));

        tracing::debug!(
            "session_uuid_middleware: got session cookie from user agent, {:?}={:?}",
            crate::session::AXUM_SESSION_COOKIE_NAME,
            &session_cookie.unwrap()
        );

        // continue to decode the session cookie
        let user_id = if let Some(session) = store
            .load_session(session_cookie.unwrap().to_owned())
            .await
            .unwrap()
        {
            if let Some(user_id) = session.get::<crate::session::UserId>("user_id") {
                tracing::debug!(
                    "session_uuid_middleware: session decoded success, user_id={:?}",
                    user_id
                );
                user_id
            } else {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        } else {
            tracing::debug!(
                "session_uuid_middleware: Err session does not exist in store, {}={}",
                crate::session::AXUM_SESSION_COOKIE_NAME,
                session_cookie.unwrap()
            );
            return Err(StatusCode::BAD_REQUEST);
        };

        Ok(Self { uuid: user_id.0 })
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    name: String,
    email: String,
}

async fn accept_form(Form(input): Form<Input>, state: Extension<AppState>) -> Redirect {
    dbg!(&input);

    match save_form(&input, &state).await {
        Ok(_) => (),
        Err(e) => tracing::error!("Failed: {:?}", e),
    }

    Redirect::to("/".parse().unwrap())
}

async fn save_form(input: &Input, state: &Extension<AppState>) -> redis::RedisResult<()> {
    let client = &state.redis_client;
    let mut con = client.get_async_connection().await?;

    let name = input.name.to_owned();
    let name_str = &name[..];

    con.set("async-key1", name_str).await?;
    let result: String = con.get("async-key1").await?;
    println!("->> my_key: {}\n", result);

    Ok(())
}

async fn handler_404(method: Method, uri: Uri) -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
